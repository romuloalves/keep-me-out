use crate::blocklist::name_matches;
use socket2::{Domain, Protocol, Socket, Type};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

pub struct ProxyHandle {
    pub addr: SocketAddr,
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}

impl Drop for ProxyHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

pub fn start(
    bind: SocketAddr,
    upstream: Vec<SocketAddr>,
    domains: Arc<Mutex<Vec<String>>>,
) -> Result<ProxyHandle, String> {
    let udp = bind_udp(bind)?;
    let addr = udp
        .local_addr()
        .map_err(|error| format!("Couldn't read the DNS socket: {error}"))?;
    udp.set_read_timeout(Some(Duration::from_millis(200)))
        .map_err(|error| format!("Couldn't configure the DNS socket: {error}"))?;
    let tcp = bind_tcp(addr)?;
    tcp.set_nonblocking(true)
        .map_err(|error| format!("Couldn't configure the DNS socket: {error}"))?;

    let stop = Arc::new(AtomicBool::new(false));
    let udp_stop = Arc::clone(&stop);
    let udp_domains = Arc::clone(&domains);
    let udp_upstream = upstream.clone();
    let udp_thread = thread::spawn(move || udp_loop(udp, udp_upstream, udp_domains, udp_stop));

    let tcp_stop = Arc::clone(&stop);
    let tcp_domains = Arc::clone(&domains);
    let tcp_thread = thread::spawn(move || tcp_loop(tcp, upstream, tcp_domains, tcp_stop));

    Ok(ProxyHandle {
        addr,
        stop,
        threads: vec![udp_thread, tcp_thread],
    })
}

fn bind_error(error: io::Error) -> String {
    match error.kind() {
        io::ErrorKind::AddrInUse => "Port 53 is already in use.".to_string(),
        io::ErrorKind::PermissionDenied => {
            "Couldn't bind port 53. Start blocking from the app so macOS can ask for an administrator password.".to_string()
        }
        _ => format!("Couldn't bind the DNS proxy: {error}"),
    }
}

fn bind_udp(addr: SocketAddr) -> Result<UdpSocket, String> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|error| bind_error(error))?;
    socket
        .set_reuse_address(true)
        .map_err(|error| bind_error(error))?;
    socket.bind(&addr.into()).map_err(bind_error)?;
    Ok(socket.into())
}

fn bind_tcp(addr: SocketAddr) -> Result<TcpListener, String> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
        .map_err(|error| bind_error(error))?;
    socket
        .set_reuse_address(true)
        .map_err(|error| bind_error(error))?;
    socket.bind(&addr.into()).map_err(bind_error)?;
    socket.listen(128).map_err(bind_error)?;
    Ok(socket.into())
}

fn udp_loop(
    socket: UdpSocket,
    upstream: Vec<SocketAddr>,
    domains: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
) {
    let mut buffer = [0u8; 4096];
    while !stop.load(Ordering::Relaxed) {
        match socket.recv_from(&mut buffer) {
            Ok((length, source)) => {
                if let Some(response) = handle_query(&buffer[..length], &domains, &upstream) {
                    let _ = socket.send_to(&response, source);
                }
            }
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    || error.kind() == io::ErrorKind::TimedOut
                    || error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
}

fn tcp_loop(
    listener: TcpListener,
    upstream: Vec<SocketAddr>,
    domains: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
) {
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => handle_tcp(stream, &domains, &upstream),
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    || error.kind() == io::ErrorKind::Interrupted =>
            {
                thread::sleep(Duration::from_millis(30));
            }
            Err(_) => break,
        }
    }
}

fn handle_tcp(mut stream: TcpStream, domains: &Mutex<Vec<String>>, upstream: &[SocketAddr]) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(3)));
    loop {
        let query = match read_tcp_message(&mut stream) {
            Ok(query) => query,
            Err(_) => return,
        };
        let Some(response) = answer(&query, domains, upstream, true) else {
            return;
        };
        if write_tcp_message(&mut stream, &response).is_err() {
            return;
        }
    }
}

fn handle_query(
    query: &[u8],
    domains: &Mutex<Vec<String>>,
    upstream: &[SocketAddr],
) -> Option<Vec<u8>> {
    answer(query, domains, upstream, false)
}

fn answer(
    query: &[u8],
    domains: &Mutex<Vec<String>>,
    upstream: &[SocketAddr],
    tcp: bool,
) -> Option<Vec<u8>> {
    let name = query_name(query)?;
    let blocked = domains
        .lock()
        .map(|list| list.iter().any(|domain| name_matches(&name, domain)))
        .unwrap_or(false);
    if blocked {
        return reply(query, 3);
    }
    let forwarded = if tcp {
        forward_tcp(query, upstream)
    } else {
        forward_udp(query, upstream)
    };
    match forwarded {
        Ok(response) => Some(response),
        Err(_) => reply(query, 2),
    }
}

fn forward_tcp(query: &[u8], upstream: &[SocketAddr]) -> io::Result<Vec<u8>> {
    if upstream.is_empty() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "no upstream"));
    }
    let mut last = io::Error::new(io::ErrorKind::Other, "upstream failed");
    for address in upstream {
        if address.ip().is_loopback() && address.port() == 53 {
            continue;
        }
        let mut stream = match TcpStream::connect_timeout(address, Duration::from_secs(2)) {
            Ok(stream) => stream,
            Err(error) => {
                last = error;
                continue;
            }
        };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
        if write_tcp_message(&mut stream, query).is_err() {
            continue;
        }
        match read_tcp_message(&mut stream) {
            Ok(response) => return Ok(response),
            Err(error) => last = error,
        }
    }
    Err(last)
}

fn forward_udp(query: &[u8], upstream: &[SocketAddr]) -> io::Result<Vec<u8>> {
    if upstream.is_empty() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "no upstream"));
    }
    let mut last = io::Error::new(io::ErrorKind::Other, "upstream failed");
    for address in upstream {
        if address.ip().is_loopback() && address.port() == 53 {
            continue;
        }
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(Some(Duration::from_secs(2)))?;
        if socket.send_to(query, address).is_err() {
            continue;
        }
        let mut buffer = [0u8; 4096];
        match socket.recv(&mut buffer) {
            Ok(length) => return Ok(buffer[..length].to_vec()),
            Err(error) => last = error,
        }
    }
    Err(last)
}

fn read_tcp_message(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut length_bytes = [0u8; 2];
    stream.read_exact(&mut length_bytes)?;
    let length = u16::from_be_bytes(length_bytes) as usize;
    if length > 4096 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "dns message too large",
        ));
    }
    let mut message = vec![0u8; length];
    stream.read_exact(&mut message)?;
    Ok(message)
}

fn write_tcp_message(stream: &mut TcpStream, message: &[u8]) -> io::Result<()> {
    let length = u16::try_from(message.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "dns message too large"))?;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(message)?;
    Ok(())
}

fn query_name(packet: &[u8]) -> Option<String> {
    if packet.len() < 12 {
        return None;
    }
    let questions = u16::from_be_bytes([packet[4], packet[5]]);
    if questions == 0 {
        return None;
    }
    read_name(packet, 12)
}

fn read_name(packet: &[u8], mut offset: usize) -> Option<String> {
    let mut labels = Vec::new();
    let mut jumps = 0;
    let mut steps = 0;
    loop {
        if offset >= packet.len() || steps > 255 {
            return None;
        }
        steps += 1;
        let length = packet[offset];
        if length == 0 {
            break;
        }
        if length & 0xC0 == 0xC0 {
            if offset + 1 >= packet.len() {
                return None;
            }
            let pointer = (((length as usize) & 0x3F) << 8) | packet[offset + 1] as usize;
            jumps += 1;
            if jumps > 16 || pointer >= packet.len() {
                return None;
            }
            offset = pointer;
            continue;
        }
        if length & 0xC0 != 0 {
            return None;
        }
        let start = offset + 1;
        let end = start + length as usize;
        if end > packet.len() {
            return None;
        }
        labels.push(
            std::str::from_utf8(&packet[start..end])
                .ok()?
                .to_ascii_lowercase(),
        );
        offset = end;
    }
    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}

fn reply(query: &[u8], rcode: u8) -> Option<Vec<u8>> {
    if query.len() < 12 || rcode > 15 {
        return None;
    }
    let questions = u16::from_be_bytes([query[4], query[5]]);
    if questions == 0 {
        return None;
    }
    let name_end = skip_name(query, 12)?;
    let question_end = name_end.checked_add(4)?;
    if question_end > query.len() {
        return None;
    }
    let mut response = Vec::with_capacity(question_end);
    response.extend_from_slice(&query[..2]);
    response.push(0x80 | (query[2] & 0x01));
    response.push(0x80 | rcode);
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    response.extend_from_slice(&query[12..question_end]);
    Some(response)
}

fn skip_name(packet: &[u8], mut offset: usize) -> Option<usize> {
    let mut steps = 0;
    loop {
        if offset >= packet.len() || steps > 255 {
            return None;
        }
        steps += 1;
        let length = packet[offset];
        if length == 0 {
            return Some(offset + 1);
        }
        if length & 0xC0 == 0xC0 {
            return (offset + 1 < packet.len()).then_some(offset + 2);
        }
        if length & 0xC0 != 0 {
            return None;
        }
        offset = offset.checked_add(1 + length as usize)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    fn encode_name(name: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        for label in name.trim_end_matches('.').split('.') {
            bytes.push(label.len() as u8);
            bytes.extend(label.as_bytes());
        }
        bytes.push(0);
        bytes
    }

    fn build_query(name: &str) -> Vec<u8> {
        let mut packet = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        packet.extend(encode_name(name));
        packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        packet
    }

    #[test]
    fn reads_a_query_name_and_stops_on_a_pointer_loop() {
        let query = build_query("www.Example.com");
        assert_eq!(query_name(&query).as_deref(), Some("www.example.com"));

        let mut looped = vec![
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        looped.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01]);
        assert!(query_name(&looped).is_none());
    }

    #[test]
    fn nxdomain_keeps_the_id_and_blocks_subdomains() {
        let upstream_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream = upstream_socket.local_addr().unwrap();
        upstream_socket
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_for_thread = Arc::clone(&hits);
        thread::spawn(move || {
            let mut buffer = [0u8; 512];
            while let Ok((length, source)) = upstream_socket.recv_from(&mut buffer) {
                hits_for_thread.fetch_add(1, Ordering::SeqCst);
                buffer[2] = 0x81;
                buffer[3] = 0x80;
                let _ = upstream_socket.send_to(&buffer[..length], source);
            }
        });

        let domains = Arc::new(Mutex::new(vec!["example.com".to_string()]));
        let proxy = start("127.0.0.1:0".parse().unwrap(), vec![upstream], domains).unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let query = build_query("a.b.example.com");
        client.send_to(&query, proxy.addr).unwrap();
        let mut buffer = [0u8; 512];
        let (length, _) = client.recv_from(&mut buffer).unwrap();
        assert!(length > 12);
        assert_eq!(&buffer[..2], &[0x12, 0x34]);
        assert_eq!(buffer[2] & 0x80, 0x80);
        assert_eq!(buffer[3] & 0x0F, 3);
        thread::sleep(Duration::from_millis(150));
        assert_eq!(hits.load(Ordering::SeqCst), 0);

        let tcp = TcpStream::connect(proxy.addr).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        tcp.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut tcp = tcp;
        write_tcp_message(&mut tcp, &build_query("example.com")).unwrap();
        let response = read_tcp_message(&mut tcp).unwrap();
        assert_eq!(response[3] & 0x0F, 3);
    }

    #[test]
    fn other_names_are_forwarded_to_upstream() {
        let upstream_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream = upstream_socket.local_addr().unwrap();
        upstream_socket
            .set_read_timeout(Some(Duration::from_millis(800)))
            .unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_for_thread = Arc::clone(&hits);
        thread::spawn(move || {
            let mut buffer = [0u8; 512];
            if let Ok((length, source)) = upstream_socket.recv_from(&mut buffer) {
                hits_for_thread.fetch_add(1, Ordering::SeqCst);
                buffer[2] = 0x81;
                buffer[3] = 0x80;
                let _ = upstream_socket.send_to(&buffer[..length], source);
            }
        });

        let domains = Arc::new(Mutex::new(Vec::new()));
        let proxy = start("127.0.0.1:0".parse().unwrap(), vec![upstream], domains).unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client
            .send_to(&build_query("example.org"), proxy.addr)
            .unwrap();
        let mut buffer = [0u8; 512];
        let (_, _) = client.recv_from(&mut buffer).unwrap();
        assert_eq!(buffer[3] & 0x0F, 0);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }
}
