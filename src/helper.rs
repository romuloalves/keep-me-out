use crate::blocklist::{self, file_mtime};
use crate::dns;
use crate::system::{self, ServiceDns};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Write;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct State {
    pid: u32,
    services: Vec<ServiceDns>,
    upstream: Vec<String>,
}

pub fn start(data_dir: &Path) -> Result<String, String> {
    fs::create_dir_all(data_dir)
        .map_err(|error| format!("Couldn't prepare the data directory: {error}"))?;
    if let Some(state) = read_state(data_dir)? {
        if pid_alive(state.pid) {
            return Ok("already blocking".into());
        }
    }

    let previous = read_state(data_dir)?;
    let current = system::snapshot()?;
    let originals = system::merge_originals(
        previous.as_ref().map(|state| state.services.as_slice()),
        &current,
    );
    let upstream = system::choose_upstream(&originals);
    write_json(&upstream_path(data_dir), &upstream)?;

    let _ = fs::remove_file(ready_path(data_dir));
    let _ = fs::remove_file(error_path(data_dir));
    let mut child = spawn_serve(data_dir)?;
    if let Err(error) = wait_until_ready(data_dir, &mut child) {
        let _ = child.kill();
        return Err(error);
    }

    if let Err(error) = system::point_at_local(&originals) {
        let _ = child.kill();
        return Err(error);
    }

    let state = State {
        pid: child.id(),
        services: originals,
        upstream,
    };
    if let Err(error) = write_json(&state_path(data_dir), &state) {
        let _ = system::restore(&state.services);
        let _ = child.kill();
        return Err(error);
    }
    system::flush_cache();
    Ok("ok".into())
}

pub fn stop(data_dir: &Path) -> Result<String, String> {
    let state = read_state(data_dir)?.ok_or_else(|| "Blocking is already off.".to_string())?;
    system::restore(&state.services)?;
    terminate(state.pid);
    system::flush_cache();
    let _ = fs::remove_file(state_path(data_dir));
    let _ = fs::remove_file(ready_path(data_dir));
    let _ = fs::remove_file(upstream_path(data_dir));
    let _ = fs::remove_file(error_path(data_dir));
    Ok("ok".into())
}

pub fn serve(data_dir: &Path) -> Result<(), String> {
    let upstream = read_upstream(data_dir);
    let domains = Arc::new(Mutex::new(blocklist::load(data_dir)?.domains));
    let watched = Arc::clone(&domains);
    let watch_dir = data_dir.to_path_buf();
    thread::spawn(move || watch_blocklist(watch_dir, watched));

    let bind: SocketAddr = "127.0.0.1:53".parse().unwrap();
    let handle = match dns::start(bind, upstream, domains) {
        Ok(handle) => handle,
        Err(error) => {
            let _ = write_text(&error_path(data_dir), &error);
            return Err(error);
        }
    };
    write_text(&ready_path(data_dir), "ok")?;
    eprintln!("listening on {}", handle.addr);
    // The process stays up until Stop signals it. Forgetting the handle keeps
    // the sockets open; dropping it would shut the proxy down.
    std::mem::forget(handle);
    loop {
        thread::sleep(Duration::from_secs(3600));
    }
}

pub fn status(data_dir: &Path) -> Result<String, String> {
    let domains = blocklist::load(data_dir)?.domains;
    let (blocking, stale) = match read_state(data_dir)? {
        Some(state) if pid_alive(state.pid) => (true, false),
        Some(_) => (false, true),
        None => (false, false),
    };
    #[derive(Serialize)]
    struct Status<'a> {
        domains: &'a [String],
        blocking: bool,
        stale: bool,
    }
    serde_json::to_string(&Status {
        domains: &domains,
        blocking,
        stale,
    })
    .map_err(|error| error.to_string())
}

fn watch_blocklist(data_dir: PathBuf, domains: Arc<Mutex<Vec<String>>>) {
    let path = blocklist::blocklist_path(&data_dir);
    let mut seen = file_mtime(&path);
    loop {
        thread::sleep(Duration::from_millis(400));
        let modified = file_mtime(&path);
        if modified == seen {
            continue;
        }
        seen = modified;
        if let Ok(list) = blocklist::load(&data_dir) {
            if let Ok(mut guard) = domains.lock() {
                *guard = list.domains;
            }
            system::flush_cache();
        }
    }
}

fn spawn_serve(data_dir: &Path) -> Result<Child, String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("Couldn't find the helper binary: {error}"))?;
    let log = File::create(log_path(data_dir)).ok();
    let stdout = log
        .as_ref()
        .and_then(|file| file.try_clone().ok())
        .map(Stdio::from)
        .unwrap_or(Stdio::null());
    let stderr = log.map(Stdio::from).unwrap_or(Stdio::null());

    let mut command = Command::new(executable);
    command
        .arg("--data-dir")
        .arg(data_dir)
        .arg("helper")
        .arg("serve")
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr);
    // The admin shell exits when start returns. A new session keeps the proxy
    // from receiving SIGHUP with that shell.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            let _ = libc::signal(libc::SIGHUP, libc::SIG_IGN);
            Ok(())
        });
    }
    command
        .spawn()
        .map_err(|error| format!("Couldn't start the DNS proxy: {error}"))
}

fn wait_until_ready(data_dir: &Path, child: &mut Child) -> Result<(), String> {
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(3) {
        if ready_path(data_dir).exists() {
            return Ok(());
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("Couldn't check the DNS proxy: {error}"))?
        {
            return Err(serve_failure_message(data_dir, &status.to_string()));
        }
        if error_path(data_dir).exists() {
            let message = serve_failure_message(data_dir, "DNS proxy failed");
            let _ = child.kill();
            return Err(message);
        }
        thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    Err("DNS proxy did not start.".into())
}

fn serve_failure_message(data_dir: &Path, fallback: &str) -> String {
    fs::read_to_string(error_path(data_dir))
        .ok()
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
        .unwrap_or_else(|| fallback.to_string())
}

fn read_upstream(data_dir: &Path) -> Vec<SocketAddr> {
    let servers = fs::read_to_string(upstream_path(data_dir))
        .ok()
        .and_then(|text| serde_json::from_str::<Vec<String>>(&text).ok())
        .unwrap_or_else(|| vec!["1.1.1.1".to_string(), "1.0.0.1".to_string()]);
    let addresses = servers
        .iter()
        .filter_map(|server| {
            let ip = server.parse().ok()?;
            Some(SocketAddr::new(ip, 53))
        })
        .filter(|address| !(address.ip().is_loopback()))
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        vec!["1.1.1.1:53".parse().unwrap(), "1.0.0.1:53".parse().unwrap()]
    } else {
        addresses
    }
}

fn read_state(data_dir: &Path) -> Result<Option<State>, String> {
    let path = state_path(data_dir);
    if !path.exists() {
        return Ok(None);
    }
    let text = fs::read_to_string(&path)
        .map_err(|error| format!("Couldn't read blocking state: {error}"))?;
    serde_json::from_str(&text)
        .map(Some)
        .map_err(|error| format!("Couldn't read blocking state: {error}"))
}

pub fn pid_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    let result = unsafe { libc::kill(pid as i32, 0) };
    if result == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn terminate(pid: u32) {
    if !pid_alive(pid) {
        return;
    }
    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
    }
    let started = Instant::now();
    while pid_alive(pid) && started.elapsed() < Duration::from_secs(2) {
        thread::sleep(Duration::from_millis(50));
    }
    if pid_alive(pid) {
        unsafe {
            libc::kill(pid as i32, libc::SIGKILL);
        }
    }
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    write_bytes(path, &bytes)
}

fn write_text(path: &Path, text: &str) -> Result<(), String> {
    write_bytes(path, text.as_bytes())
}

fn write_bytes(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("Couldn't write {}: {error}", path.display()))?;
    }
    let temporary = path.with_extension("tmp");
    {
        let mut file = File::create(&temporary)
            .map_err(|error| format!("Couldn't write {}: {error}", path.display()))?;
        file.write_all(bytes)
            .map_err(|error| format!("Couldn't write {}: {error}", path.display()))?;
        let _ = file.sync_all();
    }
    fs::rename(&temporary, path)
        .map_err(|error| format!("Couldn't write {}: {error}", path.display()))?;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o644));
    Ok(())
}

fn state_path(data_dir: &Path) -> PathBuf {
    data_dir.join("state.json")
}

fn upstream_path(data_dir: &Path) -> PathBuf {
    data_dir.join("upstream.json")
}

fn ready_path(data_dir: &Path) -> PathBuf {
    data_dir.join("ready")
}

fn error_path(data_dir: &Path) -> PathBuf {
    data_dir.join("serve-error")
}

fn log_path(data_dir: &Path) -> PathBuf {
    data_dir.join("serve.log")
}
