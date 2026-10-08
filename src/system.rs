use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::process::Command;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceDns {
    pub name: String,
    pub servers: Vec<String>,
}

pub fn snapshot() -> Result<Vec<ServiceDns>, String> {
    let output = run_networksetup(&["-listallnetworkservices".to_string()])?;
    let mut services = Vec::new();
    for name in parse_service_list(&output) {
        let servers = get_servers(&name)?;
        services.push(ServiceDns { name, servers });
    }
    Ok(services)
}

pub fn get_servers(service: &str) -> Result<Vec<String>, String> {
    let output = run_networksetup(&["-getdnsservers".to_string(), service.to_string()])?;
    Ok(parse_dns_servers(&output))
}

pub fn set_servers(service: &str, servers: &[String]) -> Result<(), String> {
    let mut args = vec!["-setdnsservers".to_string(), service.to_string()];
    if servers.is_empty() {
        args.push("Empty".to_string());
    } else {
        args.extend(servers.iter().cloned());
    }
    run_networksetup(&args).map(|_| ())
}

/// Point every service at the local proxy. On failure, put back the originals
/// already switched so a partial change does not stick.
pub fn point_at_local(originals: &[ServiceDns]) -> Result<(), String> {
    let mut changed: Vec<&ServiceDns> = Vec::new();
    for service in originals {
        if let Err(error) = set_servers(&service.name, &["127.0.0.1".to_string()]) {
            for done in &changed {
                let _ = set_servers(&done.name, &done.servers);
            }
            let _ = set_servers(&service.name, &service.servers);
            return Err(error);
        }
        changed.push(service);
    }
    Ok(())
}

pub fn restore(services: &[ServiceDns]) -> Result<(), String> {
    let mut errors = Vec::new();
    for service in services {
        if let Err(error) = set_servers(&service.name, &service.servers) {
            errors.push(error);
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join(" "))
    }
}

pub fn flush_cache() {
    let _ = Command::new("/usr/bin/dscacheutil")
        .arg("-flushcache")
        .status();
    let _ = Command::new("/usr/bin/killall")
        .args(["-HUP", "mDNSResponder"])
        .status();
}

/// `127.0.0.1` is our proxy, never the user's saved DNS. A stale run must not
/// be written back as the "original" servers.
pub fn merge_originals(previous: Option<&[ServiceDns]>, current: &[ServiceDns]) -> Vec<ServiceDns> {
    current
        .iter()
        .map(|service| {
            let usable = without_loopback(&service.servers);
            let servers = if !usable.is_empty() {
                usable
            } else if service.servers.iter().any(|server| is_loopback_ip(server)) {
                previous
                    .and_then(|saved| saved.iter().find(|item| item.name == service.name))
                    .map(|item| without_loopback(&item.servers))
                    .unwrap_or_default()
            } else {
                Vec::new()
            };
            ServiceDns {
                name: service.name.clone(),
                servers,
            }
        })
        .collect()
}

pub fn choose_upstream(services: &[ServiceDns]) -> Vec<String> {
    for service in services {
        let servers = without_loopback(&service.servers);
        if !servers.is_empty() {
            return servers;
        }
    }
    vec!["1.1.1.1".to_string(), "1.0.0.1".to_string()]
}

pub fn parse_service_list(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter(|line| !line.starts_with('*'))
        .filter(|line| !line.contains("denotes that a network service is disabled"))
        .map(str::to_string)
        .collect()
}

pub fn parse_dns_servers(text: &str) -> Vec<String> {
    let trimmed = text.trim();
    if trimmed.is_empty() || trimmed.starts_with("There aren't") {
        return Vec::new();
    }
    trimmed
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect()
}

fn without_loopback(servers: &[String]) -> Vec<String> {
    servers
        .iter()
        .filter(|server| !is_loopback_ip(server))
        .cloned()
        .collect()
}

fn is_loopback_ip(text: &str) -> bool {
    text.parse::<IpAddr>()
        .map(|address| address.is_loopback())
        .unwrap_or(false)
}

fn run_networksetup(args: &[String]) -> Result<String, String> {
    let output = Command::new("/usr/sbin/networksetup")
        .args(args)
        .output()
        .map_err(|error| format!("Couldn't run networksetup: {error}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if output.status.success() {
        Ok(stdout.to_string())
    } else {
        let detail = if stderr.trim().is_empty() {
            stdout.trim()
        } else {
            stderr.trim()
        };
        Err(format!("networksetup failed: {detail}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service(name: &str, servers: &[&str]) -> ServiceDns {
        ServiceDns {
            name: name.to_string(),
            servers: servers.iter().map(|server| (*server).to_string()).collect(),
        }
    }

    #[test]
    fn parses_services_and_skips_disabled_ones() {
        let text = "\
An asterisk (*) denotes that a network service is disabled.
Wi-Fi
USB 10/100/1000 LAN
*Thunderbolt Bridge
";
        assert_eq!(
            parse_service_list(text),
            vec!["Wi-Fi".to_string(), "USB 10/100/1000 LAN".to_string()]
        );
    }

    #[test]
    fn parses_dhcp_and_server_lists() {
        assert!(parse_dns_servers("There aren't any DNS Servers set on Wi-Fi.\n").is_empty());
        assert_eq!(
            parse_dns_servers("1.1.1.1\n8.8.8.8\n"),
            vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()]
        );
    }

    #[test]
    fn merge_never_saves_the_local_proxy_as_the_users_dns() {
        let current = vec![service("Wi-Fi", &["127.0.0.1"])];
        assert!(merge_originals(None, &current)[0].servers.is_empty());

        let previous = vec![service("Wi-Fi", &["8.8.8.8"])];
        assert_eq!(
            merge_originals(Some(&previous), &current)[0].servers,
            vec!["8.8.8.8".to_string()]
        );

        let dhcp = vec![service("Wi-Fi", &[])];
        assert!(merge_originals(Some(&dhcp), &current)[0].servers.is_empty());

        let mixed = vec![service("Wi-Fi", &["127.0.0.1", "9.9.9.9"])];
        assert_eq!(
            merge_originals(None, &mixed)[0].servers,
            vec!["9.9.9.9".to_string()]
        );

        let real = vec![service("Wi-Fi", &["1.1.1.1"])];
        assert_eq!(
            merge_originals(None, &real)[0].servers,
            vec!["1.1.1.1".to_string()]
        );
    }

    #[test]
    fn upstream_uses_saved_servers_then_cloudflare() {
        let services = vec![
            service("Wi-Fi", &[]),
            service("Ethernet", &["127.0.0.1", "9.9.9.9"]),
        ];
        assert_eq!(choose_upstream(&services), vec!["9.9.9.9".to_string()]);
        assert_eq!(
            choose_upstream(&[service("Wi-Fi", &[])]),
            vec!["1.1.1.1".to_string(), "1.0.0.1".to_string()]
        );
    }
}
