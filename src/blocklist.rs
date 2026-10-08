use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use url::{Host, Url};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Blocklist {
    #[serde(default)]
    pub domains: Vec<String>,
}

pub fn blocklist_path(data_dir: &Path) -> PathBuf {
    data_dir.join("blocklist.json")
}

pub fn load(data_dir: &Path) -> Result<Blocklist, String> {
    let path = blocklist_path(data_dir);
    if !path.exists() {
        return Ok(Blocklist {
            domains: Vec::new(),
        });
    }
    let text = fs::read_to_string(&path)
        .map_err(|error| format!("Couldn't read the blocklist: {error}"))?;
    serde_json::from_str(&text).map_err(|error| format!("Couldn't read the blocklist: {error}"))
}

pub fn save(data_dir: &Path, list: &Blocklist) -> Result<(), String> {
    fs::create_dir_all(data_dir)
        .map_err(|error| format!("Couldn't save the blocklist: {error}"))?;
    let bytes = serde_json::to_vec_pretty(list).map_err(|error| error.to_string())?;
    atomic_write(&blocklist_path(data_dir), &bytes)
}

pub fn add_domain(data_dir: &Path, input: &str) -> Result<String, String> {
    let domain = normalize_input(input)?;
    let mut list = load(data_dir)?;
    if !list.domains.iter().any(|existing| existing == &domain) {
        list.domains.push(domain.clone());
        save(data_dir, &list)?;
    }
    Ok(domain)
}

pub fn remove_domain(data_dir: &Path, input: &str) -> Result<(), String> {
    let domain = normalize_input(input).unwrap_or_else(|_| query_name(input));
    let mut list = load(data_dir)?;
    list.domains.retain(|existing| existing != &domain);
    save(data_dir, &list)
}

pub fn file_mtime(path: &Path) -> Option<SystemTime> {
    fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .ok()
}

/// Turn a domain or a pasted link into the name that should be blocked.
pub fn normalize_input(input: &str) -> Result<String, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("Enter a domain, like example.com.".into());
    }

    let host = extract_host(trimmed)?;
    let host = host.trim().trim_matches('.').to_ascii_lowercase();
    let host = host.strip_prefix("*.").unwrap_or(&host);
    let ascii = idna::domain_to_ascii(host).map_err(|_| "That isn't a domain name.".to_string())?;
    let ascii = ascii.trim_matches('.').to_ascii_lowercase();
    let ascii = ascii.strip_prefix("www.").unwrap_or(&ascii);

    if ascii == "localhost" || ascii.ends_with(".localhost") {
        return Err("localhost can't be blocked.".into());
    }
    validate_hostname(ascii)?;
    Ok(ascii.to_string())
}

pub fn name_matches(query: &str, domain: &str) -> bool {
    let query = query_name(query);
    let domain = query_name(domain);
    !domain.is_empty() && (query == domain || query.ends_with(&format!(".{domain}")))
}

pub fn query_name(name: &str) -> String {
    name.trim().trim_matches('.').to_ascii_lowercase()
}

fn extract_host(input: &str) -> Result<String, String> {
    let looks_like_url =
        input.contains("://") || input.contains('/') || input.contains('?') || input.contains('#');

    if !looks_like_url {
        if let Some((host, port)) = input.rsplit_once(':') {
            if !host.is_empty()
                && !host.contains(']')
                && !port.is_empty()
                && port.chars().all(|character| character.is_ascii_digit())
            {
                return Ok(host.to_string());
            }
        }
        return Ok(input.to_string());
    }

    let with_scheme = if input.contains("://") {
        input.to_string()
    } else {
        format!("http://{input}")
    };
    let url = Url::parse(&with_scheme).map_err(|_| "That isn't a domain name.".to_string())?;
    match url.host() {
        Some(Host::Domain(domain)) => Ok(domain.to_string()),
        Some(Host::Ipv4(_) | Host::Ipv6(_)) => {
            Err("Enter a domain name, not an IP address.".into())
        }
        None => Err("That isn't a domain name.".into()),
    }
}

fn validate_hostname(host: &str) -> Result<(), String> {
    if host.is_empty() || host.len() > 253 || !host.contains('.') {
        return Err("Enter a domain, like example.com.".into());
    }
    for label in host.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err("That isn't a domain name.".into());
        }
    }
    Ok(())
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let temporary = path.with_extension("json.tmp");
    {
        let mut file = File::create(&temporary)
            .map_err(|error| format!("Couldn't save the blocklist: {error}"))?;
        file.write_all(bytes)
            .map_err(|error| format!("Couldn't save the blocklist: {error}"))?;
        let _ = file.sync_all();
    }
    fs::rename(&temporary, path).map_err(|error| format!("Couldn't save the blocklist: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_DIRS: AtomicU64 = AtomicU64::new(0);

    fn temp_dir() -> PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "keep-me-out-blocklist-{}-{}",
            std::process::id(),
            TEMP_DIRS.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        directory
    }

    #[test]
    fn normalizes_links_and_domains() {
        let cases = [
            ("https://www.YouTube.com/feed", "youtube.com"),
            ("youtube.com.", "youtube.com"),
            ("WWW.Example.com", "example.com"),
            ("mail.google.com", "mail.google.com"),
            ("http://example.com/a/b", "example.com"),
            ("https://example.com:8443/x", "example.com"),
            ("*.Example.com", "example.com"),
            ("example.com:443", "example.com"),
            ("www.mail.google.com", "mail.google.com"),
            ("https://münchen.de/a", "xn--mnchen-3ya.de"),
            ("www.münchen.de", "xn--mnchen-3ya.de"),
        ];
        for (input, expected) in cases {
            assert_eq!(normalize_input(input).unwrap(), expected, "{input}");
        }
    }

    #[test]
    fn rejects_junk_localhost_and_ips() {
        for input in [
            "",
            "   ",
            "localhost",
            "http://localhost/x",
            "http://127.0.0.1/",
            "com",
            "not a domain",
            "https://",
        ] {
            assert!(normalize_input(input).is_err(), "{input}");
        }
    }

    #[test]
    fn matches_the_domain_and_its_subdomains_only() {
        assert!(name_matches("example.com", "example.com"));
        assert!(name_matches("example.com.", "example.com"));
        assert!(name_matches("www.example.com", "example.com"));
        assert!(name_matches("a.b.example.com", "example.com"));
        assert!(!name_matches("notexample.com", "example.com"));
        assert!(!name_matches("example.com.evil.org", "example.com"));
        assert!(!name_matches("example.co", "example.com"));
    }

    #[test]
    fn add_is_idempotent_and_remove_drops_the_domain() {
        let directory = temp_dir();
        assert_eq!(
            add_domain(&directory, "https://www.YouTube.com/feed").unwrap(),
            "youtube.com"
        );
        add_domain(&directory, "youtube.com").unwrap();
        let list = load(&directory).unwrap();
        assert_eq!(list.domains, vec!["youtube.com".to_string()]);
        remove_domain(&directory, "youtube.com").unwrap();
        assert!(load(&directory).unwrap().domains.is_empty());
        let _ = fs::remove_dir_all(&directory);
    }
}
