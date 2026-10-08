mod blocklist;
mod dns;
mod helper;
mod system;

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[derive(Debug, PartialEq, Eq)]
enum Action {
    Add(String),
    Remove(String),
    List,
    Status,
    HelperStart,
    HelperStop,
    HelperServe,
}

#[derive(Debug, PartialEq, Eq)]
enum HumanAction {
    Add(String),
    Remove(String),
    List,
    Status,
    Start,
    Stop,
    Help,
}

fn main() {
    let code = match run(std::env::args().skip(1)) {
        Ok(output) => {
            if !output.is_empty() {
                println!("{output}");
            }
            0
        }
        Err(error) => {
            eprintln!("{error}");
            1
        }
    };
    std::process::exit(code);
}

fn run(args: impl Iterator<Item = String>) -> Result<String, String> {
    let args: Vec<String> = args.collect();
    if args.first().map(String::as_str) == Some("--data-dir") {
        let (data_dir, action) = parse(&args)?;
        return dispatch(&data_dir, action);
    }
    let (data_dir, action) = parse_human(&args)?;
    dispatch_human(&data_dir, action)
}

fn dispatch(data_dir: &Path, action: Action) -> Result<String, String> {
    match action {
        Action::Add(input) => blocklist::add_domain(data_dir, &input),
        Action::Remove(input) => blocklist::remove_domain(data_dir, &input).map(|()| String::new()),
        Action::List => {
            let list = blocklist::load(data_dir)?;
            serde_json::to_string(&list.domains).map_err(|error| error.to_string())
        }
        Action::Status => helper::status(data_dir),
        Action::HelperStart => helper::start(data_dir),
        Action::HelperStop => helper::stop(data_dir),
        Action::HelperServe => helper::serve(data_dir).map(|()| String::new()),
    }
}

fn dispatch_human(data_dir: &Path, action: HumanAction) -> Result<String, String> {
    match action {
        HumanAction::Help => Ok(usage()),
        HumanAction::Add(input) => blocklist::add_domain(data_dir, &input),
        HumanAction::Remove(input) => {
            let domain = blocklist::normalize_input(&input)?;
            blocklist::remove_domain(data_dir, &domain)?;
            Ok(format!("removed {domain}"))
        }
        HumanAction::List => {
            let list = blocklist::load(data_dir)?;
            Ok(list.domains.join("\n"))
        }
        HumanAction::Status => format_status(&helper::status(data_dir)?),
        HumanAction::Start => switch_blocking(data_dir, "start"),
        HumanAction::Stop => switch_blocking(data_dir, "stop"),
    }
}

fn parse(args: &[String]) -> Result<(PathBuf, Action), String> {
    if args.first().map(String::as_str) != Some("--data-dir") || args.len() < 3 {
        return Err("Usage: keep-me-out --data-dir DIR add|remove|list|status|helper ...".into());
    }
    let data_dir = PathBuf::from(&args[1]);
    let action = match args[2].as_str() {
        "add" => Action::Add(
            args.get(3)
                .cloned()
                .ok_or_else(|| "Add needs a domain or link.".to_string())?,
        ),
        "remove" => Action::Remove(
            args.get(3)
                .cloned()
                .ok_or_else(|| "Remove needs a domain.".to_string())?,
        ),
        "list" => Action::List,
        "status" => Action::Status,
        "helper" => match args.get(3).map(String::as_str) {
            Some("start") => Action::HelperStart,
            Some("stop") => Action::HelperStop,
            Some("serve") => Action::HelperServe,
            _ => return Err("helper needs start, stop, or serve.".into()),
        },
        other => return Err(format!("Unknown command: {other}")),
    };
    Ok((data_dir, action))
}

fn parse_human(args: &[String]) -> Result<(PathBuf, HumanAction), String> {
    let mut dir = None;
    let mut words = Vec::new();
    let mut rest = args.iter().map(String::as_str);
    while let Some(arg) = rest.next() {
        if arg == "--dir" {
            if dir.is_some() {
                return Err("--dir was given twice.".into());
            }
            let value = rest
                .next()
                .ok_or_else(|| "--dir needs a directory.".to_string())?;
            dir = Some(PathBuf::from(value));
        } else if arg == "--help" || arg == "-h" {
            words.push("help");
        } else {
            words.push(arg);
        }
    }

    let data_dir = match dir {
        Some(path) => path,
        None => default_data_dir()?,
    };
    let mut words = words.into_iter();
    let action = match words.next() {
        None | Some("help") => HumanAction::Help,
        Some("add") => HumanAction::Add(
            words
                .next()
                .ok_or_else(|| "Add needs a domain or link.".to_string())?
                .to_string(),
        ),
        Some("remove") => HumanAction::Remove(
            words
                .next()
                .ok_or_else(|| "Remove needs a domain.".to_string())?
                .to_string(),
        ),
        Some("list") => HumanAction::List,
        Some("status") => HumanAction::Status,
        Some("start") => HumanAction::Start,
        Some("stop") => HumanAction::Stop,
        Some(other) => return Err(format!("Unknown command: {other}\n\n{}", usage())),
    };
    if words.next().is_some() {
        return Err(format!("Too many arguments.\n\n{}", usage()));
    }
    Ok((data_dir, action))
}

fn default_data_dir() -> Result<PathBuf, String> {
    let home = std::env::var("HOME").map_err(|_| "HOME is not set.".to_string())?;
    Ok(PathBuf::from(home).join("Library/Application Support/KeepMeOut"))
}

fn usage() -> String {
    "\
Usage: keep-me-out [--dir DIR] <command>

  add DOMAIN     Block a domain or a pasted link
  remove DOMAIN  Stop blocking a domain
  list           Print blocked domains, one per line
  status         Show whether blocking is on
  start          Point DNS at the local proxy
  stop           Restore the previous DNS servers
  help           Show this help

DIR defaults to ~/Library/Application Support/KeepMeOut, the same folder the window uses.
start and stop ask for an administrator password."
        .to_string()
}

#[derive(serde::Deserialize)]
struct HumanStatus {
    domains: Vec<String>,
    blocking: bool,
    stale: bool,
}

fn format_status(json: &str) -> Result<String, String> {
    let status: HumanStatus = serde_json::from_str(json)
        .map_err(|_| "Couldn't read blocker status.".to_string())?;
    let line = if status.blocking {
        "blocking"
    } else if status.stale {
        "blocking stopped unexpectedly"
    } else {
        "not blocking"
    };
    if status.domains.is_empty() {
        Ok(line.to_string())
    } else {
        Ok(format!("{line}\n{}", status.domains.join("\n")))
    }
}

fn switch_blocking(data_dir: &Path, command: &str) -> Result<String, String> {
    std::fs::create_dir_all(data_dir)
        .map_err(|error| format!("Couldn't prepare the data directory: {error}"))?;
    let output = if is_root() {
        match command {
            "start" => helper::start(data_dir)?,
            "stop" => helper::stop(data_dir)?,
            _ => return Err(format!("Unknown command: {command}")),
        }
    } else {
        sudo_helper(data_dir, command)?
    };
    Ok(match (command, output.trim()) {
        ("start", "already blocking") => "already blocking".to_string(),
        ("start", _) => "blocking".to_string(),
        _ => "not blocking".to_string(),
    })
}

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// Re-run the window protocol as root. The password prompt stays on the
/// terminal. The helper's own text comes back on the pipe.
fn sudo_helper(data_dir: &Path, command: &str) -> Result<String, String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("Couldn't find the helper binary: {error}"))?;
    let mut child = Command::new("/usr/bin/sudo")
        .arg("--")
        .arg(&executable)
        .arg("--data-dir")
        .arg(data_dir)
        .arg("helper")
        .arg(command)
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|error| format!("Couldn't run sudo: {error}"))?;
    let mut output = String::new();
    if let Some(mut pipe) = child.stdout.take() {
        pipe.read_to_string(&mut output)
            .map_err(|error| format!("Couldn't read sudo output: {error}"))?;
    }
    let status = child
        .wait()
        .map_err(|error| format!("Couldn't wait for sudo: {error}"))?;
    if !status.success() {
        // The helper already wrote the reason to the terminal.
        std::process::exit(status.code().unwrap_or(1));
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn parses_commands() {
        let (dir, action) = parse(&args(&["--data-dir", "/tmp/x", "add", "YouTube.com"])).unwrap();
        assert_eq!(dir, PathBuf::from("/tmp/x"));
        assert_eq!(action, Action::Add("YouTube.com".into()));

        assert!(matches!(
            parse(&args(&["--data-dir", "/tmp/x", "helper", "start"]))
                .unwrap()
                .1,
            Action::HelperStart
        ));
        assert!(parse(&args(&["status"])).is_err());
        assert!(parse(&args(&["--data-dir", "/tmp/x", "helper"])).is_err());
    }
}
