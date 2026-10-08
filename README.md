# Keep Me Out

A macOS window for blocking whole domains. The window is SwiftUI. The blocklist, DNS proxy, and start/stop switch are a Rust program.

Adding `example.com` blocks that name and every subdomain, such as `www.example.com`. Start and Stop ask for an administrator password. Start points DNS at a local proxy on `127.0.0.1`. Stop puts the previous DNS servers back. Closing the window leaves blocking on.

Browsers using Secure DNS, and iCloud Private Relay, bypass system DNS. Turn Secure DNS off in the browser for the block to apply there.

## Run

```bash
cargo build
swift build
swift run
```

Or build an app and open it:

```bash
scripts/bundle.sh
open "dist/Keep Me Out.app"
```

## CLI

The same binary runs from the terminal. It uses the same folder as the window, `~/Library/Application Support/KeepMeOut`, so a domain added in one place shows up in the other.

```bash
cargo build --release
cp target/release/keep-me-out /usr/local/bin/

keep-me-out add https://www.youtube.com/feed
keep-me-out list
keep-me-out status
keep-me-out start
keep-me-out stop
keep-me-out remove youtube.com
```

`add` takes a domain or a pasted link and prints the stored name. `list` prints one domain per line. `status` prints `blocking`, `not blocking`, or `blocking stopped unexpectedly`, then the domains. `start` and `stop` ask for an administrator password. `--dir DIR` uses a different folder.

## If the network stays dead

Blocking points DNS at `127.0.0.1`. If pages will not load and the app will not open, restore DNS in Terminal. Replace `Wi-Fi` with a service from `networksetup -listallnetworkservices`:

```bash
sudo networksetup -setdnsservers Wi-Fi Empty
sudo dscacheutil -flushcache
sudo killall -HUP mDNSResponder
```

`Empty` returns that service to the DNS it gets from the network.
