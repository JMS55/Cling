# cling (Cloudflare Latency Inspector - Networking Gui)
### Made for my Cloudflare Summer 2020 internship application

## Requirements
* Linux
* Nightly Rust
* libcap
    * Fedora: `libcap-devel`
    * Debian/Ubuntu: `libcap-dev`
    * Arch: `libcap`

## Building From Source
1. `git clone https://github.com/JMS55/cling`
2. `cd cling`
3. `rustup override set nightly`
4. `cargo build --release`
5. `sudo setcap cap_net_raw+p ./target/release/cling`

## Running
```
cling (Cloudflare Latency Inspector - Networking Gui) 1.0
JMS
Check latency to a server

USAGE:
    cling <ip_or_domain>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

ARGS:
    <ip_or_domain>    the IPv4 address or the domain to ping
```

## Privacy
When cling is passed a domain, it will connect to 1.1.1.1 (Cloudflare), 8.8.8.8 (Google), or 8.8.4.4 (Google) in order to lookup the IP address for that domain
