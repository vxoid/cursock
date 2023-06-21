# Cursock v1.2.7
Crate for raw socketing, can send raw packets and some protocols

## Changelog
- reimplemented `Icmp`, `Arp` and `Adapter` structs
- added `IpPacked` which represents eth + (ipv4 | ipv6) headers
- handling dest mac address for `Icmp` struct

## Todo
- Add ipv6 support for Icmp

## Protocols
- Arp
- Icmp

## Platforms
- Windows (npcap)
- Linux

## Links
- docs.rs - https://docs.rs/cursock
- github - https://github.com/CURVoid/cursock.git

## Examples
```rust
use cursock::*;
use cursock::utils::*;

let socket = Socket::new("wlan0").expect("initialize error");
let mut buffer = [0; 1000];

socket.read_raw_packet(&mut buffer).expect("read error");

socket.destroy();
```