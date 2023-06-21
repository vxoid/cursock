# Cursock v1.0.1
Crate for raw socketing, can send raw packets and some protocols

## Changelog
- Reimplemented Icmp and Arp protos
- removed `curerr` crate, now using std::io::Error for error handling
- Added Adapter struct

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

#[cfg(target_os = "linux")]
let socket = Socket::new("wlan0", IpVer::V6).expect("initialize error"); // Linux
#[cfg(target_os = "windows")]
let socket = Socket::new("10", IpVer::V6).expect("initialize error"); // Windows, id of the interface you can get running "route PRINT"

let buffer: [u8; 1024] = [0; 1024];

socket.send_raw_packet(&buffer).expect("send error");

socket.destroy()
```