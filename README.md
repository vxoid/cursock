# Cursock
Crate for raw socketing, can send raw packets and some protocols

## Protocols
- [x] Arp

## Platforms
- [x] Windows (npcap)
- [x] Linux

## Links
- [x] docs.rs - https://docs.rs/cursock
- [x] github - https://github.com/CURVoid/cursock.git

## Examples
```rust
#[cfg(target_os = "linux")]
let socket = cursock::Socket::new("wlan0", true).expect("initialize error"); // Linux
#[cfg(target_os = "windows")]
let socket = cursock::Socket::new("{D37YDFA1-7F4F-F09E-V622-5PACEF22AE49}", true).expect("initialize error"); // Windows
// Since windows socket implementation is using npcap you should pass "npcap-like" interface

let buffer: [u8; 1024] = [0; 1024];

socket.send_raw_packet(&buffer, true).expect("send error");

socket.destroy()
```