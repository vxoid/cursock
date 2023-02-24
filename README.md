# Cursock v1.2.4
Crate for raw socketing, can send raw packets and some protocols

## Protocols
- [x] Arp
- [x] Icmp

## Other
- [x] Tun device manager

## Platforms
- [x] Windows (npcap, wintun)
- [x] Linux

## Update Logs
- Added more cross-compilation options for cpu architecture
- Added tun device manager
- Automated destruction, made destruct methods private to avoid memory leaks from user
- Fixed raw socket read timeout error

## Links
- [x] docs.rs - https://docs.rs/cursock
- [x] github - https://github.com/CURVoid/cursock.git

## Example
```rust
#[cfg(target_os = "linux")]
let socket = cursock::Socket::new("wlan0", true).expect("initialize error"); // Linux
#[cfg(target_os = "windows")]
let socket = cursock::Socket::new("{D37YDFA1-7F4F-F09E-V622-5PACEF22AE49}", true).expect("initialize error"); // Windows
// Since windows socket implementation is using npcap you should pass "npcap-like" guid

let buffer: [u8; 1024] = [0; 1024];

socket.send_raw_packet(&buffer, true).expect("send error");

socket.destroy()
```