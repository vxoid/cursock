mod consts;
mod structs;

pub use consts::*;
pub use structs::*;

#[cfg(target_os = "linux")]
pub type SocklenT = u32;

#[link(name = "cursock")]
#[cfg(target_os = "linux")]
extern "C" {
    pub fn recvfrom(
        socket: i32,
        buffer: *mut std::os::raw::c_void,
        len: usize,
        flags: i32,
        src_addr: *mut sockaddr,
        addrlen: *mut SocklenT,
    ) -> isize;
    pub fn sendto(
        sockfd: i32,
        buf: *const std::os::raw::c_void,
        len: usize,
        flags: i32,
        dest_addr: *const sockaddr,
        addrlen: SocklenT,
    ) -> isize;
    pub fn read(fd: i32, buf: *mut std::os::raw::c_void, count: usize) -> isize;
    pub fn bind(sockfd: i32, addr: *const sockaddr, addrlen: SocklenT) -> i32;
    pub fn socket(domain: i32, type_: i32, protocol: i32) -> i32;
    pub fn open(pathname: *const i8, flags: i32) -> i32;
    pub fn ioctl(fd: i32, request: u64, ...) -> i32;
    pub fn perror(str: *const i8);
    pub fn close(fd: i32) -> i32;
}

#[link(name = "iphlpapi")]
#[cfg(target_os = "windows")]
extern "C" {
    pub fn GetAdaptersInfo(adapterinfo: *mut IP_ADAPTER_INFO, sizepointer: *mut u32) -> u32;
}

#[link(name = "wpcap", kind = "static")]
#[cfg(target_os = "windows")]
extern "C" {
    pub fn pcap_open(
        source: *const i8,
        snaplen: i32,
        flags: i32,
        read_timeout: i32,
        auth: *mut pcap_rmtauth,
        errbuf: *mut i8,
    ) -> *mut pcap;
    pub fn pcap_findalldevs_ex(
        source: *const i8,
        auth: *mut pcap_rmtauth,
        alldevs: *mut *mut pcap_if,
        errbuf: *mut i8,
    ) -> i32;
    pub fn pcap_next_ex(_: *mut pcap, _: *mut *mut pcap_pkthdr, _: *mut *const u8) -> i32;
    pub fn pcap_inject(_: *mut pcap, _: *const std::os::raw::c_void, _: usize) -> i32;
    pub fn pcap_sendpacket(_: *mut pcap, _: *const u8, _: i32) -> i32;
    pub fn pcap_geterr(_: *mut pcap) -> *mut i8;
}

#[cfg(target_os = "windows")]
pub type WintunAdapterHandle = *mut std::os::raw::c_void;
#[cfg(target_os = "windows")]
pub type WintunSessionHandle = *mut std::os::raw::c_void;
#[cfg(target_os = "windows")]
pub type GUID = _GUID;

#[link(name = "wintun")]
#[cfg(target_os = "windows")]
extern "C" {
    pub fn WintunCreateAdapter(name: *const u16, tunnel_type: *const u16, requested_GUID: *const GUID) -> WintunAdapterHandle;
    pub fn WintunStartSession(adapter: WintunAdapterHandle, _: u32) -> WintunSessionHandle;
    pub fn WintunAllocateSendPacket(session: WintunSessionHandle, size: u32) -> *mut u8;
    pub fn WintunReceivePacket(session: WintunSessionHandle, size: *mut u32) -> *mut u8;
    pub fn WintunSendPacket(session: WintunSessionHandle, packet: *mut u8);
}

pub const fn null<T>() -> *const T {
    0 as *const T
}

pub const fn null_mut<T>() -> *mut T {
    0 as *mut T
}

pub fn htons(u: u16) -> u16 {
    u.to_be()
}

pub fn ntohs(u: u16) -> u16 {
    u16::from_be(u)
}
