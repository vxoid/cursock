mod consts;
#[cfg(target_os = "windows")]
mod iphlpapi;
mod structs;

use std::os::raw::c_void;

pub use consts::*;
#[cfg(target_os = "windows")]
pub use iphlpapi::*;
pub use structs::*;

#[cfg(target_os = "linux")]
pub type SocklenT = u32;

#[link(name = "cursock")]
#[cfg(target_os = "linux")]
extern "C" {
    pub fn recvfrom(
        socket: i32,
        buffer: *mut c_void,
        len: usize,
        flags: i32,
        src_addr: *mut sockaddr,
        addrlen: *mut SocklenT,
    ) -> isize;
    pub fn sendto(
        sockfd: i32,
        buf: *const c_void,
        len: usize,
        flags: i32,
        dest_addr: *const sockaddr,
        addrlen: SocklenT,
    ) -> isize;
    pub fn bind(sockfd: i32, addr: *const sockaddr, addrlen: SocklenT) -> i32;
    pub fn socket(domain: i32, type_: i32, protocol: i32) -> i32;
    pub fn ioctl(fd: i32, request: u64, ...) -> i32;
    pub fn perror(str: *const i8);
    pub fn close(fd: i32) -> i32;
}

#[link(name = "iphlpapi")]
#[cfg(target_os = "windows")]
extern "C" {
    pub fn GetAdaptersAddresses(
        Family: u32,
        Flags: u32,
        Reserved: *mut std::ffi::c_void,
        AdapterAddresses: *mut IP_ADAPTER_ADDRESSES,
        SizePointer: *mut u32,
    ) -> u32;
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
    pub fn pcap_inject(_: *mut pcap, _: *const c_void, _: usize) -> i32;
    pub fn pcap_sendpacket(_: *mut pcap, _: *const u8, _: i32) -> i32;
    pub fn pcap_geterr(_: *mut pcap) -> *mut i8;
}
