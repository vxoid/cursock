mod consts;
mod structs;

pub use consts::*;
pub use structs::*;

#[cfg(target_os = "linux")]
pub type SocklenT = u32;

#[link(name = "cursock", kind = "static")]
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
    pub fn write(fd: i32, buf: *const std::os::raw::c_void, count: usize) -> isize;
    pub fn read(fd: i32, buf: *mut std::os::raw::c_void, count: usize) -> isize;
    pub fn bind(sockfd: i32, addr: *const sockaddr, addrlen: SocklenT) -> i32;
    pub fn socket(domain: i32, type_: i32, protocol: i32) -> i32;
    pub fn open(pathname: *const i8, flags: i32) -> i32;
    pub fn getifaddrs(ifap: *mut *mut ifaddrs) -> i32;
    pub fn ioctl(fd: i32, request: u64, ...) -> i32;
    pub fn freeifaddrs(ifa: *mut ifaddrs);
    pub fn perror(str: *const i8);
    pub fn close(fd: i32) -> i32;
}

#[link(name = "iphlpapi", kind = "static")]
#[cfg(target_os = "windows")]
extern "system" {
    pub fn GetAdaptersAddresses(
        family: u32,
        flags: u32,
        reserved: *mut std::os::raw::c_void,
        adapter_addresses: *mut IP_ADAPTER_ADDRESSES,
        size: *mut u32
    ) -> u32;
    pub fn CreateUnicastIpAddressEntry(row: *const MIB_UNICASTIPADDRESS_ROW) -> u32;
    pub fn ConvertInterfaceLuidToIndex(luid: *const u64, index: *mut u32) -> u32;
    pub fn InitializeUnicastIpAddressEntry(row: *mut MIB_UNICASTIPADDRESS_ROW);
    pub fn CreateIpNetEntry(entry: *mut MIB_IPNETROW) -> u32;
    pub fn DeleteIpNetEntry(entry: *mut MIB_IPNETROW) -> u32;
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
#[cfg(target_os = "windows")]
pub type LOGGER = Option<unsafe extern "C" fn(level: i32, timestamp: u64, message: *const u16)>;

#[link(name = "wintun", kind = "static")]
#[cfg(target_os = "windows")]
extern "C" {
    pub fn WintunCreateAdapter(name: *const u16, tunnel_type: *const u16, requested_GUID: *const GUID) -> WintunAdapterHandle;
    pub fn WintunStartSession(adapter: WintunAdapterHandle, _: u32) -> WintunSessionHandle;
    pub fn WintunAllocateSendPacket(session: WintunSessionHandle, size: u32) -> *mut u8;
    pub fn WintunReceivePacket(session: WintunSessionHandle, size: *mut u32) -> *mut u8;
    pub fn WintunReleaseReceivePacket(session: WintunSessionHandle, buffer: *const u8);
    pub fn WintunGetAdapterLUID(adapter: WintunAdapterHandle, luid: *mut u64);
    pub fn WintunSendPacket(session: WintunSessionHandle, packet: *mut u8);
    pub fn WintunOpenAdapter(name: *const u16) -> WintunAdapterHandle;
    pub fn WintunCloseAdapter(adapter: WintunAdapterHandle);
    pub fn WintunEndSession(session: WintunSessionHandle);
    pub fn WintunSetLogger(logger: LOGGER);
}

#[link(name = "kernel32", kind = "static")]
#[cfg(target_os = "windows")]
extern "system" {
    pub fn FormatMessageW(
        flags: u32,
        src: *const std::os::raw::c_void,
        message_id: u32,
        language_id: u32,
        buffer: *mut u16,
        size: u32,
        args: *mut i8
    ) -> u32;
    pub fn GetLastError() -> u32;
}

pub const fn null<T>() -> *const T {
    0 as *const T
}

pub const fn null_mut<T>() -> *mut T {
    0 as *mut T
}