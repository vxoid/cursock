#![allow(non_camel_case_types)]

#[cfg(target_os = "windows")]
use super::consts::*;

#[cfg(any(target_os = "linux", target_os = "windows"))]
#[repr(C)]
pub struct sockaddr {
    pub sa_family: u16,
    pub sa_data: [i8; 14],
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
impl Copy for sockaddr {}
#[cfg(any(target_os = "linux", target_os = "windows"))]
impl Clone for sockaddr {
    fn clone(&self) -> Self {
        sockaddr {
            sa_family: self.sa_family.clone(),
            sa_data: self.sa_data.clone(),
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
#[repr(C)]
pub struct sockaddr_in {
    pub sin_family: i16,
    pub sin_port: u16,
    pub sin_addr: in_addr,
    pub sin_zero: [i8; 8],
}

#[cfg(target_os = "linux")]
#[repr(C)]
pub struct sockaddr_ll {
    pub sll_family: u16,
    pub sll_protocol: u16,
    pub sll_ifindex: i32,
    pub sll_hatype: u16,
    pub sll_pkttype: u8,
    pub sll_halen: u8,
    pub sll_addr: [u8; 8],
}

#[cfg(target_os = "linux")]
#[repr(C)]
pub struct in_addr {
    pub s_addr: u32,
}

#[cfg(target_os = "windows")]
#[repr(C)]
pub struct in_addr {
    pub s_un: S_un,
}

#[cfg(target_os = "windows")]
#[repr(C)]
pub union S_un {
    pub s_un_b: S_un_b,
    pub s_un_w: S_un_w,
    pub s_addr: [u8; 4],
}

#[cfg(target_os = "windows")]
#[repr(C)]
pub struct S_un_b {
    pub s_b1: u8,
    pub s_b2: u8,
    pub s_b3: u8,
    pub s_b4: u8,
}

#[cfg(target_os = "windows")]
impl Copy for S_un_b {}
#[cfg(target_os = "windows")]
impl Clone for S_un_b {
    fn clone(&self) -> Self {
        Self {
            s_b1: self.s_b1.clone(),
            s_b2: self.s_b2.clone(),
            s_b3: self.s_b3.clone(),
            s_b4: self.s_b4.clone(),
        }
    }
}

#[cfg(target_os = "windows")]
#[repr(C)]
pub struct S_un_w {
    pub s_w1: u16,
    pub s_w2: u16,
}

#[cfg(target_os = "windows")]
impl Copy for S_un_w {}
#[cfg(target_os = "windows")]
impl Clone for S_un_w {
    fn clone(&self) -> Self {
        Self {
            s_w1: self.s_w1.clone(),
            s_w2: self.s_w2.clone(),
        }
    }
}

#[cfg(target_os = "linux")]
#[repr(C)]
pub struct ifreq {
    pub ifr_name: [i8; 16],
    pub ifr_ifru: ifreq_data,
}

#[cfg(target_os = "linux")]
#[repr(C)]
pub union ifreq_data {
    pub ifru_addr: sockaddr,
    pub ifru_dstaddr: sockaddr,
    pub ifru_broadaddr: sockaddr,
    pub ifru_netmask: sockaddr,
    pub ifru_hwaddr: sockaddr,
    pub ifru_flags: i16,
    pub ifru_ifindex: i32,
    pub ifru_metric: i32,
    pub ifru_mtu: i32,
    pub ifru_map: ifmap,
    pub ifru_slave: [i8; 16],
    pub ifru_newname: [i8; 16],
    pub ifru_data: *mut i8,
}

#[cfg(target_os = "linux")]
#[derive(Copy)]
#[repr(C)]
pub struct ifmap {
    pub mem_start: u64,
    pub mem_end: u64,
    pub base_addr: u16,
    pub irq: u8,
    pub dma: u8,
    pub port: u8,
}

#[cfg(target_os = "linux")]
impl Clone for ifmap {
    fn clone(&self) -> Self {
        Self {
            mem_start: self.mem_start.clone(),
            mem_end: self.mem_end.clone(),
            base_addr: self.base_addr.clone(),
            irq: self.irq.clone(),
            dma: self.dma.clone(),
            port: self.port.clone(),
        }
    }
}

#[cfg(target_os = "linux")]
#[repr(C)]
pub struct ifaddrs {
    pub ifa_next: *mut ifaddrs,
    pub ifa_name: *mut i8,
    pub ifa_flags: u32,
    pub ifa_addr: *mut sockaddr,
    pub ifa_netmask: *mut sockaddr,
    pub ifa_broadaddr: *mut sockaddr,
    pub ifa_data: *mut std::os::raw::c_void,
}

#[cfg(target_os = "windows")]
#[repr(C)]
pub struct FILE {
    pub _placeholder: *mut std::os::raw::c_void,
}

#[cfg(target_os = "windows")]
#[repr(C)]
pub struct pcap {
    pub fd: i32,
    pub snapshot: i32,
    pub linktype: i32,
    pub tzoff: i32,
    pub offset: i32,
    pub sf: pcap_sf,
    pub md: pcap_md,
    pub bufsize: i32,
    pub buffer: *mut u8,
    pub bp: *mut u8,
    pub cc: i32,
    pub pkt: *mut u8,
    pub fcode: bpf_program,
    pub errbuf: [i8; 256],
}

#[cfg(target_os = "windows")]
#[repr(C)]
pub struct pcap_sf {
    pub rfile: *mut FILE,
    pub swapped: i32,
    pub hdrsize: i32,
    pub lengths_swapped: swapped_type,
    pub version_major: i32,
    pub version_minor: i32,
    pub base: *mut u8,
}

#[cfg(target_os = "windows")]
#[repr(C)]
pub enum swapped_type {
    NOTSWAPPED,
    SWAPPED,
    MAYBESWAPPED,
}

#[cfg(target_os = "windows")]
#[repr(C)]
pub struct pcap_md {
    pub stat: pcap_stat,
    pub use_bpf: i32,
    pub totpkts: u32,
    pub totaccepted: u32,
    pub totdrops: u32,
    pub totmissed: i32,
    pub origmissed: i32,
    pub device: *mut i8,
}

#[cfg(target_os = "windows")]
#[repr(C)]
pub struct pcap_stat {
    pub ps_recv: u32,
    pub ps_drop: u32,
    pub ps_ifdrop: u32,
}

#[cfg(target_os = "windows")]
#[repr(C)]
pub struct bpf_program {
    pub bf_insns: *mut bpf_insn,
    pub bf_len: u32,
}

#[cfg(target_os = "windows")]
#[repr(C)]
pub struct bpf_insn {
    pub code: u16,
    pub jf: u8,
    pub jt: u8,
    pub k: i32,
}

#[cfg(target_os = "windows")]
#[repr(C)]
pub struct pcap_rmtauth {
    pub type_: i32,
    pub username: *mut i8,
    pub password: *mut i8,
}

#[cfg(target_os = "windows")]
#[repr(C)]
pub struct pcap_if {
    pub next: *mut pcap_if,
    pub name: *mut i8,
    pub description: *mut i8,
    pub addresses: *mut pcap_addr,
    pub flags: u32,
}

#[cfg(target_os = "windows")]
#[repr(C)]
pub struct pcap_addr {
    pub next: *mut pcap_addr,
    pub addr: *mut sockaddr,
    pub netmask: *mut sockaddr,
    pub broadaddr: *mut sockaddr,
}

#[cfg(target_os = "windows")]
#[repr(C)]
pub struct pcap_pkthdr {
    pub ts: timeval,
    pub caplen: u32,
    pub len: u32,
}

#[cfg(target_os = "windows")]
#[repr(C)]
pub struct timeval {
    tv_sec: i32,
    tv_usec: i32,
}

#[cfg(target_os = "windows")]
#[repr(C)]
pub struct IP_ADAPTER_INFO {
    pub next: *mut IP_ADAPTER_INFO,
    pub comboindex: u32,
    pub adaptername: [i8; 260],
    pub description: [i8; 132],
    pub addresslength: u32,
    pub address: [u8; 8],
    pub index: u32,
    pub type_: u32,
    pub dhcpenabled: u32,
    pub currentipaddress: *mut IP_ADDR_STRING,
    pub ipaddresslist: IP_ADDR_STRING,
    pub gatewaylist: IP_ADDR_STRING,
    pub dhcpserver: IP_ADDR_STRING,
    pub havewins: i32,
    pub primarywinsserver: IP_ADDR_STRING,
    pub secondarywinsserver: IP_ADDR_STRING,
    pub leaseobtained: TimeT,
    pub leaseexpires: TimeT,
}

#[cfg(target_os = "windows")]
#[repr(C)]
pub struct IP_ADDR_STRING {
    pub next: *mut IP_ADDR_STRING,
    pub ipaddress: IP_ADDRESS_STRING,
    pub ipmask: IP_MASK_STRING,
    pub context: u32,
}

#[cfg(target_os = "windows")]
#[repr(C)]
pub struct IP_ADDRESS_STRING {
    pub string: [i8; 16],
}

#[cfg(target_os = "windows")]
#[repr(C)]
pub struct IP_MASK_STRING {
    pub string: [i8; 16],
}

#[cfg(target_os = "windows")]
#[repr(C)]
pub struct _GUID {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: u64,
}

#[cfg(target_os = "windows")]
impl std::fmt::Display for _GUID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{{:08X}-{:04X}-{:04X}-{:04X}-{:012X}}}", self.data1, self.data2, self.data3, (self.data4 << 48).to_be(), (self.data4.to_be() << 16) >> 16)
    }
}

#[cfg(target_os = "windows")]
#[repr(C)]
pub struct MIB_UNICASTIPADDRESS_ROW {
    pub address: sockaddr_in,
    pub luid: u64,
    pub index: u32,
    pub prefix_origin: i32,
    pub suffix_origin: i32,
    pub valid_lifetime: u32,
    pub preferred_lifetime: u32,
    pub on_link_prefix_length: u8,
    pub skip_as_source: u8,
    pub dad_state: i32,
    pub scope_id: u32,
    pub timestamp: i64
}