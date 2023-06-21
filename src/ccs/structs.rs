#[derive(Clone, Copy)]
#[cfg(any(target_os = "linux", target_os = "windows"))]
#[repr(C)]
pub struct sockaddr {
    pub sa_family: u16,
    pub sa_data: [i8; 14],
}

#[derive(Clone)]
#[cfg(any(target_os = "linux", target_os = "windows"))]
#[repr(C)]
pub struct sockaddr_in {
    pub sin_family: i16,
    pub sin_port: u16,
    pub sin_addr: in_addr,
    pub sin_zero: [i8; 8],
}

#[derive(Clone)]
#[cfg(any(target_os = "linux", target_os = "windows"))]
#[repr(C)]
pub struct in_addr {
    pub s_addr: u32,
}

#[derive(Clone)]
#[cfg(any(target_os = "linux", target_os = "windows"))]
#[repr(C)]
pub struct sockaddr_in6 {
    pub sin6_family: u16,
    pub sin6_port: u16,
    pub sin6_flowinfo: u32,
    pub sin6_addr: in6_addr,
    pub sin6_scope_id: u32,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub union in6_addr {
    pub s6_addr: [u8; 16],
    pub s6_addr16: [u16; 8],
    pub s6_addr32: [u32; 4],
    pub s6_addr128: u128,
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
