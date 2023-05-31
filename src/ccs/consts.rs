#[cfg(target_os = "linux")]
pub const AF_PACKET: i32 = 17;
#[cfg(target_os = "linux")]
pub const AF_INET: i32 = 2;
#[cfg(target_os = "linux")]
pub const AF_INET6: i32 = 10;
#[cfg(target_os = "linux")]
pub const SOCK_RAW: i32 = 3;
#[cfg(target_os = "linux")]
pub const SOCK_DGRAM: i32 = 2;
#[cfg(target_os = "linux")]
pub const ETH_P_ARP: i32 = 0x0806;
#[cfg(target_os = "linux")]
pub const ETH_P_ALL: i32 = 0x0003;
#[cfg(target_os = "linux")]
pub const ETH_P_IP: i32 = 0x0800;
#[cfg(target_os = "linux")]
pub const ARPHRD_ETHER: u16 = 1;
#[cfg(target_os = "linux")]
pub const SIOCGIFHWADDR: u64 = 0x8927;
#[cfg(target_os = "linux")]
pub const SIOCGIFINDEX: u64 = 0x8933;
#[cfg(target_os = "linux")]
pub const SIOCGIFADDR: u64 = 0x8915;
#[cfg(target_os = "linux")]
pub const PACKET_BROADCAST: u8 = 1;
#[cfg(target_os = "windows")]
pub const PCAP_OPENFLAG_PROMISCUOUS: i32 = 1;
#[cfg(target_os = "windows")]
pub const AF_INET: usize = 2;
#[cfg(target_os = "windows")]
pub const AF_INET6: usize = 23;
#[cfg(target_os = "windows")]
pub const AF_UNSPEC: usize = 0;
#[cfg(target_os = "windows")]
pub const GAA_FLAG_INCLUDE_PREFIX: u8 = 0x00000008;
#[cfg(target_os = "windows")]
pub type TimeT = i64; // Should be changed after 292 billion years, due to overflow