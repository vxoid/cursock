#![allow(non_camel_case_types)]

use super::sockaddr;

pub const MAX_ADAPTER_DESCRIPTION_LENGTH: usize = 128;
pub const MAX_ADAPTER_NAME_LENGTH: usize = 256;
pub const MAX_ADAPTER_ADDRESS_LENGTH: usize = 8;
pub const MAX_DHCPV6_DUID_LENGTH: usize = 130;

#[repr(C)]
pub struct IP_ADAPTER_ADDRESSES {
    pub length: u32,
    pub if_index: u32,
    pub next: *mut IP_ADAPTER_ADDRESSES,
    pub adapter_name: *mut u8,
    pub first_unicast_address: *mut IP_ADAPTER_UNICAST_ADDRESS,
    pub first_anycast_address: *mut IP_ADAPTER_ANYCAST_ADDRESS,
    pub first_multicast_address: *mut IP_ADAPTER_MULTICAST_ADDRESS,
    pub first_dns_server_address: *mut IP_ADAPTER_DNS_SERVER_ADDRESS,
    pub dns_suffix: *mut u16,
    pub description: *mut u16,
    pub friendly_name: *mut u16,
    pub physical_address: [u8; MAX_ADAPTER_ADDRESS_LENGTH],
    pub physical_address_length: u32,
    pub flags: u32,
    pub mtu: u32,
    pub if_type: u32,
    pub oper_status: u32,
    pub ipv6_if_index: u32,
    pub zone_indices: [u32; 16],
    pub first_prefix: *mut IP_ADAPTER_PREFIX,
}

#[repr(C)]
pub struct IP_ADAPTER_PREFIX {
    pub length: u32,
    pub flags: u32,
    pub next: *mut IP_ADAPTER_PREFIX,
    pub address: SOCKET_ADDRESS,
    pub prefix_length: u32,
}

#[repr(C)]
pub struct IP_ADAPTER_DNS_SERVER_ADDRESS {
    pub length: u32,
    pub reserved: u32,
    pub next: *mut IP_ADAPTER_DNS_SERVER_ADDRESS,
    pub address: SOCKET_ADDRESS,
}

#[repr(C)]
pub struct IP_ADAPTER_MULTICAST_ADDRESS {
    pub length: u32,
    pub flags: u32,
    pub next: *mut IP_ADAPTER_MULTICAST_ADDRESS,
    pub address: SOCKET_ADDRESS,
    pub adapter_index: u32,
}

#[repr(C)]
pub struct IP_ADAPTER_UNICAST_ADDRESS {
    pub length: u32,
    pub flags: u32,
    pub next: *mut IP_ADAPTER_UNICAST_ADDRESS,
    pub address: SOCKET_ADDRESS,
    pub prefix_origin: u32,
    pub suffix_origin: u32,
    pub dad_state: u32,
    pub valid_lifetime: u32,
    pub preferred_lifetime: u32,
    pub lease_lifetime: u32,
    pub on_link_prefix_length: u8,
}

#[repr(C)]
pub struct SOCKET_ADDRESS {
    pub lp_sockaddr: *mut sockaddr,
    pub i_sockaddr_length: i32,
}

#[repr(C)]
pub struct IP_ADAPTER_ANYCAST_ADDRESS {
    pub length: u32,
    pub flags: u32,
    pub next: *mut IP_ADAPTER_ANYCAST_ADDRESS,
    pub address: SOCKET_ADDRESS,
}