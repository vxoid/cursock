use crate::*;
#[cfg(target_os = "linux")]
use std::ffi::CString;

use std::process::Command;

#[macro_export]
macro_rules! callback {
    ($arg: expr) => {
        $arg
    };
    ($callback: expr, $arg: expr) => {
        $callback(&$arg)
    }
}
#[macro_export]
macro_rules! timeout {
    (
        $vis:vis $fnname:ident($($argname:ident: $arg:ty $(=> $callback: expr)?), *) -> $return:ty, $fn:expr
    ) => {
        $vis fn $fnname($($argname: $arg,)* time: std::time::Duration) -> Option<$return> {
            use std::thread;
            use std::sync::mpsc;

            let (tx, rx) = mpsc::channel();

            thread::spawn(move || {
                let _ = tx.send($fn($(callback!($($callback, )?$argname),)*));
            });
    
            let result: $return = match rx.recv_timeout(time) {
                Ok(result) => result,
                Err(mpsc::RecvTimeoutError::Timeout) => return None,
                Err(_) => return None
            };
            
            Some(result)
        }
    };
}

pub const HW_TYPE: u16 = 1;
pub const ARP_REPLY: u16 = 2;
pub const ARP_REQUEST: u16 = 1;
pub const IP_PROTO: u16 = 0x0800;
pub const ARP_PROTO: u16 = 0x0806;
pub const ICMP_PROTO: u16 = 0x0001;
pub const ICMP_ECHO_REQUEST: u8 = 8;
pub const ICMP_ECHO_RESPONSE: u8 = 0;
pub const EMPTY_ARRAY: [i8; 1] = [0];


/// trait for binary operations should be implemented on integers
/// # Examples
/// ```
/// use cursock::utils::*;
/// struct Integer {
///     pub integer: u32
/// }
///
/// impl BinOpers for Integer {
///     fn get_bit(&self, index: usize) -> Bit {
///         Handle::from((self.integer.clone() >> index & 1) as u8)
///     }
///     fn set_bit(&self, value: Bit, index: usize) -> Self {
///         let integer: u32 = match value {
///             Bit::One => {
///                 let mask: u32 = 1;
///                 self.integer.clone() | (mask << index)
///             },
///             Bit::Zero => {
///                 let mask: u32 = 1;
///                 self.integer.clone() & !(mask << index)
///             },
///         };
///
///         Integer { integer }
///     }
/// }
///
/// let mut a = Integer { integer: 0b01 };
/// let bit: u8 = a.get_bit(0).to();
/// assert_eq!(bit, 1);
/// assert_eq!(a.set_bit(Bit::One, 1).integer, 0b11);
/// ```
pub trait BinOpers {
    fn get_bit(&self, index: usize) -> Bit;
    fn set_bit(&self, value: Bit, index: usize) -> Self;
}

/// arp header wrapper with fields that contains only addresses
///
/// # Example
/// ```
/// use cursock::utils::*;
///
/// let response = ArpResponse::new(Handle::from([192, 168, 1, 1]), Handle::from([0; MAC_LEN]), Handle::from([192, 168, 1, 2]), Handle::from([0; MAC_LEN]));
///
/// let src_ip: [u8; IPV4_LEN] = response.get_src_ip().to();
/// let dst_ip: [u8; IPV4_LEN] = response.get_dst_ip().to();
/// let src_mac: [u8; MAC_LEN] = response.get_src_mac().to();
/// let dst_mac: [u8; MAC_LEN] = response.get_dst_mac().to();
///
/// assert_eq!(src_ip, [192, 168, 1, 1]);
/// assert_eq!(dst_ip, [192, 168, 1, 2]);
/// assert_eq!(src_mac, [0; MAC_LEN]);
/// assert_eq!(dst_mac, [0; MAC_LEN]);
/// ```
pub struct ArpResponse {
    src_mac: Mac,
    dst_mac: Mac,
    src_ip: Ipv4,
    dst_ip: Ipv4,
}

/// an ip header wrapper without useless fields
/// 
/// 
pub struct IpData {
    total_len: u16,
    ttl: u8,
    src: Ipv4,
    dst: Ipv4
}

/// an icmp header wrapper without useless fields
pub struct IcmpData {
    type_: IcmpType,
    code: u8,
    checksum: u16,
    data: Vec<u8>
}

/// enum of ip versions
pub enum IpVersions {
    V4,
    V6
}

pub enum SetupTypes<'all_lt, 'addr_lt, 'str_lt> {
    RouteAll(&'all_lt [(&'addr_lt Ipv4Addr, &'str_lt str)]),
    Separated
}

/// an icmp types enum
/// 
/// # Example
/// ```
/// use cursock::utils::*;
/// 
/// let echo_reply = IcmpType::EchoReply;
/// let raw_echo_reply: u8 = echo_reply.to();
/// 
/// assert_eq!(raw_echo_reply, 0)
/// ```
pub enum IcmpType {
    SKIP,
    Reserved,
    Redirect,
    Photuris,
    EchoReply,
    Unassigned,
    Traceroute,
    IPv6IAmHere,
    EchoRequest,
    Experimental,
    SourceQuench,
    TimeExceeded,
    TimestampReply,
	IPv6WhereAreYou,
    DomainNameReply,
    TimestampRequest,
    ParameterProblem,
    AddressMaskReply,
    InformationReply,
    DomainNameRequest,
    InformationRequest,
    AddressMaskRequest,
    RouterSolicitation,
    MobileHostRedirect,
    RouterAdvertisement,
    AlternateHostAddress,
    DestenationUnreachable,
    DatagramConversionError,
    MobileRegistrationReply,
    MobileRegistrationRequest,
}

/// bit representation
///
/// # Example
/// ```
/// use cursock::utils::*;
///
/// let bit = Bit::Zero;
///
/// let boolean_bit: bool = bit.to();
/// let decimal_bit: u8 = bit.to();
///
/// assert_eq!(boolean_bit, false);
/// assert_eq!(decimal_bit, 0)
/// ```
pub enum Bit {
    One,
    Zero,
}

impl Handle<u8> for IcmpType {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::EchoReply,
            3 => Self::DestenationUnreachable,
            4 => Self::SourceQuench,
            5 => Self::Redirect,
            6 => Self::AlternateHostAddress,
            8 => Self::EchoRequest,
            9 => Self::RouterAdvertisement,
            10 => Self::RouterSolicitation,
            11 => Self::TimeExceeded,
            12 => Self::ParameterProblem,
            13 => Self::TimestampRequest,
            14 => Self::TimestampReply,
            15 => Self::InformationRequest,
            16 => Self::InformationReply,
            17 => Self::AddressMaskRequest,
            18 => Self::AddressMaskReply,
            19..=29 => Self::Reserved,
            30 => Self::Traceroute,
            31 => Self::DatagramConversionError,
            32 => Self::MobileHostRedirect,
            33 => Self::IPv6WhereAreYou,
            34 => Self::IPv6IAmHere,
            35 => Self::MobileRegistrationRequest,
            36 => Self::MobileRegistrationReply,
            37 => Self::DomainNameRequest,
            38 => Self::DomainNameReply,
            39 => Self::SKIP,
            40 => Self::Photuris,
            41 => Self::Experimental,
            _ => Self::Unassigned
        }
    }

    fn to(&self) -> u8 {

        match *self {
            IcmpType::SKIP => 39,
            IcmpType::Reserved => 19,
            IcmpType::Redirect => 5,
            IcmpType::Photuris => 40,
            IcmpType::EchoReply => 0,
            IcmpType::Unassigned => 2,
            IcmpType::Traceroute => 30,
            IcmpType::IPv6IAmHere => 34,
            IcmpType::EchoRequest => 8,
            IcmpType::Experimental => 41,
            IcmpType::SourceQuench => 4,
            IcmpType::TimeExceeded => 11,
            IcmpType::TimestampReply => 14,
            IcmpType::IPv6WhereAreYou => 33,
            IcmpType::DomainNameReply => 38,
            IcmpType::TimestampRequest => 13,
            IcmpType::ParameterProblem => 12,
            IcmpType::AddressMaskReply => 18,
            IcmpType::InformationReply => 16,
            IcmpType::DomainNameRequest => 37,
            IcmpType::InformationRequest => 15,
            IcmpType::AddressMaskRequest => 17,
            IcmpType::RouterSolicitation => 10,
            IcmpType::MobileHostRedirect => 32,
            IcmpType::RouterAdvertisement => 9,
            IcmpType::AlternateHostAddress => 6,
            IcmpType::DestenationUnreachable => 3,
            IcmpType::DatagramConversionError => 31,
            IcmpType::MobileRegistrationReply => 36,
            IcmpType::MobileRegistrationRequest => 35,
        }
    }
}

impl IpData {
    pub fn new(total_len: u16, ttl: u8, src: Ipv4, dst: Ipv4) -> Self {
        Self { total_len, ttl, src, dst }
    }
    
    getters!(
        pub get_total_len(total_len) -> u16;
        pub get_ttl(ttl) -> u8;
        pub get_src(src) -> Ipv4;
        pub get_dst(dst) -> Ipv4;
    );
    setters!(
        pub set_total_len(u16) -> total_len;
        pub set_ttl(u8) -> ttl;
        pub set_src(Ipv4) -> src;
        pub set_dst(Ipv4) -> dst;
    );
}

impl IcmpData {
    pub fn new(type_: IcmpType, code: u8, checksum: u16, data: Vec<u8>) -> Self {
        Self { type_, code, checksum, data }
    }

    getters!(
        pub get_type(type_) -> IcmpType;
        pub get_code(code) -> u8;
        pub get_checksum(checksum) -> u16;
        pub get_data(data) -> Vec<u8>;
    );

    setters!(
        pub set_type(IcmpType) -> type_;
        pub set_code(u8) -> code;
        pub set_checksum(u16) -> checksum;
        pub set_data(Vec<u8>) -> data;
    );
}

impl Handle<bool> for Bit {
    fn from(value: bool) -> Self {
        match value {
            true => Self::One,
            false => Self::Zero,
        }
    }
    fn to(&self) -> bool {
        match *self {
            Self::One => true,
            Self::Zero => false,
        }
    }
}

impl Handle<u8> for Bit {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::One,
            0 => Self::Zero,
            _ => {
                println!(
                    "Can\'t convert {} as bit, \"Zero\" will be used as default",
                    value
                );
                Self::Zero
            }
        }
    }
    fn to(&self) -> u8 {
        match *self {
            Self::One => 1,
            Self::Zero => 0,
        }
    }
}

impl BinOpers for u32 {
    fn get_bit(&self, index: usize) -> Bit {
        Handle::from((self.clone() >> index & 1) as u8)
    }
    fn set_bit(&self, value: Bit, index: usize) -> Self {
        match value {
            Bit::One => {
                let mask: Self = 1;
                self.clone() | (mask << index)
            }
            Bit::Zero => {
                let mask: Self = 1;
                self.clone() & !(mask << index)
            }
        }
    }
}

impl ArpResponse {
    pub fn new(src_ip: Ipv4, src_mac: Mac, dst_ip: Ipv4, dst_mac: Mac) -> Self {
        Self {
            src_ip,
            src_mac,
            dst_ip,
            dst_mac,
        }
    }

    getters!(
        pub get_src_mac(src_mac) -> Mac;
        pub get_src_ip(src_ip) -> Ipv4;
        pub get_dst_mac(dst_mac) -> Mac;
        pub get_dst_ip(dst_ip) -> Ipv4;
    );
    setters!(
        pub set_src_mac(Mac) -> src_mac;
        pub set_src_ip(Ipv4) -> src_ip;
        pub set_dst_mac(Mac) -> dst_mac;
        pub set_dst_ip(Ipv4) -> dst_ip;
    );
}

pub fn run_queries(queries: &[&[&str]], program: &str) -> Result<(), CursedErrorHandle> {
    for query in queries {
        if let Err(err) = Command::new(program).args(*query).output() {
            return Err(
                CursedErrorHandle::new(
                    CursedError::Sockets,
                    format!("can\'t run command due to \"{}\"", err.to_string())
                )
            );
        }
    }

    Ok(())
}

#[cfg(target_os = "windows")]
pub fn get_interface_by_index(index: u32) -> Result<(Option<Ipv4Addr>, Option<Ipv6Addr>, Mac, String), CursedErrorHandle> {
    let mut size: u32 = 0;
    let addresses: *mut ccs::IP_ADAPTER_ADDRESSES = ccs::null_mut();
    unsafe {
        ccs::GetAdaptersAddresses(
            ccs::AF_UNSPEC as u32,
            0,
            ccs::null_mut(),
            addresses,
            &mut size
        )
    };

    let mut buffer: Vec<u8> = Vec::with_capacity(size as usize);
    let addresses: *mut ccs::IP_ADAPTER_ADDRESSES = buffer.as_mut_ptr() as *mut ccs::IP_ADAPTER_ADDRESSES;

    let err: u32 = unsafe {
        ccs::GetAdaptersAddresses(
            ccs::AF_UNSPEC as u32,
            0,
            ccs::null_mut(),
            addresses,
            &mut size
        )
    };

    if err != ccs::ERROR_SUCCESS {
        return Err(
            CursedErrorHandle::new(
                CursedError::OS,
                "can\'t get adapter addresses".to_string()
            )
        );
    }

    let mut data: Option<(Option<Ipv4Addr>, Option<Ipv6Addr>, Mac, String)> = None;
    let mut p_current: *mut ccs::IP_ADAPTER_ADDRESSES = addresses;
    while !p_current.is_null() {
        let adapter: &mut ccs::IP_ADAPTER_ADDRESSES = unsafe {
            &mut *p_current
        };

        if index == adapter.index {
            let mut mac: [u8; MAC_LEN] = [0; MAC_LEN];
            memcpy(mac.as_mut_ptr(), adapter.physical_address.as_ptr(), MAC_LEN);
            let mac: Mac = Handle::from(mac);
            
            let mut ipv4: Option<Ipv4Addr> = None;
            let mut ipv6: Option<Ipv6Addr> = None;

            let mut unicast_address: *mut ccs::IP_ADAPTER_UNICAST_ADDRESS_LH = adapter.first_unicast;
            while !unicast_address.is_null() {
                let r_unicast_address: &mut ccs::IP_ADAPTER_UNICAST_ADDRESS_LH = unsafe {
                    &mut *unicast_address
                };

                let p_sockaddr: *mut ccs::sockaddr = r_unicast_address.address.sock_addr;
                if !p_sockaddr.is_null() {
                    let family: u16 = unsafe {
                        (*p_sockaddr).sa_family
                    };
                    match family as i32 {
                        ccs::AF_INET => {
                            let address: &mut ccs::sockaddr_in = unsafe {
                                &mut *(p_sockaddr as *mut ccs::sockaddr_in)
                            };
                            
                            ipv4 = Some(Ipv4Addr::from(address.sin_addr.s_addr))
                        },
                        ccs::AF_INET6 => {
                            let address: &mut ccs::sockaddr_in6 = unsafe {
                                &mut *(p_sockaddr as *mut ccs::sockaddr_in6)
                            };

                            ipv6 = Some(Ipv6Addr::from(address.sin6_addr.s6_addr));
                        },
                        _ => {}
                    }
                }

                unicast_address = r_unicast_address.next;
            }
            
            data = Some((ipv4, ipv6, mac, str_from_cstr(adapter.adapter_name)))
        }

        p_current = adapter.next
    }
    let data = match data {
        Some(data) => data,
        None => return Err(
            CursedErrorHandle::new(
                CursedError::InvalidArgument,
                format!("{} isn\'t valid adapter index", index)
            )
        ),
    };

    Ok(data)
}

#[cfg(target_os = "windows")]
pub fn get_interface_by_guid(guid: &str) -> Result<(Option<Ipv4Addr>, Option<Ipv6Addr>, Mac, u32), CursedErrorHandle> {
    let mut size: u32 = 0;
    let addresses: *mut ccs::IP_ADAPTER_ADDRESSES = ccs::null_mut();
    unsafe {
        ccs::GetAdaptersAddresses(
            ccs::AF_UNSPEC as u32,
            0,
            ccs::null_mut(),
            addresses,
            &mut size
        )
    };

    let mut buffer: Vec<u8> = Vec::with_capacity(size as usize);
    let addresses: *mut ccs::IP_ADAPTER_ADDRESSES = buffer.as_mut_ptr() as *mut ccs::IP_ADAPTER_ADDRESSES;

    let err: u32 = unsafe {
        ccs::GetAdaptersAddresses(
            ccs::AF_UNSPEC as u32,
            0,
            ccs::null_mut(),
            addresses,
            &mut size
        )
    };

    if err != ccs::ERROR_SUCCESS {
        return Err(
            CursedErrorHandle::new(
                CursedError::OS,
                "can\'t get adapter addresses".to_string()
            )
        );
    }

    let mut data: Option<(Option<Ipv4Addr>, Option<Ipv6Addr>, Mac, u32)> = None;
    let mut p_current: *mut ccs::IP_ADAPTER_ADDRESSES = addresses;
    while !p_current.is_null() {
        let adapter: &mut ccs::IP_ADAPTER_ADDRESSES = unsafe {
            &mut *p_current
        };

        if guid == str_from_cstr(adapter.adapter_name) {
            let mut mac: [u8; MAC_LEN] = [0; MAC_LEN];
            memcpy(mac.as_mut_ptr(), adapter.physical_address.as_ptr(), MAC_LEN);
            let mac: Mac = Handle::from(mac);
            
            let mut ipv4: Option<Ipv4Addr> = None;
            let mut ipv6: Option<Ipv6Addr> = None;

            let mut unicast_address: *mut ccs::IP_ADAPTER_UNICAST_ADDRESS_LH = adapter.first_unicast;
            while !unicast_address.is_null() {
                let r_unicast_address: &mut ccs::IP_ADAPTER_UNICAST_ADDRESS_LH = unsafe {
                    &mut *unicast_address
                };

                let p_sockaddr: *mut ccs::sockaddr = r_unicast_address.address.sock_addr;
                if !p_sockaddr.is_null() {
                    let family: u16 = unsafe {
                        (*p_sockaddr).sa_family
                    };
                    match family as i32 {
                        ccs::AF_INET => {
                            let address: &mut ccs::sockaddr_in = unsafe {
                                &mut *(p_sockaddr as *mut ccs::sockaddr_in)
                            };
                            
                            ipv4 = Some(Ipv4Addr::from(address.sin_addr.s_addr))
                        },
                        ccs::AF_INET6 => {
                            let address: &mut ccs::sockaddr_in6 = unsafe {
                                &mut *(p_sockaddr as *mut ccs::sockaddr_in6)
                            };

                            ipv6 = Some(Ipv6Addr::from(address.sin6_addr.s6_addr));
                        },
                        _ => {}
                    }
                }

                unicast_address = r_unicast_address.next;
            }
            
            data = Some((ipv4, ipv6, mac, adapter.index))
        }

        p_current = adapter.next
    }
    let data = match data {
        Some(data) => data,
        None => return Err(
            CursedErrorHandle::new(
                CursedError::InvalidArgument,
                format!("{} isn\'t valid adapter guid", guid)
            )
        ),
    };

    Ok(data)
}

#[cfg(target_os = "linux")]
pub fn get_interface_info(
    interface: &str,
    debug: bool,
) -> Result<(Option<Ipv4Addr>, Option<Ipv6Addr>, Mac, i32), CursedErrorHandle> {
    let socket: i32 = unsafe {
        ccs::socket(
            ccs::AF_INET,
            ccs::SOCK_DGRAM,
            0,
        )
    };

    if socket < 0 {
        if debug {
            unsafe { ccs::perror(EMPTY_ARRAY.as_ptr()) }
        }
        return Err(
            CursedErrorHandle::new(
                CursedError::Initialize,
                format!("Can\'t initialize socket ({} < 0)", socket),
            )
        );
    }

    let interface: CString = match CString::new(interface) {
        Ok(interface) => interface,
        Err(err) => {
            return Err(CursedErrorHandle::new(
                CursedError::Parse,
                format!(
                    "{} is not valid c string can\'t convert it due to {}",
                    interface,
                    err.to_string()
                ),
            ))
        }
    };
    
    let ifru: ccs::ifreq_data = ccs::ifreq_data { ifru_ifindex: 0 };
    let mut if_request: ccs::ifreq = ccs::ifreq {
        ifr_name: [0; 16],
        ifr_ifru: ifru,
    };

    memcpy(
        if_request.ifr_name.as_mut_ptr(),
        interface.as_ptr(),
        interface.as_bytes_with_nul().len(),
    );

    let index: i32 = get_interface_index(socket, &mut if_request, debug)?;
    let mac: Mac = get_interface_mac(socket, &mut if_request, debug)?;
    let ipv4: Option<Ipv4Addr> = match get_interface_ipv4(socket, &mut if_request, debug) {
        Ok(ipv4) => Some(ipv4),
        Err(_) => None,
    };
    unsafe { ccs::close(socket); }

    let socket: i32 = unsafe {
        ccs::socket(
            ccs::AF_INET6,
            ccs::SOCK_DGRAM,
            0,
        )
    };
    if socket < 0 {
        if debug {
            unsafe { ccs::perror(EMPTY_ARRAY.as_ptr()) }
        }
        return Err(
            CursedErrorHandle::new(
                CursedError::Initialize,
                format!("Can\'t initialize socket ({} < 0)", socket),
            )
        );
    }

    let ipv6: Option<Ipv6Addr> = match get_interface_ipv6(socket, &mut if_request, debug) {
        Ok(ipv6) => Some(ipv6),
        Err(_) => None,
    };
    unsafe { ccs::close(socket); }

    Ok((ipv4, ipv6, mac, index))
}

#[cfg(target_os = "linux")]
fn get_interface_index(socket: i32, ifr: *mut ccs::ifreq, debug: bool) -> Result<i32, CursedErrorHandle> {
    let err: i32 = unsafe { ccs::ioctl(socket, ccs::SIOCGIFINDEX, ifr) };

    if err < 0 {
        if debug {
            unsafe { ccs::perror(EMPTY_ARRAY.as_ptr()) }
        }
        return Err(CursedErrorHandle::new(
            CursedError::Sockets,
            String::from("Got error while getting SIOCGIFINDEX"),
        ));
    }

    let index: i32 = unsafe { (*ifr).ifr_ifru.ifru_ifindex.clone() };

    Ok(index)
}

#[cfg(target_os = "linux")]
fn get_interface_ipv4(socket: i32, ifr: *mut ccs::ifreq, debug: bool) -> Result<Ipv4Addr, CursedErrorHandle> {
    let err: i32;

    err = unsafe { ccs::ioctl(socket, ccs::SIOCGIFADDR, ifr) };

    if err < 0 {
        if debug {
            unsafe { ccs::perror(EMPTY_ARRAY.as_ptr()) }
        }
        return Err(CursedErrorHandle::new(
            CursedError::Sockets,
            String::from("Got error while getting SIOCGIFADDR"),
        ));
    }

    let addr: *const ccs::sockaddr_in =
        unsafe { &(*ifr).ifr_ifru.ifru_addr as *const ccs::sockaddr } as *const ccs::sockaddr_in;
    let mut ip: [u8; IPV4_LEN] = [0; IPV4_LEN];

    memcpy(
        ip.as_mut_ptr(),
        unsafe { &(*addr).sin_addr.s_addr },
        std::mem::size_of::<[u8; IPV4_LEN]>(),
    );

    Ok(Ipv4Addr::from(ip))
}

#[cfg(target_os = "linux")]
fn get_interface_ipv6(socket: i32, ifr: *mut ccs::ifreq, debug: bool) -> Result<Ipv6Addr, CursedErrorHandle> {
    let err: i32;

    err = unsafe { ccs::ioctl(socket, ccs::SIOCGIFADDR, ifr) };

    if err < 0 {
        if debug {
            unsafe { ccs::perror(EMPTY_ARRAY.as_ptr()) }
        }
        return Err(CursedErrorHandle::new(
            CursedError::Sockets,
            String::from("Got error while getting SIOCGIFADDR"),
        ));
    }

    let addr: *const ccs::sockaddr_in6 =
        unsafe { &(*ifr).ifr_ifru.ifru_addr as *const ccs::sockaddr } as *const ccs::sockaddr_in6;

    Ok(Ipv6Addr::from(unsafe { (*addr).sin6_addr.s6_addr }))
}

#[cfg(target_os = "linux")]
fn get_interface_mac(socket: i32, ifr: *mut ccs::ifreq, debug: bool) -> Result<Mac, CursedErrorHandle> {
    let err: i32 = unsafe { ccs::ioctl(socket, ccs::SIOCGIFHWADDR, ifr) };

    if err < 0 {
        if debug {
            unsafe { ccs::perror(EMPTY_ARRAY.as_ptr()) }
        }
        return Err(CursedErrorHandle::new(
            CursedError::Sockets,
            String::from("Got error while getting SIOCGIFHWADDR"),
        ));
    }

    let sa_data: [i8; 14] = unsafe { (*ifr).ifr_ifru.ifru_hwaddr.sa_data };

    let mut mac: [u8; MAC_LEN] = [0; MAC_LEN];

    memcpy(
        mac.as_mut_ptr(),
        sa_data.as_ptr(),
        std::mem::size_of::<[u8; MAC_LEN]>(),
    );

    Ok(Handle::from(mac))
}