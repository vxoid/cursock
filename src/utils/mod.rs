use std::net;

#[macro_export]
macro_rules! getters {
    (
        $($vis:vis $fn:ident($field:ident) -> $type:ty;)*
    ) => {
        $(
            $vis fn $fn(&self) -> &$type {
                &self.$field
            }
        )*
    };
}

#[macro_export]
macro_rules! setters {
    (
        $($vis:vis $fn:ident($type:ty) -> $field:ident;)*
    ) => {
        $(
            $vis fn $fn(&mut self, value: $type) {
                self.$field = value
            }
        )*
    };
}

pub const HW_TYPE: u16 = 1;
pub const ARP_REPLY: u16 = 2;
pub const MAC_LEN: usize = 6;
pub const IPV4_LEN: usize = 4;
pub const IPV6_LEN: usize = 16;
pub const ARP_REQUEST: u16 = 1;
pub const IP_PROTO: u16 = 0x0800;
pub const ARP_PROTO: u16 = 0x0806;
pub const ICMP_PROTO: u16 = 0x0001;
pub const ICMP_ECHO_REQUEST: u8 = 8;
pub const ICMP_ECHO_RESPONSE: u8 = 0;
pub const EMPTY_ARRAY: [i8; 1] = [0];
pub const IPV4_HEADER_SIZE: usize = std::mem::size_of::<IpV4Header>();
pub const ARP_HEADER_SIZE: usize = std::mem::size_of::<ArpHeader>();
pub const ETH_HEADER_SIZE: usize = std::mem::size_of::<EthHeader>();
pub const ICMPV4_HEADER_SIZE: usize = std::mem::size_of::<IcmpV4Header>();

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

/// struct for representing mac addresses
///
/// # Example
/// ```
/// use cursock::utils::*;
///
/// let mac_addr: Mac = Handle::from([0xff; MAC_LEN]);
///
/// let mac_octets: [u8; MAC_LEN] = mac_addr.to();
///
/// assert_eq!(mac_octets, [0xff; MAC_LEN])
/// ```
#[derive(Clone)]
pub struct Mac {
    mac_addr: [u8; MAC_LEN],
}

/// enum with ip versions
pub enum IpVer {
    V4,
    V6
}

/// arp header
#[repr(C)]
pub struct ArpHeader {
    pub hardware_type: u16,
    pub protocol_type: u16,
    pub hardware_len: u8,
    pub protocol_len: u8,
    pub opcode: u16,
    pub sender_mac: [u8; MAC_LEN],
    pub sender_ip: [u8; IPV4_LEN],
    pub target_mac: [u8; MAC_LEN],
    pub target_ip: [u8; IPV4_LEN],
}

/// icmp header
#[repr(C)]
pub struct IcmpV4Header {
    pub type_: u8,
    pub code: u8,
    pub check: u16,
    pub id: u16,
    pub sq: u16,
}

/// eth header
#[repr(C)]
pub struct EthHeader {
    pub dest: [u8; MAC_LEN],
    pub source: [u8; MAC_LEN],
    pub proto: u16,
}

/// ip header
#[repr(C)]
pub struct IpV4Header {
    pub verihl: u8,
    pub tos: u8,
    pub tot_len: u16,
    pub id: u16,
    pub frag: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub check: u16,
    pub saddr: [u8; IPV4_LEN],
    pub daddr: [u8; IPV4_LEN],
}

/// wrapper around type's pointer simple to box or arc smart pointer
///
/// # Example
/// ```
/// use cursock::utils::*;
///
/// let a = 1;
///
/// let a_wrapper = Wrapper::new(&a);
///
/// assert_eq!(*a_wrapper.reference(), a)
/// ```
pub struct Wrapper<T: ?Sized> {
    pointer: *const T,
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
    src_ip: net::Ipv4Addr,
    dst_ip: net::Ipv4Addr,
}

/// an ip header wrapper without useless fields
/// 
/// 
pub struct IpData {
    total_len: u16,
    ttl: u8,
    src: net::IpAddr,
    dst: net::IpAddr
}

/// an icmp header wrapper without useless fields
/// 
/// 
pub struct IcmpData {
    type_: IcmpType,
    code: u8,
    id: u16,
    sq: u16,
    checksum: u16,
    data: Vec<u8>
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
#[derive(Clone)]
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
#[derive(Clone)]
pub enum Bit {
    One,
    Zero,
}

impl From<u8> for IcmpType {
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
}

impl Into<u8> for IcmpType {
    fn into(self) -> u8 {
        match self {
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

impl PartialEq for IcmpType {
    fn eq(&self, other: &Self) -> bool {
        let byte: u8 = self.clone().into();
        byte == other.clone().into()
    }
}

impl IpVer {
    pub fn prefered(&self, v4: Option<net::Ipv4Addr>, v6: Option<net::Ipv6Addr>) -> Option<net::IpAddr> {
        match (self, v4, v6) {
            (IpVer::V4, None, Some(v6)) => Some(net::IpAddr::V6(v6)),
            (IpVer::V4, Some(v4), _) => Some(net::IpAddr::V4(v4)),
            (IpVer::V6, _, Some(v6)) => Some(net::IpAddr::V6(v6)),
            (IpVer::V6, Some(v4), None) => Some(net::IpAddr::V4(v4)),
            _ => None
        }
    }
}

impl IpData {
    pub fn new(total_len: u16, ttl: u8, src: net::IpAddr, dst: net::IpAddr) -> Self {
        Self { total_len, ttl, src, dst }
    }
    
    getters!(
        pub get_total_len(total_len) -> u16;
        pub get_ttl(ttl) -> u8;
        pub get_src(src) -> net::IpAddr;
        pub get_dst(dst) -> net::IpAddr;
    );
    setters!(
        pub set_total_len(u16) -> total_len;
        pub set_ttl(u8) -> ttl;
        pub set_src(net::IpAddr) -> src;
        pub set_dst(net::IpAddr) -> dst;
    );
}

impl IcmpData {
    pub fn new(type_: IcmpType, code: u8, checksum: u16, id: u16, sq: u16, data: Vec<u8>) -> Self {
        Self { type_, code, checksum, id, sq, data }
    }

    getters!(
        pub get_type(type_) -> IcmpType;
        pub get_code(code) -> u8;
        pub get_checksum(checksum) -> u16;
        pub get_id(id) -> u16;
        pub get_sq(sq) -> u16;
        pub get_data(data) -> [u8];
    );

    setters!(
        pub set_type(IcmpType) -> type_;
        pub set_code(u8) -> code;
        pub set_checksum(u16) -> checksum;
        pub set_id(u16) -> id;
        pub set_sq(u16) -> sq;
        pub set_data(Vec<u8>) -> data;
    );
}

impl From<bool> for Bit {
    fn from(value: bool) -> Self {
        match value {
            true => Self::One,
            false => Self::Zero,
        }
    }
}

impl Into<bool> for Bit {
    fn into(self) -> bool {
        match self {
            Self::One => true,
            Self::Zero => false,
        }
    }
}

impl From<u8> for Bit {
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
}

impl Into<u8> for Bit {
    fn into(self) -> u8 {
        match self {
            Self::One => 1,
            Self::Zero => 0,
        }
    }
}

impl From<[u8; MAC_LEN]> for Mac {
    fn from(mac_addr: [u8; MAC_LEN]) -> Self {
        Self { mac_addr }
    }
}

impl Into<[u8; MAC_LEN]> for Mac {
    fn into(self) -> [u8; MAC_LEN] {
        self.mac_addr
    }
}


impl<T: ?Sized> Wrapper<T> {
    pub fn new(pointer: *const T) -> Self {
        Self { pointer }
    }
    pub fn reference(&self) -> &T {
        unsafe { &*self.pointer }
    }
    pub fn mut_reference(&self) -> &mut T {
        unsafe { &mut *(self.pointer as *mut T) }
    }
}

impl std::fmt::Display for Mac {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
            self.mac_addr[0],
            self.mac_addr[1],
            self.mac_addr[2],
            self.mac_addr[3],
            self.mac_addr[4],
            self.mac_addr[5]
        )
    }
}

impl BinOpers for u32 {
    fn get_bit(&self, index: usize) -> Bit {
        Bit::from((self.clone() >> index & 1) as u8)
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
    pub fn new(src_ip: net::Ipv4Addr, src_mac: Mac, dst_ip: net::Ipv4Addr, dst_mac: Mac) -> Self {
        Self {
            src_ip,
            src_mac,
            dst_ip,
            dst_mac,
        }
    }

    getters!(
        pub get_src_mac(src_mac) -> Mac;
        pub get_src_ip(src_ip) -> net::Ipv4Addr;
        pub get_dst_mac(dst_mac) -> Mac;
        pub get_dst_ip(dst_ip) -> net::Ipv4Addr;
    );
    setters!(
        pub set_src_mac(Mac) -> src_mac;
        pub set_src_ip(net::Ipv4Addr) -> src_ip;
        pub set_dst_mac(Mac) -> dst_mac;
        pub set_dst_ip(net::Ipv4Addr) -> dst_ip;
    );
}

/// function for building to the exponent
///
/// # Example
/// ```
/// use cursock::utils::*;
///
/// let a = 3;
/// let b = power(a as f64, 2); // 1*3*3
///
/// assert_eq!(b, 9f64)
/// ```
pub fn power(f: f64, power: u16) -> f64 {
    power_with_start(1f64, f, power)
}

fn power_with_start(start: f64, f: f64, power: u16) -> f64 {
    let mut out: f64 = start;

    for _ in 0..power {
        out *= f
    }

    out
}

/// c memcpy clone
///
/// # Example
///
/// ```
/// use cursock::utils::*;
///
/// let a: [i128; 4] = [1210, 3271231, 478654, 239]; // Just random numbers
/// let mut b: [i128; 4] = [0; 4];
/// let mut c: [i128; 4] = [0; 4];
///
/// memcpy(&mut b, &a, std::mem::size_of::<[i128; 4]>());
/// memcpy(c.as_mut_ptr(), a.as_ptr(), std::mem::size_of::<[i128; 4]>());
///
/// assert_eq!(a, b);
/// assert_eq!(a, c);
/// assert_eq!(b, c)
/// ```
pub fn memcpy<TD, TS>(dest: *mut TD, src: *const TS, size: usize) -> *mut TD {
    if dest as usize == 0 {
        return 0 as *mut TD;
    }

    let byte_dest: *mut u8 = dest as *mut u8;
    let byte_src: *const u8 = src as *const u8;

    unsafe {
        for i in 0..size {
            *((byte_dest as usize + i) as *mut u8) = *((byte_src as usize + i) as *const u8)
        }
    }

    dest
}

/// creates string from bytes
///
/// # Example
/// ```
/// use cursock::utils::*;
///
/// let bytes = b"Hello, world";
///
/// assert_eq!(str_from_bytes(bytes).as_bytes(), bytes)
/// ```
pub fn str_from_bytes(bytes: &[u8]) -> String {
    bytes
        .into_iter()
        .map(|u| u.clone() as char)
        .collect()
}

/// creates string from char pointer
///
/// # Example
/// ```
/// use cursock::utils::*;
/// use std::ffi::CString;
///
/// let string = "Hello, world";
/// let cstring = CString::new(string).expect("cstring init error");
///
/// assert_eq!(&str_from_cstr(cstring.as_ptr())[..], string)
/// ```
pub fn str_from_cstr(cstr: *const i8) -> String {
    let mut string: String = String::new();

    let mut i: usize = 0;
    loop {
        let byte: i8 = unsafe { *((cstr as usize + i) as *const i8) };
        if byte == 0 {
            break;
        }

        string.push(byte as u8 as char);

        i += 1
    }

    string
}