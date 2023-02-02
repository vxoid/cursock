pub const HW_TYPE: u16 = 1;
pub const ARP_REPLY: u16 = 2;
pub const ARP_REQUEST: u16 = 1;
pub const IP_PROTO: u16 = 0x0800;
pub const ARP_PROTO: u16 = 0x0806;
pub const EMPTY_ARRAY: [i8; 1] = [0];
pub const READ_BUFFER_LEN: usize = 60;
pub const ARP_HEADER_SIZE: usize = std::mem::size_of::<ArpHeader>();
pub const ETH_HEADER_SIZE: usize = std::mem::size_of::<EthHeader>();
pub const IPV4_LEN: usize = 4;
pub const MAC_LEN: usize = 6;

/// trait for binary operations should be implemented on integers
/// # Examples
/// ```
/// use arpv::utils::*;
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
/// trait for conveting one type into other similar to the From trait
/// # Examples
/// ```
/// use arpv::utils::*;
///
/// enum Bit {
///     One,
///     Zero
/// }
///
/// impl Handle<bool> for Bit {
///     fn from(value: bool) -> Self {
///         match value {
///             true => Self::One,
///             false => Self::Zero
///         }
///     }
///     fn to(&self) -> bool {
///         match *self {
///             Self::One => true,
///             Self::Zero => false,
///         }
///     }
/// }
///
/// let boolean: bool = Bit::Zero.to();
///
/// assert_eq!(boolean, false)
/// ```
pub trait Handle<T> {
    fn from(value: T) -> Self;
    fn to(&self) -> T;
}

/// struct for representing ipv4 addresses
///
/// # Example
/// ```
/// use arpv::utils::*;
///
/// let ip_addr: Ipv4 = Handle::from([192, 168, 1, 1]);
///
/// let ip_octets: [u8; IPV4_LEN] = ip_addr.to(); // Basicly IPV4_LEN is count of octets of ipv4 (4)
///
/// assert_eq!(ip_octets, [192, 168, 1, 1])
/// ```
pub struct Ipv4 {
    ip_addr: [u8; IPV4_LEN],
}

/// struct for representing mac addresses
///
/// # Example
/// ```
/// use arpv::utils::*;
///
/// let mac_addr: Mac = Handle::from([0xff; MAC_LEN]);
///
/// let mac_octets: [u8; MAC_LEN] = mac_addr.to();
///
/// assert_eq!(mac_octets, [0xff; MAC_LEN])
/// ```
pub struct Mac {
    mac_addr: [u8; MAC_LEN],
}

/// wrapper around type's pointer simple to box or arc smart pointer
///
/// # Example
/// ```
/// use arpv::utils::*;
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

/// eth header
#[repr(C)]
pub struct EthHeader {
    pub dest: [u8; MAC_LEN],
    pub source: [u8; MAC_LEN],
    pub proto: u16,
}

/// ip header
#[repr(C)]
pub struct IpHeader {
    pub verihl: u8,
    pub tos: u8,
    pub tot_len: u16,
    pub id: u16,
    pub frag_off: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub check: u16,
    pub saddr: [u8; IPV4_LEN],
    pub daddr: [u8; IPV4_LEN],
}

/// arp header wrapper with fields that contains only addresses
///
/// # Example
/// ```
/// use arpv::utils::*;
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

/// bit representation
///
/// # Example
/// ```
/// use arpv::utils::*;
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

unsafe impl<T: ?Sized> Send for Wrapper<T> {}

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

impl Clone for Mac {
    fn clone(&self) -> Self {
        Self {
            mac_addr: self.mac_addr.clone(),
        }
    }
}

impl Handle<[u8; MAC_LEN]> for Mac {
    fn from(mac_addr: [u8; MAC_LEN]) -> Self {
        Self { mac_addr }
    }
    fn to(&self) -> [u8; MAC_LEN] {
        self.mac_addr.clone()
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

impl Clone for Ipv4 {
    fn clone(&self) -> Self {
        Self {
            ip_addr: self.ip_addr.clone(),
        }
    }
}

impl Handle<[u8; IPV4_LEN]> for Ipv4 {
    fn from(ip_addr: [u8; IPV4_LEN]) -> Self {
        Self { ip_addr }
    }
    fn to(&self) -> [u8; IPV4_LEN] {
        self.ip_addr.clone()
    }
}

impl std::fmt::Display for Ipv4 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}",
            self.ip_addr[0], self.ip_addr[1], self.ip_addr[2], self.ip_addr[3],
        )
    }
}

impl Handle<u32> for Ipv4 {
    fn from(value: u32) -> Self {
        let o1: u8 = (value & 0xff) as u8;
        let o2: u8 = ((value >> 8) & 0xff) as u8;
        let o3: u8 = ((value >> 16) & 0xff) as u8;
        let o4: u8 = ((value >> 24) & 0xff) as u8;

        Handle::from([o4, o3, o2, o1])
    }
    fn to(&self) -> u32 {
        ((self.ip_addr[0] as u32) << 24)
            + ((self.ip_addr[1] as u32) << 16)
            + ((self.ip_addr[2] as u32) << 8)
            + ((self.ip_addr[3] as u32) << 0)
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

    pub fn get_src_mac(&self) -> Mac {
        self.src_mac.clone()
    }
    pub fn set_src_mac(&mut self, mac: Mac) {
        self.src_mac = mac
    }

    pub fn get_src_ip(&self) -> Ipv4 {
        self.src_ip.clone()
    }
    pub fn set_src_ip(&mut self, ip: Ipv4) {
        self.src_ip = ip
    }

    pub fn get_dst_mac(&self) -> Mac {
        self.dst_mac.clone()
    }
    pub fn set_dst_mac(&mut self, mac: Mac) {
        self.dst_mac = mac
    }

    pub fn get_dst_ip(&self) -> Ipv4 {
        self.dst_ip.clone()
    }
    pub fn set_dst_ip(&mut self, ip: Ipv4) {
        self.dst_ip = ip
    }
}

/// function for building to the exponent
///
/// # Example
/// ```
/// use arpv::utils::*;
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
/// use arpv::utils::*;
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
/// use arpv::utils::*;
///
/// let bytes = b"Hello, world";
///
/// assert_eq!(str_from_bytes(bytes).as_bytes(), bytes)
/// ```
pub fn str_from_bytes(bytes: &[u8]) -> String {
    let mut string: String = String::new();

    for byte in bytes {
        string.push(byte.clone() as char)
    }

    string
}

/// creates string from char pointer
///
/// # Example
/// ```
/// use arpv::utils::*;
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
