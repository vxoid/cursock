use crate::*;
#[cfg(any(target_os = "windows", target_os = "linux"))]
use std::net::Ipv6Addr;

use std::process::*;

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


#[cfg(target_os = "linux")]
pub const TUN_HEADER_SIZE: usize = std::mem::size_of::<TunHeader>();
pub const HW_TYPE: u16 = 1;
pub const ARP_REPLY: u16 = 2;
pub const ARP_REQUEST: u16 = 1;
pub const IPV4_PROTO: u16 = 0x0800;
pub const IPV6_PROTO: u16 = 0x86DD;
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
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
}

/// header for setting and reading tun packet protocol for linux
#[repr(C)]
#[cfg(target_os = "linux")]
pub struct TunHeader {
    pub protocol: u32
}

/// an ip header wrapper without useless fields
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
    RouteAll(&'all_lt [(&'addr_lt IpAddr, &'str_lt str)]),
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

/// WinAPI common errors api
#[cfg(target_os = "windows")]
#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum WinAPIError {
    ERROR_SUCCESS = 0,
    ERROR_INVALID_FUNCTION = 1,
    ERROR_FILE_NOT_FOUND = 2,
    ERROR_PATH_NOT_FOUND = 3,
    ERROR_ACCESS_DENIED = 5,
    ERROR_INVALID_HANDLE = 6,
    ERROR_NOT_ENOUGH_MEMORY = 8,
    ERROR_INVALID_DATA = 13,
    ERROR_INVALID_PARAMETER = 87,
    ERROR_BUFFER_OVERFLOW = 111,
    ERROR_CALL_NOT_IMPLEMENTED = 120,
    ERROR_INSUFFICIENT_BUFFER = 122,
    ERROR_INVALID_NAME = 123,
    ERROR_ALREADY_EXISTS = 183,
    ERROR_ENVVAR_NOT_FOUND = 203,
    ERROR_MORE_DATA = 234,
    ERROR_OPERATION_ABORTED = 995,
    ERROR_NO_TOKEN = 1008,
    ERROR_DLL_INIT_FAILED = 1114,
    ERROR_NOT_FOUND = 1168,
    ERROR_NO_MORE_ITEMS = 259,
}

// #[allow(non_camel_case_types)]
// #[cfg(target_os = "linux")]
// #[repr(i32)]
// pub enum LinuxAPIError {
//     EPERM = 1,
//     ENOENT = 2,
//     EIO = 5,
//     EBADF = 9,
//     EAGAIN = 11,
//     ENOMEM = 12,
//     EACCES = 13,
//     EFAULT = 14,
//     ENOTDIR = 20,
//     EINVAL = 22,
//     ENFILE = 23,
//     EMFILE = 24,
//     EDEADLK = 35,
//     EBUSY = 37,
//     ENOTEMPTY = 39,
//     EINTR = 4,
//     EEXIST = 17,
//     ESPIPE = 29,
//     EROFS = 30,
//     EISDIR = 21,
//     ECHILD = 10,
//     ENODEV = 19,
//     ESRCH = 3,
//     ETXTBSY = 26,
//     ENOEXEC = 8,
//     ENAMETOOLONG = 36,
//     ENOSYS = 38,
//     ELOOP = 40,
//     ENOMSG = 42,
//     EIDRM = 43,
//     EOPNOTSUPP = 95,
//     ECONNRESET = 104,
//     ECONNABORTED = 103,
//     ECONNREFUSED = 111,
//     EINPROGRESS = 115,
//     EALREADY = 114,
//     EMSGSIZE = 90,
//     EPROTONOSUPPORT = 93,
//     EADDRINUSE = 98,
//     EADDRNOTAVAIL = 99,
//     ENETDOWN = 100,
//     ENETUNREACH = 101,
//     ENETRESET = 102,
//     EHOSTUNREACH = 113,
//     EHOSTDOWN = 112,
//     EISCONN = 106,
//     ENOTCONN = 107,
// }

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

#[cfg(target_os = "windows")]
impl WinAPIError {
    pub fn to_str(&self) -> &'static str {
        match self {
            WinAPIError::ERROR_SUCCESS => "success",
            WinAPIError::ERROR_INVALID_FUNCTION => "invalid function",
            WinAPIError::ERROR_FILE_NOT_FOUND => "file not found",
            WinAPIError::ERROR_PATH_NOT_FOUND => "path not found",
            WinAPIError::ERROR_ACCESS_DENIED => "access denied",
            WinAPIError::ERROR_INVALID_HANDLE => "invalid handle",
            WinAPIError::ERROR_NOT_ENOUGH_MEMORY => "not enough memory",
            WinAPIError::ERROR_INVALID_DATA => "invalid data",
            WinAPIError::ERROR_INVALID_PARAMETER => "invalid parameter",
            WinAPIError::ERROR_BUFFER_OVERFLOW => "buffer overflow",
            WinAPIError::ERROR_CALL_NOT_IMPLEMENTED => "call not implemented",
            WinAPIError::ERROR_INSUFFICIENT_BUFFER => "insufficient buffer",
            WinAPIError::ERROR_INVALID_NAME => "invalid name",
            WinAPIError::ERROR_ALREADY_EXISTS => "already exists",
            WinAPIError::ERROR_ENVVAR_NOT_FOUND => "envvar not found",
            WinAPIError::ERROR_MORE_DATA => "more data",
            WinAPIError::ERROR_OPERATION_ABORTED => "operation aborted",
            WinAPIError::ERROR_NO_TOKEN => "no token",
            WinAPIError::ERROR_DLL_INIT_FAILED => "dll init failed",
            WinAPIError::ERROR_NOT_FOUND => "not found",
            WinAPIError::ERROR_NO_MORE_ITEMS => "no more items",
        }
    }
}

#[cfg(target_os = "windows")]
impl Into<CursedError> for WinAPIError {
    fn into(self) -> CursedError {
        match self {
            WinAPIError::ERROR_SUCCESS => CursedError::NoError,
            WinAPIError::ERROR_INVALID_FUNCTION => CursedError::Other(CursedErrorType::Invalid),
            WinAPIError::ERROR_FILE_NOT_FOUND => CursedError::File(CursedErrorType::NotFound),
            WinAPIError::ERROR_PATH_NOT_FOUND => CursedError::Path(CursedErrorType::NotFound),
            WinAPIError::ERROR_ACCESS_DENIED => CursedError::Other(CursedErrorType::AccessDenied),
            WinAPIError::ERROR_INVALID_HANDLE => CursedError::Other(CursedErrorType::Invalid),
            WinAPIError::ERROR_NOT_ENOUGH_MEMORY => CursedError::Memory(CursedErrorType::NotEnough),
            WinAPIError::ERROR_INVALID_DATA => CursedError::Other(CursedErrorType::Invalid),
            WinAPIError::ERROR_INVALID_PARAMETER => CursedError::Input(CursedErrorType::Invalid),
            WinAPIError::ERROR_BUFFER_OVERFLOW => CursedError::Buffer(CursedErrorType::Overflow),
            WinAPIError::ERROR_CALL_NOT_IMPLEMENTED => CursedError::Other(CursedErrorType::NotImplemented),
            WinAPIError::ERROR_INSUFFICIENT_BUFFER => CursedError::Buffer(CursedErrorType::Overflow),
            WinAPIError::ERROR_INVALID_NAME => CursedError::Other(CursedErrorType::Invalid),
            WinAPIError::ERROR_ALREADY_EXISTS => CursedError::Other(CursedErrorType::AlreadyExists),
            WinAPIError::ERROR_ENVVAR_NOT_FOUND => CursedError::Envvar(CursedErrorType::NotFound),
            WinAPIError::ERROR_MORE_DATA => CursedError::Other(CursedErrorType::NotEnough),
            WinAPIError::ERROR_OPERATION_ABORTED => CursedError::Other(CursedErrorType::Aborted),
            WinAPIError::ERROR_NO_TOKEN => CursedError::Other(CursedErrorType::NotFound),
            WinAPIError::ERROR_DLL_INIT_FAILED => CursedError::Other(CursedErrorType::NotImplemented),
            WinAPIError::ERROR_NOT_FOUND => CursedError::Other(CursedErrorType::NotFound),
            WinAPIError::ERROR_NO_MORE_ITEMS => CursedError::Other(CursedErrorType::NotFound),
        }
    }
}

#[cfg(target_os = "windows")]
impl TryFrom<u32> for WinAPIError {
    type Error = CursedErrorHandle;

    fn try_from(code: u32) -> Result<Self, CursedErrorHandle> {
        match code {
            0 => Ok(WinAPIError::ERROR_SUCCESS),
            1 => Ok(WinAPIError::ERROR_INVALID_FUNCTION),
            2 => Ok(WinAPIError::ERROR_FILE_NOT_FOUND),
            3 => Ok(WinAPIError::ERROR_PATH_NOT_FOUND),
            5 => Ok(WinAPIError::ERROR_ACCESS_DENIED),
            6 => Ok(WinAPIError::ERROR_INVALID_HANDLE),
            8 => Ok(WinAPIError::ERROR_NOT_ENOUGH_MEMORY),
            13 => Ok(WinAPIError::ERROR_INVALID_DATA),
            87 => Ok(WinAPIError::ERROR_INVALID_PARAMETER),
            111 => Ok(WinAPIError::ERROR_BUFFER_OVERFLOW),
            120 => Ok(WinAPIError::ERROR_CALL_NOT_IMPLEMENTED),
            122 => Ok(WinAPIError::ERROR_INSUFFICIENT_BUFFER),
            123 => Ok(WinAPIError::ERROR_INVALID_NAME),
            183 => Ok(WinAPIError::ERROR_ALREADY_EXISTS),
            203 => Ok(WinAPIError::ERROR_ENVVAR_NOT_FOUND),
            234 => Ok(WinAPIError::ERROR_MORE_DATA),
            995 => Ok(WinAPIError::ERROR_OPERATION_ABORTED),
            1008 => Ok(WinAPIError::ERROR_NO_TOKEN),
            1114 => Ok(WinAPIError::ERROR_DLL_INIT_FAILED),
            1168 => Ok(WinAPIError::ERROR_NOT_FOUND),
            259 => Ok(WinAPIError::ERROR_NO_MORE_ITEMS),
            _ => Err(
                CursedErrorHandle::new(
                    CursedError::Input(CursedErrorType::Invalid),
                    format!("{} isn\'t common error code", code)
                )
            )
        }
    }
}

#[cfg(target_os = "windows")]
impl ToString for WinAPIError {
    fn to_string(&self) -> String {
        self.to_str().to_string()
    }
}


// #[cfg(target_os = "linux")]
// impl Into<CursedError> for LinuxAPIError {
//     fn into(self) -> CursedError {
//         match self {
//             LinuxAPIError::EPERM => CursedError::Other(CursedErrorType::AccessDenied),
//             LinuxAPIError::ENOENT => CursedError::File(CursedErrorType::NotFound),
//             LinuxAPIError::EIO => CursedError::Input(CursedErrorType::Invalid),
//             LinuxAPIError::EBADF => CursedError::File(CursedErrorType::Invalid),
//             LinuxAPIError::EAGAIN => CursedError::Other(CursedErrorType::Interrupted),
//             LinuxAPIError::ENOMEM => CursedError::Memory(CursedErrorType::NotEnough),
//             LinuxAPIError::EACCES => CursedError::Other(CursedErrorType::AccessDenied),
//             LinuxAPIError::EFAULT => CursedError::Address(CursedErrorType::Invalid),
//             LinuxAPIError::ENOTDIR => CursedError::File(CursedErrorType::NotFound),
//             LinuxAPIError::EINVAL => CursedError::Input(CursedErrorType::Invalid),
//             LinuxAPIError::ENFILE => CursedError::File(CursedErrorType::Refused),
//             LinuxAPIError::EMFILE => CursedError::File(CursedErrorType::Refused),
//             LinuxAPIError::EDEADLK => CursedError::Call(CursedErrorType::Aborted),
//             LinuxAPIError::EBUSY => CursedError::Other(CursedErrorType::AlreadyExists),
//             LinuxAPIError::ENOTEMPTY => CursedError::Data(CursedErrorType::Invalid),
//             LinuxAPIError::EINTR => CursedError::Call(CursedErrorType::Interrupted),
//             LinuxAPIError::EEXIST => CursedError::Other(CursedErrorType::AlreadyExists),
//             LinuxAPIError::ESPIPE => CursedError::Input(CursedErrorType::Invalid),
//             LinuxAPIError::EROFS => CursedError::Call(CursedErrorType::NotImplemented),
//             LinuxAPIError::EISDIR => CursedError::File(CursedErrorType::NotFound),
//             LinuxAPIError::ECHILD => CursedError::Call(CursedErrorType::Interrupted),
//             LinuxAPIError::ENODEV => CursedError::Input(CursedErrorType::Invalid),
//             LinuxAPIError::ESRCH => CursedError::Call(CursedErrorType::NotFound),
//             LinuxAPIError::ETXTBSY => CursedError::File(CursedErrorType::AlreadyExists),
//             LinuxAPIError::ENOEXEC => CursedError::Call(CursedErrorType::NotImplemented),
//             LinuxAPIError::ENAMETOOLONG => CursedError::Input(CursedErrorType::Invalid),
//             LinuxAPIError::ENOSYS => CursedError::Other(CursedErrorType::NotImplemented),
//             LinuxAPIError::ELOOP => CursedError::Call(CursedErrorType::Aborted),
//             LinuxAPIError::ENOMSG => CursedError::Data(CursedErrorType::NotEnough),
//             LinuxAPIError::EIDRM => CursedError::Input(CursedErrorType::Invalid),
//             LinuxAPIError::EOPNOTSUPP => CursedError::Call(CursedErrorType::NotSupported),
//             LinuxAPIError::ECONNRESET => CursedError::Connection(CursedErrorType::Reset),
//             LinuxAPIError::ECONNABORTED => CursedError::Connection(CursedErrorType::Aborted),
//             LinuxAPIError::ECONNREFUSED => CursedError::Connection(CursedErrorType::Refused),
//             LinuxAPIError::EINPROGRESS => CursedError::Call(CursedErrorType::AlreadyExists),
//             LinuxAPIError::EALREADY => CursedError::Other(CursedErrorType::AlreadyExists),
//             LinuxAPIError::EMSGSIZE => CursedError::Buffer(CursedErrorType::Overflow),
//             LinuxAPIError::EPROTONOSUPPORT => CursedError::Input(CursedErrorType::NotSupported),
//             LinuxAPIError::EADDRINUSE => CursedError::Address(CursedErrorType::AlreadyExists),
//             LinuxAPIError::EADDRNOTAVAIL => CursedError::Address(CursedErrorType::NotFound),
//             LinuxAPIError::ENETDOWN => CursedError::Connection(CursedErrorType::Refused),
//             LinuxAPIError::ENETUNREACH => CursedError::Connection(CursedErrorType::Refused),
//             LinuxAPIError::ENETRESET => CursedError::Connection(CursedErrorType::Reset),
//             LinuxAPIError::EHOSTUNREACH => CursedError::Connection(CursedErrorType::Refused),
//             LinuxAPIError::EHOSTDOWN => CursedError::Connection(CursedErrorType::Refused),
//             LinuxAPIError::EISCONN => CursedError::Connection(CursedErrorType::Refused),
//             LinuxAPIError::ENOTCONN => CursedError::Connection(CursedErrorType::Refused),
//         }
//     }
// }

// #[cfg(target_os = "linux")]
// impl LinuxAPIError {
//     pub fn to_str(&self) -> &'static str {
//         match self {
//             LinuxAPIError::EPERM => "permission",
//             LinuxAPIError::ENOENT => "file not found",
//             LinuxAPIError::EIO => "io",
//             LinuxAPIError::EBADF => "bad file descriptor",
//             LinuxAPIError::EAGAIN => "temporarily unavailable",
//             LinuxAPIError::ENOMEM => "not enough memory",
//             LinuxAPIError::EACCES => "access",
//             LinuxAPIError::EFAULT => "invalid address",
//             LinuxAPIError::ENOTDIR => "not a directory",
//             LinuxAPIError::EINVAL => "invalid argument",
//             LinuxAPIError::ENFILE => "too many open files in system",
//             LinuxAPIError::EMFILE => "too many open files",
//             LinuxAPIError::EDEADLK => "deadlock",
//             LinuxAPIError::EBUSY => "in use",
//             LinuxAPIError::ENOTEMPTY => "not empty",
//             LinuxAPIError::EINTR => "interrupted",
//             LinuxAPIError::EEXIST => "already exists",
//             LinuxAPIError::ESPIPE => "illegal seek",
//             LinuxAPIError::EROFS => "read-only fs",
//             LinuxAPIError::EISDIR => "is a directory",
//             LinuxAPIError::ECHILD => "child",
//             LinuxAPIError::ENODEV => "no such device",
//             LinuxAPIError::ESRCH => "no such process",
//             LinuxAPIError::ETXTBSY => "text file is busy",
//             LinuxAPIError::ENOEXEC => "no executable",
//             LinuxAPIError::ENAMETOOLONG => "name too long",
//             LinuxAPIError::ENOSYS => "not implemented",
//             LinuxAPIError::ELOOP => "too many symbolic links",
//             LinuxAPIError::ENOMSG => "no message of desired type",
//             LinuxAPIError::EIDRM => "identifier removed",
//             LinuxAPIError::EOPNOTSUPP => "operation not supported",
//             LinuxAPIError::ECONNRESET => "connection reset",
//             LinuxAPIError::ECONNABORTED => "connection aborted",
//             LinuxAPIError::ECONNREFUSED => "connection refused",
//             LinuxAPIError::EINPROGRESS => "in progress",
//             LinuxAPIError::EALREADY => "already exists",
//             LinuxAPIError::EMSGSIZE => "message too large",
//             LinuxAPIError::EPROTONOSUPPORT => "protocol not supported",
//             LinuxAPIError::EADDRINUSE => "address in use",
//             LinuxAPIError::EADDRNOTAVAIL => "address not available",
//             LinuxAPIError::ENETDOWN => "network down",
//             LinuxAPIError::ENETUNREACH => "network unreachable",
//             LinuxAPIError::ENETRESET => "network reset",
//             LinuxAPIError::EHOSTUNREACH => "host unreachable",
//             LinuxAPIError::EHOSTDOWN => "host down",
//             LinuxAPIError::EISCONN => "already connected",
//             LinuxAPIError::ENOTCONN => "not connected",
//         }
//     }
// }

// #[cfg(target_os = "linux")]
// impl TryFrom<i32> for LinuxAPIError {
//     type Error = CursedErrorHandle;

//     fn try_from(code: i32) -> Result<Self, CursedErrorHandle> {
//         match code {
//             1 => Ok(LinuxAPIError::EPERM),
//             2 => Ok(LinuxAPIError::ENOENT),
//             5 => Ok(LinuxAPIError::EIO),
//             9 => Ok(LinuxAPIError::EBADF),
//             11 => Ok(LinuxAPIError::EAGAIN),
//             12 => Ok(LinuxAPIError::ENOMEM),
//             13 => Ok(LinuxAPIError::EACCES),
//             14 => Ok(LinuxAPIError::EFAULT),
//             20 => Ok(LinuxAPIError::ENOTDIR),
//             22 => Ok(LinuxAPIError::EINVAL),
//             23 => Ok(LinuxAPIError::ENFILE),
//             24 => Ok(LinuxAPIError::EMFILE),
//             35 => Ok(LinuxAPIError::EDEADLK),
//             37 => Ok(LinuxAPIError::EBUSY),
//             39 => Ok(LinuxAPIError::ENOTEMPTY),
//             4 => Ok(LinuxAPIError::EINTR),
//             17 => Ok(LinuxAPIError::EEXIST),
//             29 => Ok(LinuxAPIError::ESPIPE),
//             30 => Ok(LinuxAPIError::EROFS),
//             21 => Ok(LinuxAPIError::EISDIR),
//             10 => Ok(LinuxAPIError::ECHILD),
//             19 => Ok(LinuxAPIError::ENODEV),
//             3 => Ok(LinuxAPIError::ESRCH),
//             26 => Ok(LinuxAPIError::ETXTBSY),
//             8 => Ok(LinuxAPIError::ENOEXEC),
//             36 => Ok(LinuxAPIError::ENAMETOOLONG),
//             38 => Ok(LinuxAPIError::ENOSYS),
//             40 => Ok(LinuxAPIError::ELOOP),
//             42 => Ok(LinuxAPIError::ENOMSG),
//             43 => Ok(LinuxAPIError::EIDRM),
//             95 => Ok(LinuxAPIError::EOPNOTSUPP),
//             104 => Ok(LinuxAPIError::ECONNRESET),
//             103 => Ok(LinuxAPIError::ECONNABORTED),
//             111 => Ok(LinuxAPIError::ECONNREFUSED),
//             115 => Ok(LinuxAPIError::EINPROGRESS),
//             114 => Ok(LinuxAPIError::EALREADY),
//             90 => Ok(LinuxAPIError::EMSGSIZE),
//             93 => Ok(LinuxAPIError::EPROTONOSUPPORT),
//             98 => Ok(LinuxAPIError::EADDRINUSE),
//             99 => Ok(LinuxAPIError::EADDRNOTAVAIL),
//             100 => Ok(LinuxAPIError::ENETDOWN),
//             101 => Ok(LinuxAPIError::ENETUNREACH),
//             102 => Ok(LinuxAPIError::ENETRESET),
//             113 => Ok(LinuxAPIError::EHOSTUNREACH),
//             112 => Ok(LinuxAPIError::EHOSTDOWN),
//             106 => Ok(LinuxAPIError::EISCONN),
//             107 => Ok(LinuxAPIError::ENOTCONN),
//             _ => Err(
//                 CursedErrorHandle::new(
//                     CursedError::Input(CursedErrorType::Invalid),
//                     format!("{} isn\'t common linux api code", code)
//                 )
//             ),
//         }
//     }
// }

// #[cfg(target_os = "linux")]
// impl ToString for LinuxAPIError {
//     fn to_string(&self) -> String {
//         self.to_str().to_string()
//     }
// }

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

impl PartialEq<Bit> for Bit {
    fn eq(&self, other: &Bit) -> bool {
        match other {
            Bit::One => match self {
                Bit::One => true,
                Bit::Zero => false,
            },
            Bit::Zero => match self {
                Bit::One => false,
                Bit::Zero => true,
            },
        }
    }
}
impl Eq for Bit {}

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

impl BinOpers for u8 {
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

impl BinOpers for u16 {
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

impl BinOpers for u128 {
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
    pub fn new(src_ip: Ipv4Addr, src_mac: Mac, dst_ip: Ipv4Addr, dst_mac: Mac) -> Self {
        Self {
            src_ip,
            src_mac,
            dst_ip,
            dst_mac,
        }
    }

    getters!(
        pub get_src_mac(src_mac) -> Mac;
        pub get_src_ip(src_ip) -> Ipv4Addr;
        pub get_dst_mac(dst_mac) -> Mac;
        pub get_dst_ip(dst_ip) -> Ipv4Addr;
    );
    setters!(
        pub set_src_mac(Mac) -> src_mac;
        pub set_src_ip(Ipv4Addr) -> src_ip;
        pub set_dst_mac(Mac) -> dst_mac;
        pub set_dst_ip(Ipv4Addr) -> dst_ip;
    );
}

pub fn prefix_from_netmask(netmask: &Ipv4Addr) -> u8 {
    let mut prefix_len: u8 = 0;
    
    'netmask: for octet in netmask.octets() {
        let mut bit: usize = u8::BITS as usize;

        loop {
            bit -= 1;

            if octet.get_bit(bit) != Bit::One {
                break 'netmask;
            }
            prefix_len += 1;

            if bit == 0 {
                break;
            }
        }
    }

    prefix_len
}

pub fn netmask_from_prefix(prefix: u8) -> Ipv4Addr {
    let prefix: u8 = if prefix > 32 {
        32
    } else {
        prefix
    };

    let mut raw_netmask: u32 = 0xffffffff;
    raw_netmask = (raw_netmask << 32-prefix) >> 32-prefix;

    let octets: [u8; IPV4_LEN] = unsafe {
        std::mem::transmute(raw_netmask)
    };

    Ipv4Addr::from(octets)
}

pub fn run_queries(queries: &[(&str, &str)], program: &str) -> Result<(), CursedErrorHandle> {
    for query in queries {
        let output: Output = match Command::new(program).args([query.0, query.1]).output() {
            Ok(output) => output,
            Err(err) => return Err(
                CursedErrorHandle::new(
                    CursedError::from(err.kind()),
                    format!("can\'t run command due to \"{}\"", err.to_string())
                )
            )
        };

        let err: Vec<u8> = output.stderr;
        if err.len() > 0 {
            return Err(
                CursedErrorHandle::new(
                    CursedError::Input(CursedErrorType::Invalid),
                    format!("\"{}\" execution ended with \"{}\"", query.1, str_from_bytes(&err))
                )
            );
        }
    }

    Ok(())
}

pub fn get_interface_addresses(interface: &str) -> Result<(Option<(Ipv4Addr, u8)>, Option<(Ipv6Addr, u8)>), CursedErrorHandle> {
    #[cfg(target_os = "linux")]
    {
        let (ipv4, ipv6, _, _) = get_interface_by_name(interface)?;
        Ok((ipv4, ipv6))
    }
    #[cfg(target_os = "windows")]
    {
        let index: u32 = match interface.parse() {
            Ok(index) => index,
            Err(err) => return Err(
                CursedErrorHandle::new(
                    CursedError::Data(CursedErrorType::Parse),
                    format!("can\'t parse {} as interface index due to \"{}\"", interface, err.to_string()),
                )
            ),
        };

        let (ipv4, ipv6, _, _) = get_interface_by_index(index)?;
        Ok((ipv4, ipv6))
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        let _ = interface;

        Err(CursedErrorHandle::new(
            CursedError::Other(CursedErrorType::NotSupported),
            format!("{} is not supported yet!", std::env::consts::OS),
        ))
    }
}

#[cfg(target_os = "windows")]
pub fn get_interface_by_index(index: u32) -> Result<(Option<(Ipv4Addr, u8)>, Option<(Ipv6Addr, u8)>, Mac, String), CursedErrorHandle> {
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

    let result: u32 = unsafe {
        ccs::GetAdaptersAddresses(
            ccs::AF_UNSPEC as u32,
            0,
            ccs::null_mut(),
            addresses,
            &mut size
        )
    };

    if result != ccs::ERROR_SUCCESS {
        let err: WinAPIError = match WinAPIError::try_from(result) {
            Ok(err) => err,
            Err(_) => return Err(
                CursedErrorHandle::new(
                    CursedError::Unknown,
                    format!("can\'t get adapter addresses due to \"{}\" win api error", result)
                )
            ),
        };
        let message: &str = err.to_str();

        return Err(
            CursedErrorHandle::new(
                err.into(),
                format!("can\'t get adapter addresses due to \"{}\" ({}) win api error", message, result)
            )
        );
    }

    let mut data: Option<(Option<(Ipv4Addr, u8)>, Option<(Ipv6Addr, u8)>, Mac, String)> = None;
    let mut p_current: *mut ccs::IP_ADAPTER_ADDRESSES = addresses;
    while !p_current.is_null() {
        let adapter: &mut ccs::IP_ADAPTER_ADDRESSES = unsafe {
            &mut *p_current
        };

        if index == adapter.index {
            let mut mac: [u8; MAC_LEN] = [0; MAC_LEN];
            memcpy(mac.as_mut_ptr(), adapter.physical_address.as_ptr(), MAC_LEN);
            let mac: Mac = Handle::from(mac);
            
            let mut ipv4: Option<(Ipv4Addr, u8)> = None;
            let mut ipv6: Option<(Ipv6Addr, u8)> = None;

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
                        ccs::AF_INET => if let None = ipv4 {
                            let address: &mut ccs::sockaddr_in = unsafe {
                                &mut *(p_sockaddr as *mut ccs::sockaddr_in)
                            };
                            
                            ipv4 = Some((Ipv4Addr::from(address.sin_addr.s_addr), r_unicast_address.onlink_prefix_length))
                        },
                        ccs::AF_INET6 => if let None = ipv6 {
                            let address: &mut ccs::sockaddr_in6 = unsafe {
                                &mut *(p_sockaddr as *mut ccs::sockaddr_in6)
                            };

                            ipv6 = Some((Ipv6Addr::from(address.sin6_addr.s6_addr), r_unicast_address.onlink_prefix_length));
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
                CursedError::Input(CursedErrorType::Invalid),
                format!("{} isn\'t valid adapter index", index)
            )
        ),
    };

    Ok(data)
}

#[cfg(target_os = "windows")]
pub fn get_interface_by_guid(guid: &str) -> Result<(Option<(Ipv4Addr, u8)>, Option<(Ipv6Addr, u8)>, Mac, u32), CursedErrorHandle> {
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

    let result: u32 = unsafe {
        ccs::GetAdaptersAddresses(
            ccs::AF_UNSPEC as u32,
            0,
            ccs::null_mut(),
            addresses,
            &mut size
        )
    };

    if result != ccs::ERROR_SUCCESS {
        let err: WinAPIError = match WinAPIError::try_from(result) {
            Ok(err) => err,
            Err(_) => return Err(
                CursedErrorHandle::new(
                    CursedError::Unknown,
                    format!("can\'t get adapter addresses due to \"{}\" win api error", result)
                )
            ),
        };
        let message: &str = err.to_str();

        return Err(
            CursedErrorHandle::new(
                err.into(),
                format!("can\'t get adapter addresses due to \"{}\" ({}) win api error", message, result)
            )
        );
    }

    let mut data: Option<(Option<(Ipv4Addr, u8)>, Option<(Ipv6Addr, u8)>, Mac, u32)> = None;
    let mut p_current: *mut ccs::IP_ADAPTER_ADDRESSES = addresses;
    while !p_current.is_null() {
        let adapter: &mut ccs::IP_ADAPTER_ADDRESSES = unsafe {
            &mut *p_current
        };

        if guid == str_from_cstr(adapter.adapter_name) {
            let mut mac: [u8; MAC_LEN] = [0; MAC_LEN];
            memcpy(mac.as_mut_ptr(), adapter.physical_address.as_ptr(), MAC_LEN);
            let mac: Mac = Handle::from(mac);
            
            let mut ipv4: Option<(Ipv4Addr, u8)> = None;
            let mut ipv6: Option<(Ipv6Addr, u8)> = None;

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
                        ccs::AF_INET => if let None = ipv4 {
                            let address: &mut ccs::sockaddr_in = unsafe {
                                &mut *(p_sockaddr as *mut ccs::sockaddr_in)
                            };
                            
                            ipv4 = Some((Ipv4Addr::from(address.sin_addr.s_addr), r_unicast_address.onlink_prefix_length))
                        },
                        ccs::AF_INET6 => if let None = ipv6 {
                            let address: &mut ccs::sockaddr_in6 = unsafe {
                                &mut *(p_sockaddr as *mut ccs::sockaddr_in6)
                            };

                            ipv6 = Some((Ipv6Addr::from(address.sin6_addr.s6_addr), r_unicast_address.onlink_prefix_length));
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
                CursedError::Input(CursedErrorType::Invalid),
                format!("{} isn\'t valid adapter guid", guid)
            )
        ),
    };

    Ok(data)
}

#[cfg(target_os = "linux")]
pub fn get_interface_by_name(interface: &str) -> Result<(Option<(Ipv4Addr, u8)>, Option<(Ipv6Addr, u8)>, Mac, i32), CursedErrorHandle> {
    let mut addrs: *mut ccs::ifaddrs = ccs::null_mut();

    let result: i32 = unsafe {
        ccs::getifaddrs(&mut addrs)
    };

    if result < 0 {
        let err: io::Error = io::Error::last_os_error();
    
        return Err(
            CursedErrorHandle::new(
                CursedError::from(err.kind()),
                format!("can\'t get interfaces due to \"{}\"", err.to_string()),
            )
        );
    }

    let mut current: *mut ccs::ifaddrs = addrs;
    let mut ipv4: Option<(Ipv4Addr, u8)> = None;
    let mut ipv6: Option<(Ipv6Addr, u8)> = None;

    let (mac, index): (Mac, i32) = get_ifr_info(interface)?;

    while !current.is_null() {
        let r_current: &mut ccs::ifaddrs = unsafe {
            &mut *current
        };

        if str_from_cstr(r_current.ifa_name) == interface {            
            let r_current: &mut ccs::ifaddrs = unsafe {
                &mut *current
            };
            let family: i32 = unsafe {
                (*r_current.ifa_addr).sa_family as i32
            };

            match family {
                ccs::AF_INET => if let None = ipv4 {
                    let addr: &mut ccs::sockaddr_in = unsafe {
                        &mut *(r_current.ifa_addr as *mut ccs::sockaddr_in)
                    };
                    let netmask: &mut ccs::sockaddr_in = unsafe {
                        &mut *(r_current.ifa_netmask as *mut ccs::sockaddr_in)
                    };

                    ipv4 = Some((Ipv4Addr::from(addr.sin_addr.s_addr), prefix_from_netmask(&Ipv4Addr::from(netmask.sin_addr.s_addr))))
                },
                ccs::AF_INET6 => if let None = ipv6 {
                    let addr: &mut ccs::sockaddr_in6 = unsafe {
                        &mut *(r_current.ifa_addr as *mut ccs::sockaddr_in6)
                    };
                        
                    ipv6 = Some((Ipv6Addr::from(addr.sin6_addr.s6_addr), addr.sin6_prefixlen as u8))
                },
                _ => {}
            }
        }

        current = r_current.ifa_next
    }
    unsafe { ccs::freeifaddrs(addrs) }

    Ok((ipv4, ipv6, mac, index))
}

#[cfg(target_os = "linux")]
pub fn get_ifr_info(interface: &str) -> Result<(Mac, i32), CursedErrorHandle> {
    let socket: i32 = unsafe {
        ccs::socket(
            ccs::AF_INET,
            ccs::SOCK_DGRAM,
            0,
        )
    };

    if socket < 0 {
        let err: io::Error = io::Error::last_os_error();
    
        return Err(
            CursedErrorHandle::new(
                CursedError::from(err.kind()),
                format!("can\'t init socket due to \"{}\"", err.to_string()),
            )
        );
    }

    let interface: CString = match CString::new(interface) {
        Ok(interface) => interface,
        Err(err) => {
            return Err(CursedErrorHandle::new(
                CursedError::Data(CursedErrorType::Parse),
                format!(
                    "{} is not valid c string can\'t convert it due to \"{}\"",
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

    let interface_length: usize = interface.as_bytes_with_nul().len();
    let ifr_length: usize = if_request.ifr_name.len();
    let length: usize = if interface_length > ifr_length {
        ifr_length
    } else {
        interface_length
    };
    memcpy(
        if_request.ifr_name.as_mut_ptr(),
        interface.as_ptr(),
        length,
    );

    let mac: Mac = get_ifr_mac(socket, &mut if_request)?;
    let index: i32 = get_ifr_index(socket, &mut if_request)?;

    unsafe { ccs::close(socket); }

    Ok((mac, index))
}

#[cfg(target_os = "linux")]
fn get_ifr_index(socket: i32, ifr: *mut ccs::ifreq) -> Result<i32, CursedErrorHandle> {
    let result: i32 = unsafe { ccs::ioctl(socket, ccs::SIOCGIFINDEX, ifr) };

    if result < 0 {
        let err: io::Error = io::Error::last_os_error();
    
        return Err(
            CursedErrorHandle::new(
                CursedError::from(err.kind()),
                format!("can\'t get if index due to \"{}\"", err.to_string()),
            )
        );
    }

    let index: i32 = unsafe { (*ifr).ifr_ifru.ifru_ifindex.clone() };

    Ok(index)
}

#[cfg(target_os = "linux")]
fn get_ifr_mac(socket: i32, ifr: *mut ccs::ifreq) -> Result<Mac, CursedErrorHandle> {
    let result: i32 = unsafe { ccs::ioctl(socket, ccs::SIOCGIFHWADDR, ifr) };

    if result < 0 {
        let err: io::Error = io::Error::last_os_error();
    
        return Err(
            CursedErrorHandle::new(
                CursedError::from(err.kind()),
                format!("can\'t get if mac due to \"{}\"", err.to_string()),
            )
        );
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


pub fn virtual_ip(interface: &str, addr: &IpAddr, prefix: u8) -> Result<(), CursedErrorHandle> {
    #[cfg(target_os = "linux")]
    {
        virtual_ip_linux(interface, addr, prefix)
    }
    #[cfg(target_os = "windows")]
    {
        virtual_ip_windows(interface, addr, prefix)
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        let _ = addr;
        let _ = prefix;
        let _ = interface;
        
        Err(CursedErrorHandle::new(
            CursedError::Other(CursedErrorType::NotSupported),
            format!("{} is not supported yet!", std::env::consts::OS),
        ))
    }
}

#[cfg(target_os = "windows")]
fn virtual_ip_windows(interface: &str, addr: &IpAddr, prefix: u8) -> Result<(), CursedErrorHandle> {
    let index: u32 = match interface.parse() {
        Ok(index) => index,
        Err(err) => return Err(
            CursedErrorHandle::new(
                CursedError::Data(CursedErrorType::Parse),
                format!("can\'t parse {} as interface index due to \"{}\"", interface, err.to_string()),
            )
        ),
    };

    let (address, lt): (ccs::SOCKADDR_INET, u32) = match addr {
        IpAddr::V4(ipv4) => {
            let sockaddr: ccs::sockaddr_in = ccs::sockaddr_in {
                sin_family: ccs::AF_INET as i16,
                sin_port: 0,
                sin_addr: ccs::in_addr { s_addr: ipv4.octets() },
                sin_zero: [0; 8]
            };

            (ccs::SOCKADDR_INET { ipv4: sockaddr }, 0)
        },
        IpAddr::V6(ipv6) => {
            let sockaddr: ccs::sockaddr_in6 = ccs::sockaddr_in6 {
                sin6_family: ccs::AF_INET6 as i16,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: ccs::in6_addr { s6_addr: ipv6.octets() },
                sin6_scope_id: 0
            };

            (ccs::SOCKADDR_INET { ipv6: sockaddr }, 0xFFFFFFFF)
        },
    };

    let unicast: ccs::MIB_UNICASTIPADDRESS_ROW = ccs::MIB_UNICASTIPADDRESS_ROW {
        address,
        luid: 0,
        index,
        prefix_origin: 0x01,
        suffix_origin: 0x01,
        valid_lifetime: lt,
        preferred_lifetime: lt,
        on_link_prefix_length: prefix,
        skip_as_source: 0,
        dad_state: 0,
        scope_id: 0,
        timestamp: 0
    };

    let result: u32 = unsafe {
        ccs::CreateUnicastIpAddressEntry(&unicast)
    };
    if result != 0 {
        let err: WinAPIError = match WinAPIError::try_from(result) {
            Ok(err) => err,
            Err(_) => return Err(
                CursedErrorHandle::new(
                    CursedError::Unknown,
                    format!("got {} error while creating virtual ip", result)
                )
            ),
        };
        let message: &str = err.to_str();

        return Err(
            CursedErrorHandle::new(
                err.into(),
                format!("got {} ({}) error while creating virtual ip", message, result)
            )
        );
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn virtual_ip_linux(interface: &str, addr: &IpAddr, prefix: u8) -> Result<(), CursedErrorHandle> {
    let query: String = format!("ip addr add {}/{} dev \"{}\"", addr, prefix, interface);

    run_queries(&[("-c", &query)], "sh")
}

pub fn delete_ip(interface: &str, addr: &IpAddr, prefix: u8) -> Result<(), CursedErrorHandle> {
    #[cfg(target_os = "linux")]
    {
        delete_ip_linux(interface, addr, prefix)
    }
    #[cfg(target_os = "windows")]
    {
        delete_ip_windows(interface, addr, prefix)
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        let _ = addr;
        let _ = prefix;
        let _ = interface;
        
        Err(CursedErrorHandle::new(
            CursedError::Other(CursedErrorType::NotSupported),
            format!("{} is not supported yet!", std::env::consts::OS),
        ))
    }
}

#[cfg(target_os = "linux")]
fn delete_ip_linux(interface: &str, addr: &IpAddr, prefix: u8) -> Result<(), CursedErrorHandle> {
    let query: String = format!("ip addr del {}/{} dev {}", addr, prefix, interface);

    run_queries(&[("-c", &query)], "sh")
}

#[cfg(target_os = "windows")]
fn delete_ip_windows(interface: &str, addr: &IpAddr, prefix: u8) -> Result<(), CursedErrorHandle> {
    let index: u32 = match interface.parse() {
        Ok(index) => index,
        Err(err) => return Err(
            CursedErrorHandle::new(
                CursedError::Data(CursedErrorType::Parse),
                format!("can\'t parse {} as interface index due to \"{}\"", interface, err.to_string()),
            )
        ),
    };

    let address: ccs::SOCKADDR_INET = match addr {
        IpAddr::V4(ipv4) => {
            let sockaddr: ccs::sockaddr_in = ccs::sockaddr_in {
                sin_family: ccs::AF_INET as i16,
                sin_port: 0,
                sin_addr: ccs::in_addr { s_addr: ipv4.octets() },
                sin_zero: [0; 8]
            };

            ccs::SOCKADDR_INET { ipv4: sockaddr }
        },
        IpAddr::V6(ipv6) => {
            let sockaddr: ccs::sockaddr_in6 = ccs::sockaddr_in6 {
                sin6_family: ccs::AF_INET6 as i16,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: ccs::in6_addr { s6_addr: ipv6.octets() },
                sin6_scope_id: 0
            };

            ccs::SOCKADDR_INET { ipv6: sockaddr }
        },
    };

    let unicast: ccs::MIB_UNICASTIPADDRESS_ROW = ccs::MIB_UNICASTIPADDRESS_ROW {
        address,
        luid: 0,
        index,
        prefix_origin: 0,
        suffix_origin: 0,
        valid_lifetime: 0,
        preferred_lifetime: 0,
        on_link_prefix_length: prefix,
        skip_as_source: 0,
        dad_state: 0,
        scope_id: 0,
        timestamp: 0
    };

    let result: u32 = unsafe {
        ccs::DeleteUnicastIpAddressEntry(&unicast)
    };
    if result != 0 {
        let err: WinAPIError = match WinAPIError::try_from(result) {
            Ok(err) => err,
            Err(_) => return Err(
                CursedErrorHandle::new(
                    CursedError::Unknown,
                    format!("got {} error while creating virtual ip", result)
                )
            ),
        };
        let message: &str = err.to_str();

        return Err(
            CursedErrorHandle::new(
                err.into(),
                format!("got {} ({}) error while creating virtual ip", message, result)
            )
        );
    }

    Ok(())
}

#[cfg(target_os = "windows")]
pub fn log(code: Option<u32>) -> Result<String, CursedErrorHandle> {
    match code {
        Some(code) => match log_code(code) {
            Ok(message) => return Ok(message),
            Err(_) => {},
        },
        None => {},
    }
    
    let code: u32 = unsafe {
        ccs::GetLastError()
    };

    log_code(code)
}

#[cfg(target_os = "windows")]
fn log_code(code: u32) -> Result<String, CursedErrorHandle> {
    let system: *mut u16 = ccs::null_mut();

    let result: u32 = unsafe { ccs::FormatMessageW(
            ccs::FORMAT_MESSAGE_FROM_SYSTEM | ccs::FORMAT_MESSAGE_ALLOCATE_BUFFER |
            ccs::FORMAT_MESSAGE_MAX_WIDTH_MASK,
            ccs::null(),
            code,
            0x0800,
            system,
            0,
            ccs::null_mut()
    ) };

    if system as usize == 0 || result == 0 {
        return Err(
            CursedErrorHandle::new(
                CursedError::Buffer(CursedErrorType::Overflow),
                "no error message".to_string()
            )
        );
    }

    Ok(str_from_cutf16(system))
}