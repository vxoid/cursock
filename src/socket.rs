use std::time::Duration;
#[cfg(target_os = "windows")]
use std::ffi::CString;

use crate::*;

/// Struct for raw socketing
///
/// # Examples
/// ```
/// #[cfg(target_os = "linux")]
/// let socket = cursock::Socket::new("wlan0", true).expect("initialize error"); // Linux
/// #[cfg(target_os = "windows")]
/// let socket = cursock::Socket::new("8", true).expect("initialize error"); // Windows
/// // Since v1.2.5 you need to use index which you can get running "route print"
///
/// let buffer: [u8; 1024] = [0; 1024];
///
/// socket.send_raw_packet(&buffer, true).expect("send error");
///
/// socket.destroy()
/// ```
pub struct Socket {
    #[cfg(target_os = "linux")]
    index: i32,
    #[cfg(target_os = "linux")]
    socket: i32,
    #[cfg(target_os = "windows")]
    adapter: usize,
    src_ip: IpAddr,
    src_mac: Mac,
}

impl Socket {
    /// Initializes socket structure
    ///
    /// # Examples
    /// ```
    /// #[cfg(target_os = "linux")]
    /// let socket = cursock::Socket::new("wlan0", true).expect("initialize error"); // Linux
    /// #[cfg(target_os = "windows")]
    /// let socket = cursock::Socket::new("8", true).expect("initialize error"); // Windows
    /// // Since v1.2.5 you need to use index which you can get running "route print"
    /// ```
    pub fn new(interface: &str, prefered: IpVersions, debug: bool) -> Result<Self, CursedErrorHandle> {
        #[cfg(target_os = "linux")]
        {
            Self::new_linux(interface, prefered, debug)
        }
        #[cfg(target_os = "windows")]
        {
            Self::new_windows(interface, prefered, debug)
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            let _ = debug;
            let _ = prefered;
            let _ = interface;
            Err(CursedErrorHandle::new(
                CursedError::OS,
                format!("{} is not supported yet!", std::env::consts::OS),
            ))
        }
    }
    /// Sends raw packet
    ///
    /// # Examples
    /// ```
    /// let socket = cursock::Socket::new("wlan0", true).expect("initialize error");
    /// let buffer = [0; 100];
    /// socket.send_raw_packet(&buffer, true).expect("send error")
    /// ```
    pub fn send_raw_packet(&self, buffer: &[u8], debug: bool) -> Result<(), CursedErrorHandle> {
        #[cfg(target_os = "linux")]
        {
            self.send_raw_packet_linux(buffer, debug)
        }
        #[cfg(target_os = "windows")]
        {
            self.send_raw_packet_windows(buffer, debug)
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            let _ = buffer;
            let _ = debug;
            Err(CursedErrorHandle::new(
                CursedError::OS,
                format!("{} is not supported yet!", std::env::consts::OS),
            ))
        }
    }
    /// Reads raw packet, can be used for sniffing
    ///
    /// # Examples
    /// ```
    /// let socket = cursock::Socket::new("wlan0", true).expect("initialize error");
    /// let mut buffer = [0; 1000];
    /// socket.read_raw_packet(&mut buffer, true).expect("read error")
    /// ```
    pub fn read_raw_packet(&self, buffer: &mut [u8], debug: bool) -> Result<usize, CursedErrorHandle> {
        #[cfg(target_os = "linux")]
        {
            self.read_raw_packet_linux(buffer, debug)
        }
        #[cfg(target_os = "windows")]
        {
            self.read_raw_packet_windows(buffer, debug)
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            let _ = buffer;
            let _ = debug;
            Err(CursedErrorHandle::new(
                CursedError::OS,
                format!("{} is not supported yet!", std::env::consts::OS),
            ))
        }
    }
    pub fn read_raw_packet_timeout(
        &self,
        buffer: &mut [u8],
        debug: bool,
        timeout: Duration,
    ) -> Result<usize, CursedErrorHandle> {
        match Self::read_timeout(Wrapper::new(self), Wrapper::new(buffer), debug, timeout) {
            Some(result) => result,
            None => return Err(
                CursedErrorHandle::new(CursedError::TimeOut, String::from("socket read timed out!"))
            ),
        }
    }

    timeout!{
        read_timeout(
            socket: Wrapper<Socket> => Wrapper::reference,
            buffer: Wrapper<[u8]> => Wrapper::mut_reference,
            debug: bool
        ) -> Result<usize, CursedErrorHandle>,
        Self::read_raw_packet
    }

    getters!(
        pub get_src_ip(src_ip) -> IpAddr;
        pub get_src_mac(src_mac) -> Mac;
    );

    #[cfg(target_os = "linux")]
    fn new_linux(interface: &str, prefered: IpVersions, debug: bool) -> Result<Self, CursedErrorHandle> {
        let socket: i32 = unsafe {
            ccs::socket(
                ccs::AF_PACKET,
                ccs::SOCK_RAW,
                (ccs::ETH_P_ALL as u16).to_be() as i32,
            )
        };

        if socket < 0 {
            if debug {
                unsafe { ccs::perror(EMPTY_ARRAY.as_ptr()) }
            }
            return Err(CursedErrorHandle::new(
                CursedError::Initialize,
                format!("Can\'t initialize socket ({} < 0)", socket),
            ));
        }

        let (ipv4, ipv6, src_mac, index) = get_interface_info(interface, debug)?;
        let src_ip: IpAddr = {
            match prefered {
                IpVersions::V4 => {
                    if let Some(ipv4) = ipv4 {
                        IpAddr::V4(ipv4)
                    } else if let Some(ipv6) = ipv6 {
                        IpAddr::V6(ipv6)
                    } else {
                        return Err(
                            CursedErrorHandle::new(
                                CursedError::NotEnought,
                                format!("{} interface has no ipv4 or ipv6 addresses", interface)
                            )
                        );
                    }
                },
                IpVersions::V6 => {
                    if let Some(ipv6) = ipv6 {
                        IpAddr::V6(ipv6)
                    } else if let Some(ipv4) = ipv4 {
                        IpAddr::V4(ipv4)
                    } else {
                        return Err(
                            CursedErrorHandle::new(
                                CursedError::NotEnought,
                                format!("{} interface has no ipv4 or ipv6 addresses", interface)
                            )
                        );
                    }
                }
            }
        };

        if debug {
            println!(
                "{} - {}, ip: {}, mac: {}",
                index,
                interface,
                src_ip,
                src_mac
            );
        }

        Ok(Self {
            socket,
            src_mac,
            src_ip,
            index,
        })
    }
    #[cfg(target_os = "windows")]
    fn new_windows(interface: &str, prefered: IpVersions, debug: bool) -> Result<Self, CursedErrorHandle> {
        let index: u32 = match interface.parse() {
            Ok(index) => index,
            Err(err) => return Err(
                CursedErrorHandle::new(
                    CursedError::Parse,
                    format!("can\'t parse {} as interface index due to \"{}\"", interface, err.to_string()),
                )
            ),
        };

        let (ipv4, ipv6, src_mac, guid) = get_interface_by_index(index)?;
        let src_ip: IpAddr = {
            match prefered {
                IpVersions::V4 => {
                    if let Some(ipv4) = ipv4 {
                        IpAddr::V4(ipv4)
                    } else if let Some(ipv6) = ipv6 {
                        IpAddr::V6(ipv6)
                    } else {
                        return Err(
                            CursedErrorHandle::new(
                                CursedError::NotEnought,
                                format!("{} interface has no ipv4 or ipv6 addresses", index)
                            )
                        );
                    }
                },
                IpVersions::V6 => {
                    if let Some(ipv6) = ipv6 {
                        IpAddr::V6(ipv6)
                    } else if let Some(ipv4) = ipv4 {
                        IpAddr::V4(ipv4)
                    } else {
                        return Err(
                            CursedErrorHandle::new(
                                CursedError::NotEnought,
                                format!("{} interface has no ipv4 or ipv6 addresses", index)
                            )
                        );
                    }
                }
            }
        };

        if debug {
            println!("{} - ip: {}, mac: {}, guid: {}", index, src_ip, src_mac, guid);
        }

        let pcap_interface: String = format!("rpcap://\\Device\\NPF_{}", guid);
        let pcap_interface: CString = match CString::new(pcap_interface.clone()) {
            Ok(pcap_interface) => pcap_interface,
            Err(err) => {
                return Err(CursedErrorHandle::new(
                    CursedError::Parse,
                    format!(
                        "{} is not valid c string can\'t convert it due to {}",
                        pcap_interface,
                        err.to_string()
                    ),
                ))
            }
        };

        let mut error_buffer: [i8; 256] = [0; 256];

        let adapter: *mut ccs::pcap = unsafe {
            ccs::pcap_open(
                pcap_interface.as_ptr(),
                65535,
                ccs::PCAP_OPENFLAG_PROMISCUOUS,
                1,
                ccs::null_mut(),
                error_buffer.as_mut_ptr(),
            )
        };

        if adapter as usize == 0 {
            return Err(CursedErrorHandle::new(
                CursedError::Sockets,
                format!(
                    "Can\'t open adapted due to {}",
                    str_from_cstr(error_buffer.as_ptr())
                ),
            ));
        }

        Ok(Self {
            adapter: adapter as usize,
            src_ip,
            src_mac,
        })
    }
    #[cfg(target_os = "linux")]
    fn read_raw_packet_linux(
        &self,
        buffer: &mut [u8],
        debug: bool,
    ) -> Result<usize, CursedErrorHandle> {
        let length: isize = unsafe {
            ccs::recvfrom(
                self.socket,
                buffer.as_mut_ptr() as *mut std::os::raw::c_void,
                buffer.len(),
                0,
                ccs::null_mut(),
                ccs::null_mut(),
            )
        };

        if length < 0 {
            if debug {
                unsafe { ccs::perror(EMPTY_ARRAY.as_ptr()) }
            }

            return Err(CursedErrorHandle::new(
                CursedError::Sockets,
                String::from("Can\'t receive packet"),
            ));
        }

        if debug {
            println!("Received {} bytes", length);
        }

        Ok(length as usize)
    }
    #[cfg(target_os = "windows")]
    fn read_raw_packet_windows(
        &self,
        buffer: &mut [u8],
        debug: bool,
    ) -> Result<usize, CursedErrorHandle> {
        let mut header: *mut ccs::pcap_pkthdr = ccs::null_mut();
        let mut pkt_data: *const u8 = ccs::null();

        let mut result: i32 = 0;
        while result == 0 {
            result = unsafe {
                ccs::pcap_next_ex(self.adapter as *mut ccs::pcap, &mut header, &mut pkt_data)
            };
        }

        let header: &mut ccs::pcap_pkthdr = unsafe { &mut *header };

        if debug {
            println!("Received {} bytes", header.caplen)
        }

        memcpy(buffer.as_mut_ptr(), pkt_data, buffer.len());

        Ok(header.caplen as usize)
    }
    #[cfg(target_os = "windows")]
    fn send_raw_packet_windows(&self, buffer: &[u8], debug: bool) -> Result<(), CursedErrorHandle> {
        let length: i32 = unsafe {
            ccs::pcap_inject(
                self.adapter as *mut ccs::pcap,
                buffer.as_ptr() as *const std::os::raw::c_void,
                buffer.len(),
            )
        };

        if length < 0 {
            let error: String =
                unsafe { str_from_cstr(ccs::pcap_geterr(self.adapter as *mut ccs::pcap)) };

            return Err(CursedErrorHandle::new(
                CursedError::Sockets,
                format!("Can\'t send buffer due to \"{}\"", error),
            ));
        }

        if debug {
            println!("Sended {} bytes", length)
        }

        Ok(())
    }
    #[cfg(target_os = "linux")]
    fn send_raw_packet_linux(&self, buffer: &[u8], debug: bool) -> Result<(), CursedErrorHandle> {
        let raw_src_mac: [u8; MAC_LEN] = self.src_mac.to();
        let mut addr: ccs::sockaddr_ll = ccs::sockaddr_ll {
            sll_family: 0,
            sll_protocol: 0,
            sll_ifindex: self.index,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: MAC_LEN as u8,
            sll_addr: [0; 8],
        };
        for i in 0..MAC_LEN {
            addr.sll_addr[i] = raw_src_mac[i]
        }

        let addrlen: ccs::SocklenT = std::mem::size_of_val(&addr) as ccs::SocklenT;

        let length: isize = unsafe {
            ccs::sendto(
                self.socket,
                buffer.as_ptr() as *const std::os::raw::c_void,
                buffer.len(),
                0,
                &addr as *const ccs::sockaddr_ll as *const ccs::sockaddr,
                addrlen,
            )
        };

        if length < 0 {
            if debug {
                unsafe { ccs::perror(EMPTY_ARRAY.as_ptr()) }
            }
            return Err(CursedErrorHandle::new(
                CursedError::Sockets,
                String::from("Can\'t send buffer"),
            ));
        }

        if debug {
            println!("Sended {} bytes", length)
        }

        Ok(())
    }
}

unsafe impl Send for Socket {}
unsafe impl Sync for Socket {}