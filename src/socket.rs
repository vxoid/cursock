use std::io;

#[cfg(any(target_os = "windows",))]
use std::ffi::CString;

use crate::*;

/// Struct for raw socketing
///
/// # Examples
/// ```
/// use cursock::*;
/// use cursock::utils::*;
///
/// #[cfg(target_os = "linux")]
/// let socket = Socket::new("wlan0", IpVer::V6).expect("initialize error"); // Linux
/// #[cfg(target_os = "windows")]
/// let socket = Socket::new("10", IpVer::V6).expect("initialize error"); // Windows, id of the interface you can get running "route PRINT"
///
/// let buffer: [u8; 1024] = [0; 1024];
///
/// socket.send_raw_packet(&buffer).expect("send error");
///
/// socket.destroy()
/// ```
pub struct Socket {
    #[cfg(target_os = "linux")]
    socket: i32,
    #[cfg(target_os = "windows")]
    adapter: usize,
    interface: Adapter,
}

impl Socket {
    /// Initializes socket structure
    ///
    /// # Examples
    /// ```
    /// use cursock::*;
    /// use cursock::utils::*;
    ///
    /// #[cfg(target_os = "linux")]
    /// let socket = Socket::new("wlan0").expect("initialize error"); // Linux
    /// #[cfg(target_os = "windows")]
    /// let socket = Socket::new("10").expect("initialize error"); // Windows, id of the interface you can get running "route PRINT"
    /// ```
    pub fn new(interface: &str) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            Self::new_linux(interface)
        }
        #[cfg(target_os = "windows")]
        {
            Self::new_windows(interface)
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            let _ = interface;
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{} is not supported yet!", std::env::consts::OS),
            ))
        }
    }
    /// Sends raw packet
    ///
    /// # Examples
    /// ```
    /// use cursock::*;
    /// use cursock::utils::*;
    ///
    /// let socket = Socket::new("wlan0").expect("initialize error");
    /// let buffer = [0; 100];
    /// socket.send_raw_packet(&buffer).expect("send error")
    /// ```
    pub fn send_raw_packet(&self, buffer: &[u8]) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.send_raw_packet_linux(buffer)
        }
        #[cfg(target_os = "windows")]
        {
            self.send_raw_packet_windows(buffer)
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            let _ = buffer;
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{} is not supported yet!", std::env::consts::OS),
            ))
        }
    }
    /// Reads raw packet, can be used for sniffing
    ///
    /// # Examples
    /// ```
    /// use cursock::*;
    /// use cursock::utils::*;
    ///
    /// let socket = Socket::new("wlan0").expect("initialize error");
    /// let mut buffer = [0; 1000];
    /// socket.read_raw_packet(&mut buffer).expect("read error")
    /// ```
    pub fn read_raw_packet(&self, buffer: &mut [u8]) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.read_raw_packet_linux(buffer)
        }
        #[cfg(target_os = "windows")]
        {
            self.read_raw_packet_windows(buffer)
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            let _ = buffer;
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{} is not supported yet!", std::env::consts::OS),
            ))
        }
    }

    pub fn get_src_mac(&self) -> &Mac {
        self.interface.get_mac()
    }
    pub fn get_adapter(&self) -> &Adapter {
        &self.interface
    }

    /// Destroys socket structure
    ///
    /// # Examples
    /// ```
    /// use cursock::*;
    ///
    /// let socket = Socket::new("wlan0").expect("initialize error");
    /// socket.destroy()
    /// ```
    pub fn destroy(&self) {
        #[cfg(target_os = "linux")]
        {
            self.destroy_linux()
        }
    }
    #[cfg(target_os = "linux")]
    fn new_linux(interface: &str) -> io::Result<Self> {
        let socket: i32 = unsafe {
            ccs::socket(
                ccs::AF_PACKET,
                ccs::SOCK_RAW,
                (ccs::ETH_P_ALL as u16).to_be() as i32,
            )
        };

        if socket < 0 {
            return Err(io::Error::last_os_error());
        }

        let adapter = Adapter::get_by_ifname(interface)?;

        Ok(Self {
            socket,
            interface: adapter,
        })
    }
    #[cfg(target_os = "windows")]
    fn new_windows(interface: &str) -> io::Result<Self> {
        let id = interface
            .parse::<u32>()
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;

        let interface = Adapter::get_by_id(id)?;

        let guid = interface.get_guid();
        let pcap_interface: String = format!("rpcap://\\Device\\NPF_{}", guid);
        let pcap_interface: CString = CString::new(pcap_interface)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;

        let mut error_buffer: [i8; 256] = [0; 256];

        let adapter: *mut ccs::pcap = unsafe {
            ccs::pcap_open(
                pcap_interface.as_ptr(),
                65535,
                ccs::PCAP_OPENFLAG_PROMISCUOUS,
                100,
                std::ptr::null_mut(),
                error_buffer.as_mut_ptr(),
            )
        };

        if adapter as usize == 0 {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                format!(
                    "Can\'t open adapted due to {}",
                    str_from_cstr(error_buffer.as_ptr())
                ),
            ));
        }

        Ok(Self {
            adapter: adapter as usize,
            interface,
        })
    }
    #[cfg(target_os = "linux")]
    fn read_raw_packet_linux(&self, buffer: &mut [u8]) -> io::Result<()> {
        let length: isize = unsafe {
            ccs::recvfrom(
                self.socket,
                buffer.as_mut_ptr() as *mut std::os::raw::c_void,
                buffer.len(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };

        if length < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }
    #[cfg(target_os = "windows")]
    fn read_raw_packet_windows(&self, buffer: &mut [u8]) -> io::Result<()> {
        let mut header: *mut ccs::pcap_pkthdr = std::ptr::null_mut();
        let mut pkt_data: *const u8 = std::ptr::null();

        let result: i32 = unsafe {
            ccs::pcap_next_ex(self.adapter as *mut ccs::pcap, &mut header, &mut pkt_data)
        };

        if result == 0 {
            return self.read_raw_packet_windows(buffer);
        } else if result != 1 {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                format!("pcap_next_ex call failed with code {}", result),
            ));
        }

        let header: &mut ccs::pcap_pkthdr = unsafe { &mut *header };

        let size: usize = if buffer.len() < header.caplen as usize {
            buffer.len()
        } else {
            header.caplen as usize
        };

        memcpy(buffer.as_mut_ptr(), pkt_data, size);

        Ok(())
    }
    #[cfg(target_os = "windows")]
    fn send_raw_packet_windows(&self, buffer: &[u8]) -> io::Result<()> {
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

            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                format!("can\'t send buffer due to \"{}\"", error),
            ));
        }

        Ok(())
    }
    #[cfg(target_os = "linux")]
    fn send_raw_packet_linux(&self, buffer: &[u8]) -> io::Result<()> {
        let raw_src_mac: [u8; MAC_LEN] = self.interface.get_mac().clone().into();
        let mut addr: ccs::sockaddr_ll = ccs::sockaddr_ll {
            sll_family: 0,
            sll_protocol: 0,
            sll_ifindex: *self.get_adapter().get_index(),
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
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }
    #[cfg(target_os = "linux")]
    fn destroy_linux(&self) {
        unsafe { ccs::close(self.socket) };
    }
}

impl Clone for Socket {
    #[cfg(target_os = "windows")]
    fn clone(&self) -> Self {
        Self {
            adapter: self.adapter,
            interface: self.interface.clone(),
        }
    }
    #[cfg(target_os = "linux")]
    fn clone(&self) -> Self {
        Self {
            socket: self.socket,
            interface: self.interface.clone(),
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    fn clone(&self) -> Self {
        Self {
            interface: self.interface.clone(),
        }
    }
}
