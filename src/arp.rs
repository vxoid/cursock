use crate::*;

/// arp protocol implementation
/// 
/// # Examples
/// ```
/// use cursock::*;
/// let arp: Arp = Arp::new("eth0", true).expect("init error");
/// 
/// let target: Ipv4 = Handle::from([192, 168, 0, 1]);
/// arp.who_has(&target, true).expect("who has error");
/// 
/// let response: ArpResponse = arp.read_arp(true).expect("read error");
/// 
/// arp.destroy();
/// ```
pub struct Arp {
    socket: Socket,
    ipv4: Ipv4Addr
}

impl Arp {
    /// Initializes arp structure
    ///
    /// # Examples
    /// ```
    /// use cursock::*;
    /// use cursock::utils::*;
    /// #[cfg(target_os = "linux")]
    /// let arp = cursock::Arp::new("wlan0", true).expect("initialize error"); // Linux
    /// #[cfg(target_os = "windows")]
    /// let arp = cursock::Arp::new("8", true).expect("initialize error"); // Windows
    /// // Since v1.2.5 you need to use index which you can get running "route print"
    /// ```
    pub fn new(interface: &str, debug: bool) -> Result<Self, CursedErrorHandle> {
        let socket: Socket = Socket::new(interface, IpVersions::V4, debug)?;
        if let IpAddr::V4(ipv4) = socket.get_src_ip().clone()  {
            return Ok(Self { socket, ipv4 });
        }

        Err(
            CursedErrorHandle::new(
                CursedError::Input(CursedErrorType::Invalid),
                format!("since {} interface has no ipv4 addresses we can\'t use arp", interface)
            )
        )
    }
    /// Does an arp request
    /// # Examples
    /// ```
    /// use cursock::*;
    /// use cursock::utils::*;
    ///
    /// let arp = cursock::Arp::new("wlan0", true).expect("initialize error");
    /// let ip_addr: Ipv4 = Handle::from([192, 168, 1, 1]);
    /// arp.who_has(&ip_addr, true).expect("send error")
    /// ```
    pub fn who_has(&self, dst_ip: &Ipv4Addr, debug: bool) -> Result<(), CursedErrorHandle> {
        const BUFFER_SIZE: usize = ETH_HEADER_SIZE + ARP_HEADER_SIZE;
        let mut buffer: [u8; BUFFER_SIZE] = [0; BUFFER_SIZE];

        let eth_header: &mut EthHeader = unsafe { &mut *(buffer.as_mut_ptr() as *mut EthHeader) };
        let arp_header: &mut ArpHeader =
            unsafe { &mut *((buffer.as_mut_ptr() as usize + ETH_HEADER_SIZE) as *mut ArpHeader) };

        eth_header.dest = [0xff; MAC_LEN];

        eth_header.source = self.socket.get_src_mac().to();
        arp_header.target_mac = [0; MAC_LEN];
        arp_header.sender_mac = self.socket.get_src_mac().to();

        eth_header.proto = (ARP_PROTO as u16).to_be();

        arp_header.hardware_type = (HW_TYPE as u16).to_be();
        arp_header.protocol_type = (IPV4_PROTO as u16).to_be();
        arp_header.hardware_len = MAC_LEN as u8;
        arp_header.protocol_len = IPV4_LEN as u8;
        arp_header.opcode = (ARP_REQUEST as u16).to_be();

        arp_header.sender_ip = self.ipv4.octets();
        arp_header.target_ip = dst_ip.octets();

        if debug {
            print!("Buffer: [ ");
            for byte in buffer {
                print!("{} ", byte)
            }
            println!("]")
        }

        self.socket.send_raw_packet(&buffer, debug)
    }
    /// Does an arp reply
    /// # Examples
    /// ```
    /// use cursock::*;
    /// use cursock::utils::*;
    ///
    /// let arp = cursock::Arp::new("wlan0", true).expect("initialize error");
    /// let ip_addr1: Ipv4 = Handle::from([192, 168, 1, 1]);
    /// let mac_addr1: Mac = Handle::from([0xff; 6]);
    /// let ip_addr2: Ipv4 = Handle::from([192, 168, 1, 2]);
    /// arp.is_at(arp.get_src_mac(), &ip_addr1, &mac_addr1, &ip_addr2, true).expect("send error")
    /// ```
    pub fn is_at(
        &self,
        src_mac: &Mac,
        src_ip: &Ipv4,
        dst_mac: &Mac,
        dst_ip: &Ipv4,
        debug: bool,
    ) -> Result<(), CursedErrorHandle> {
        const BUFFER_SIZE: usize = ETH_HEADER_SIZE + ARP_HEADER_SIZE;
        let mut buffer: [u8; BUFFER_SIZE] = [0; BUFFER_SIZE];

        let eth_header: &mut EthHeader = unsafe { &mut *(buffer.as_mut_ptr() as *mut EthHeader) };
        let arp_header: &mut ArpHeader =
            unsafe { &mut *((buffer.as_mut_ptr() as usize + ETH_HEADER_SIZE) as *mut ArpHeader) };

        eth_header.dest = dst_mac.to();

        eth_header.source = self.socket.get_src_mac().to();
        arp_header.target_mac = dst_mac.to();
        arp_header.sender_mac = src_mac.to();

        eth_header.proto = (ARP_PROTO as u16).to_be();

        arp_header.hardware_type = (HW_TYPE as u16).to_be();
        arp_header.protocol_type = (IPV4_PROTO as u16).to_be();
        arp_header.hardware_len = MAC_LEN as u8;
        arp_header.protocol_len = IPV4_LEN as u8;
        arp_header.opcode = (ARP_REPLY as u16).to_be();

        arp_header.sender_ip = src_ip.to();
        arp_header.target_ip = dst_ip.to();

        if debug {
            print!("Buffer: [ ");
            for byte in buffer {
                print!("{:X} ", byte)
            }
            println!("]")
        }

        self.socket.send_raw_packet(&buffer, debug)
    }
    /// Reads an arp reply
    /// # Examples
    /// ```
    /// use cursock::*;
    /// use cursock::utils::*;
    ///
    /// let arp = cursock::Arp::new("wlan0", true).expect("initialize error");
    /// let ip_addr: Ipv4 = Handle::from([192, 168, 1, 1]);
    /// arp.who_has(&ip_addr, true).expect("send error");
    /// let response = arp.read_arp(true).expect("read error");
    /// ```
    pub fn read_arp(&self, debug: bool) -> Result<ArpResponse, CursedErrorHandle> {
        let mut arp_response: ArpResponse = ArpResponse::new(
            Ipv4Addr::from(0),
            Handle::from([0; MAC_LEN]),
            Ipv4Addr::from(0),
            Handle::from([0; MAC_LEN]),
        );
        const BUFFER_SIZE: usize = 60;
        let mut buffer: [u8; BUFFER_SIZE] = [0; BUFFER_SIZE];

        let eth_header: &EthHeader = unsafe { &*(buffer.as_ptr() as *mut EthHeader) };
        let arp_header: &ArpHeader =
            unsafe { &*((buffer.as_ptr() as usize + ETH_HEADER_SIZE) as *mut ArpHeader) };

        loop {
            if let Err(err) = self.socket.read_raw_packet(&mut buffer, debug) {
                return Err(err);
            }

            if eth_header.proto == ARP_PROTO.to_be()
                && arp_header.opcode == ARP_REPLY.to_be()
            {
                if debug {
                    print!("Buffer: [ ");
                    for byte in buffer {
                        print!("{:x} ", byte)
                    }
                    println!("]");
                }

                break;
            }
        }

        arp_response.set_dst_mac(Handle::from(arp_header.target_mac));
        arp_response.set_src_mac(Handle::from(arp_header.sender_mac));
        arp_response.set_dst_ip(Ipv4Addr::from(arp_header.target_ip));
        arp_response.set_src_ip(Ipv4Addr::from(arp_header.sender_ip));

        Ok(arp_response)
    }
    /// Reads arp with timeout    
    /// # Examples
    /// ```
    /// use cursock::*;
    /// use cursock::utils::*;
    /// use std::time::Duration;
    ///
    /// let arp = cursock::Arp::new("wlan0", true).expect("initialize error");
    /// let ip_addr: Ipv4 = Handle::from([192, 168, 1, 1]);
    /// arp.who_has(&ip_addr, true).expect("send error");
    /// let response = arp.read_arp_timeout(Duration::from_millis(1000), true).expect("read error");
    /// ```
    pub fn read_arp_timeout(
        &self,
        debug: bool,
        timeout: Duration,
    ) -> Result<ArpResponse, CursedErrorHandle> {
        match Self::read_arp_with_timeout(Wrapper::new(self), debug, timeout) {
            Some(result) => result,
            None => return Err(
                CursedErrorHandle::new(CursedError::Other(CursedErrorType::Timedout), String::from("arp read timed out!"))
            ),
        }
    }

    timeout!{
        read_arp_with_timeout(arp: Wrapper<Arp> => Wrapper::reference, debug: bool) -> Result<ArpResponse, CursedErrorHandle>,
        Self::read_arp
    }

    getters!(
        pub get_socket(socket) -> Socket;
    );
}