use std::{thread, time::Duration};

use crate::*;

pub struct Arp {
    socket: Socket,
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
    /// let arp = cursock::Arp::new("{D37YDFA1-7F4F-F09E-V622-5PACEF22AE49}", true).expect("initialize error"); // Windows
    /// // Since windows socket implementation is using npcap you should pass "npcap-like" interface
    /// ```
    pub fn new(interface: &str, debug: bool) -> Result<Self, CursedErrorHandle> {
        let socket: Socket = match Socket::new(interface, debug) {
            Ok(socket) => socket,
            Err(err) => return Err(err),
        };
        Ok(Self { socket })
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
    pub fn who_has(&self, dst_ip: &Ipv4, debug: bool) -> Result<(), CursedErrorHandle> {
        const BUFFER_SIZE: usize = ETH_HEADER_SIZE + ARP_HEADER_SIZE;
        let mut buffer: [u8; BUFFER_SIZE] = [0; BUFFER_SIZE];

        let eth_header: &mut EthHeader = unsafe { &mut *(buffer.as_mut_ptr() as *mut EthHeader) };
        let arp_header: &mut ArpHeader =
            unsafe { &mut *((buffer.as_mut_ptr() as usize + ETH_HEADER_SIZE) as *mut ArpHeader) };

        eth_header.dest = [0xff; MAC_LEN];

        eth_header.source = self.get_src_mac().to();
        arp_header.target_mac = [0; MAC_LEN];
        arp_header.sender_mac = self.get_src_mac().to();

        eth_header.proto = ccs::htons(ARP_PROTO);

        arp_header.hardware_type = ccs::htons(HW_TYPE);
        arp_header.protocol_type = ccs::htons(IP_PROTO);
        arp_header.hardware_len = MAC_LEN as u8;
        arp_header.protocol_len = IPV4_LEN as u8;
        arp_header.opcode = ccs::htons(ARP_REQUEST);

        arp_header.sender_ip = self.get_src_ip().to();
        arp_header.target_ip = dst_ip.to();

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

        eth_header.source = self.get_src_mac().to();
        arp_header.target_mac = dst_mac.to();
        arp_header.sender_mac = src_mac.to();

        eth_header.proto = ccs::htons(ARP_PROTO);

        arp_header.hardware_type = ccs::htons(HW_TYPE);
        arp_header.protocol_type = ccs::htons(IP_PROTO);
        arp_header.hardware_len = MAC_LEN as u8;
        arp_header.protocol_len = IPV4_LEN as u8;
        arp_header.opcode = ccs::htons(ARP_REPLY);

        arp_header.sender_ip = src_ip.to();
        arp_header.target_ip = dst_ip.to();

        if debug {
            print!("Buffer: [ ");
            for byte in buffer {
                print!("{} ", byte)
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
            Handle::from(0),
            Handle::from([0; MAC_LEN]),
            Handle::from(0),
            Handle::from([0; MAC_LEN]),
        );
        let mut buffer: [u8; READ_BUFFER_LEN] = [0; READ_BUFFER_LEN];

        let eth_header: &EthHeader = unsafe { &*(buffer.as_ptr() as *mut EthHeader) };
        let arp_header: &ArpHeader =
            unsafe { &*((buffer.as_ptr() as usize + ETH_HEADER_SIZE) as *mut ArpHeader) };

        loop {
            if let Err(_) = self.socket.read_raw_packet(&mut buffer, debug) {
                continue;
            }

            if ccs::ntohs(eth_header.proto) == ARP_PROTO
                && ccs::ntohs(arp_header.opcode) == ARP_REPLY
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
        arp_response.set_dst_ip(Handle::from(arp_header.target_ip));
        arp_response.set_src_ip(Handle::from(arp_header.sender_ip));

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
        timeout: Duration,
        debug: bool,
    ) -> Result<ArpResponse, CursedErrorHandle> {
        let (tx, rx) = std::sync::mpsc::channel();
        let wrapper: Wrapper<Arp> = Wrapper::new(self);

        thread::spawn(move || {
            let _ = tx.send(wrapper.reference().read_arp(debug));
        });

        let result: Result<ArpResponse, CursedErrorHandle> = match rx.recv_timeout(timeout) {
            Ok(result) => result,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                return Err(CursedErrorHandle::new(
                    CursedError::TimeOut,
                    format!("Receive timed out ({} secconds)", timeout.as_secs_f64()),
                ))
            }
            Err(err) => {
                return Err(CursedErrorHandle::new(
                    CursedError::ThreadJoin,
                    format!("Can\'t receive response due to \"{}\"", err.to_string()),
                ))
            }
        };

        result
    }
    pub fn get_src_ip(&self) -> &Ipv4 {
        self.socket.get_src_ip()
    }
    pub fn get_src_mac(&self) -> &Mac {
        self.socket.get_src_mac()
    }
    /// Destroys arp structure
    ///
    /// # Examples
    /// ```
    /// use cursock::*;
    ///
    /// let arp = cursock::Arp::new("wlan0", true).expect("initialize error");
    /// arp.destroy()
    /// ```
    pub fn destroy(&self) {
        self.socket.destroy()
    }
}
