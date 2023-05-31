use std::net;
use std::io;

use crate::*;

#[derive(Clone)]
pub struct Arp {
    socket: Socket,
    ipv4: net::Ipv4Addr
}

impl Arp {
    /// Initializes arp structure
    ///
    /// # Examples
    /// ```
    /// use cursock::*;
    /// use cursock::utils::*;
    /// #[cfg(target_os = "linux")]
    /// let arp = Arp::new("wlan0").expect("initialize error"); // Linux
    /// #[cfg(target_os = "windows")]
    /// let arp = Arp::new("10").expect("initialize error"); // Windows, id of the interface you can get running "route PRINT"
    /// ```
    pub fn new(interface: &str) -> io::Result<Self> {
        let socket: Socket = Socket::new(interface, IpVer::V4)?;

        let ipv4 = match socket.get_src_ip() {
            net::IpAddr::V4(ipv4) => ipv4.clone(),
            net::IpAddr::V6(ipv6) => return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("{} don\'t have any ipv4 address, found {}", socket.get_adapter().get_name(), ipv6)
            )),
        };

        Ok(Self { socket, ipv4 })
    }
    /// Does an arp request
    /// # Examples
    /// ```
    /// use cursock::*;
    /// use std::net::Ipv4Addr;
    ///
    /// let arp = Arp::new("wlan0").expect("initialize error");
    /// let ip_addr: Ipv4Addr = Ipv4Addr::from([192, 168, 0, 1]);
    /// let response = arp.who_has(&ip_addr).expect("send error");
    /// ```
    pub fn who_has(&self, dst_ip: &net::Ipv4Addr) -> io::Result<ArpResponse> {
        const BUFFER_SIZE: usize = ETH_HEADER_SIZE + ARP_HEADER_SIZE;
        let mut buffer: [u8; BUFFER_SIZE] = [0; BUFFER_SIZE];

        let eth_header: &mut EthHeader = unsafe { &mut *(buffer.as_mut_ptr() as *mut EthHeader) };
        let arp_header: &mut ArpHeader =
            unsafe { &mut *((buffer.as_mut_ptr() as usize + ETH_HEADER_SIZE) as *mut ArpHeader) };

        eth_header.dest = [0xff; MAC_LEN];

        eth_header.source = self.socket.get_src_mac().clone().into();
        arp_header.target_mac = [0; MAC_LEN];
        arp_header.sender_mac = self.socket.get_src_mac().clone().into();

        eth_header.proto = u16::from_be(ARP_PROTO);

        arp_header.hardware_type = u16::from_be(HW_TYPE);
        arp_header.protocol_type = u16::from_be(IP_PROTO);
        arp_header.hardware_len = MAC_LEN as u8;
        arp_header.protocol_len = IPV4_LEN as u8;
        arp_header.opcode = u16::from_be(ARP_REQUEST);

        arp_header.sender_ip = self.ipv4.octets();
        arp_header.target_ip = dst_ip.octets();

        self.socket.send_raw_packet(&buffer)?;

        self.read_arp(|header| u16::from_be(header.opcode) == ARP_REPLY && &net::Ipv4Addr::from(header.sender_ip) == dst_ip)
    }
    /// Does an arp reply
    /// # Examples
    /// ```
    /// use cursock::*;
    /// use std::net::Ipv4Addr;
    ///
    /// let arp = Arp::new("wlan0").expect("initialize error");
    /// let ip_addr1: Ipv4Addr = Ipv4Addr::from([192, 168, 1, 1]);
    /// let mac_addr1: Mac = Mac::from([0xff; 6]);
    /// let ip_addr2: Ipv4Addr = Ipv4Addr::from([192, 168, 1, 2]);
    /// arp.is_at(arp.get_src_mac(), &ip_addr1, &mac_addr1, &ip_addr2).expect("send error")
    /// ```
    pub fn is_at(
        &self,
        src_mac: &Mac,
        src_ip: &net::Ipv4Addr,
        dst_mac: &Mac,
        dst_ip: &net::Ipv4Addr
    ) -> io::Result<()> {
        const BUFFER_SIZE: usize = ETH_HEADER_SIZE + ARP_HEADER_SIZE;
        let mut buffer: [u8; BUFFER_SIZE] = [0; BUFFER_SIZE];

        let eth_header: &mut EthHeader = unsafe { &mut *(buffer.as_mut_ptr() as *mut EthHeader) };
        let arp_header: &mut ArpHeader =
            unsafe { &mut *((buffer.as_mut_ptr() as usize + ETH_HEADER_SIZE) as *mut ArpHeader) };

        eth_header.dest = dst_mac.clone().into();

        eth_header.source = self.socket.get_src_mac().clone().into();
        arp_header.target_mac = dst_mac.clone().into();
        arp_header.sender_mac = src_mac.clone().into();

        eth_header.proto = u16::from_be(ARP_PROTO);

        arp_header.hardware_type = u16::from_be(HW_TYPE);
        arp_header.protocol_type = u16::from_be(IP_PROTO);
        arp_header.hardware_len = MAC_LEN as u8;
        arp_header.protocol_len = IPV4_LEN as u8;
        arp_header.opcode = u16::from_be(ARP_REPLY);

        arp_header.sender_ip = src_ip.octets();
        arp_header.target_ip = dst_ip.octets();

        self.socket.send_raw_packet(&buffer)
    }

    fn read_arp<F>(&self, mut closure: F) -> io::Result<ArpResponse>
        where F: FnMut(&ArpHeader) -> bool {
        const BUFFER_SIZE: usize = 60;
        let mut buffer: [u8; BUFFER_SIZE] = [0; BUFFER_SIZE];

        let eth_header: &EthHeader = unsafe { &*(buffer.as_ptr() as *mut EthHeader) };
        let arp_header: &ArpHeader =
            unsafe { &*((buffer.as_ptr() as usize + ETH_HEADER_SIZE) as *mut ArpHeader) };

        loop {
            if let Err(err) = self.socket.read_raw_packet(&mut buffer) {
                return Err(err);
            }

            if u16::from_be(eth_header.proto) == ARP_PROTO && closure(arp_header)
            {
                break;
            }
        }

        let arp_response: ArpResponse = ArpResponse::new(
            net::Ipv4Addr::from(arp_header.sender_ip),
            Mac::from(arp_header.sender_mac),
            net::Ipv4Addr::from(arp_header.target_ip),
            Mac::from(arp_header.target_mac),
        );

        Ok(arp_response)
    }

    /// Destroys arp structure
    ///
    /// # Examples
    /// ```
    /// use cursock::*;
    ///
    /// let arp = cursock::Arp::new("wlan0").expect("initialize error");
    /// arp.destroy()
    /// ```
    pub fn destroy(&self) {
        self.socket.destroy()
    }

    getters!(
        pub get_socket(socket) -> Socket;
    );
}