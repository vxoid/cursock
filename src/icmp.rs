use std::net;
use std::io;

use rand::Rng;

use crate::*;

#[derive(Clone)]
pub struct IcmpV4 {
    socket: Socket,
    ipv4: net::Ipv4Addr
}

impl IcmpV4 {
    /// Initializes icmp structure
    ///
    /// # Examples
    /// ```
    /// use cursock::*;
    /// 
    /// #[cfg(target_os = "linux")]
    /// let icmp = IcmpV4::new("wlan0").expect("initialize error"); // Linux
    /// #[cfg(target_os = "windows")]
    /// let icmp = IcmpV4::new("10").expect("initialize error"); // Windows, id of the interface you can get running "route PRINT"
    /// ```
    pub fn new(interface: &str) -> io::Result<Self> {
        let socket = Socket::new(interface, IpVer::V4)?;
        
        let ipv4 = match socket.get_src_ip() {
            net::IpAddr::V4(ipv4) => ipv4.clone(),
            net::IpAddr::V6(ipv6) => return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("{} don\'t have any ipv4 address, found {}", socket.get_adapter().get_name(), ipv6)
            )),
        };

        Ok(Self { socket, ipv4 })
    }

    /// Creates icmp connection, can be used for icmp echo requests
    /// 
    /// # Examples
    /// ```
    /// use cursock::*;
    /// 
    /// let icmp = IcmpV4::new("wlan0").expect("initialize error");
    /// 
    /// let connection = icmp.new_connection().expect("connection error");
    /// ```
    pub fn new_connection(&self) -> io::Result<IcmpV4Connection> {
        let mut rng = rand::thread_rng();

        Ok(IcmpV4Connection { sq: 1, id: rng.gen(), parent: self })
    }

    /// Sends icmp request
    /// 
    /// # Examples
    /// ```
    /// use cursock::*;
    /// use std::net;
    /// 
    /// let icmp = IcmpV4::new("wlan0").expect("initialize error");
    /// 
    /// let ip = net::Ipv4Addr::new(192, 168, 1, 1);
    /// let mac = Mac::from([0xff; 6]);
    /// 
    /// let data = IcmpData::new(IcmpType::EchoRequest, 0, 0, 0x1234, 1, vec![0; 255]);
    /// icmp.send(&ip, &mac, data).expect("send error");
    /// ```
    pub fn send(&self, dst_ip: &net::Ipv4Addr, mac: &Mac, icmp_data: IcmpData) -> io::Result<()> {
        let message = icmp_data.get_data();
        let buffer_len: usize = ETH_HEADER_SIZE+IPV4_HEADER_SIZE+ICMPV4_HEADER_SIZE+message.len();
        let mut buffer: Vec<u8> = vec![0; ETH_HEADER_SIZE+IPV4_HEADER_SIZE+ICMPV4_HEADER_SIZE+message.len()];

        let eth_header: &mut EthHeader = unsafe {
            &mut *(buffer.as_mut_ptr() as *mut EthHeader)
        };
        let ip_header: &mut IpV4Header = unsafe {
            &mut *((buffer.as_mut_ptr() as usize + ETH_HEADER_SIZE) as *mut IpV4Header)
        };
        let icmp_header: &mut IcmpV4Header = unsafe {
            &mut *((buffer.as_mut_ptr() as usize + ETH_HEADER_SIZE + IPV4_HEADER_SIZE) as *mut IcmpV4Header)
        };

        eth_header.source = self.socket.get_src_mac().clone().into();
        eth_header.dest = mac.clone().into();
        eth_header.proto = u16::from_be(IP_PROTO);

        ip_header.verihl = (4 << 4) + 5; // 4 - ip version - 5 header len (20)
        ip_header.tot_len = u16::from_be((IPV4_HEADER_SIZE+ICMPV4_HEADER_SIZE+message.len()) as u16);
        ip_header.ttl = 128;
        ip_header.protocol = ICMP_PROTO as u8;
        ip_header.saddr = self.ipv4.octets();
        ip_header.daddr = dst_ip.octets();

        icmp_header.type_ = icmp_data.get_type().clone().into();
        icmp_header.id = icmp_data.get_id().clone();
        icmp_header.sq = icmp_data.get_sq().to_be();
        
        let message_start: usize = ETH_HEADER_SIZE+IPV4_HEADER_SIZE+ICMPV4_HEADER_SIZE;
        for i in message_start..buffer_len {
            buffer[i] = message[i-message_start].clone()
        }

        let icmp_checksum: u16 = checksum(
            icmp_header as *const IcmpV4Header as *const u8,
            buffer_len - (ETH_HEADER_SIZE + IPV4_HEADER_SIZE)
        );

        let ip_checksum: u16 = checksum(
            ip_header as *const IpV4Header as *const u8,
            IPV4_HEADER_SIZE
        );
        ip_header.check = ip_checksum;
        icmp_header.check = icmp_checksum;
        
        self.socket.send_raw_packet(&buffer)
    }

    /// Reads icmp request
    ///
    /// # Examples
    /// ```
    /// use cursock::*;
    /// use cursock::utils::*;
    /// use std::net::Ipv4Addr;
    /// 
    /// let icmp = IcmpV4::new("wlan0").expect("initialize error");
    /// let mut buffer = [0u8; 65535];
    /// 
    /// icmp.read(&mut buffer).expect("read error");
    /// ```
    pub fn read<F>(&self, buffer: &mut [u8], mut closure: F) -> io::Result<(IpData, IcmpData)>
        where F: FnMut(&IpData, &IcmpData) -> bool {
        let eth_header: &EthHeader = unsafe {
            &*(buffer.as_ptr() as *const EthHeader)
        };
        let ip_header: &IpV4Header = unsafe {
            &*((buffer.as_ptr() as usize + ETH_HEADER_SIZE) as *const IpV4Header)
        };
        let icmp_header: &IcmpV4Header = unsafe {
            &*((buffer.as_mut_ptr() as usize + ETH_HEADER_SIZE + IPV4_HEADER_SIZE) as *const IcmpV4Header)
        };
        
        loop {
            self.socket.read_raw_packet(buffer)?;
        
            if eth_header.proto != u16::from_be(IP_PROTO) || ip_header.protocol != ICMP_PROTO as u8 {
                continue
            }
            let message_len = ip_header.tot_len.to_be() as usize - (IPV4_HEADER_SIZE+ICMPV4_HEADER_SIZE);

            let ip_data: IpData = IpData::new(
                ip_header.tot_len,
                ip_header.ttl,
                net::IpAddr::V4(net::Ipv4Addr::from(ip_header.saddr)),
                net::IpAddr::V4(net::Ipv4Addr::from(ip_header.daddr))
            );
            let icmp_data: IcmpData = IcmpData::new(
                IcmpType::from(icmp_header.type_),
                icmp_header.code,
                icmp_header.check,
                icmp_header.id,
                icmp_header.sq,
                buffer[ETH_HEADER_SIZE+IPV4_HEADER_SIZE+ICMPV4_HEADER_SIZE..ETH_HEADER_SIZE+IPV4_HEADER_SIZE+ICMPV4_HEADER_SIZE+message_len].to_vec()
            );

            if closure(&ip_data, &icmp_data) {
                return Ok((ip_data, icmp_data));
            }
        }
    }

    /// destroys structure
    /// 
    /// # Examples
    /// ```
    /// use cursock::*;
    /// let icmp = IcmpV4::new("wlan0").expect("initialize error");
    /// 
    /// icmp.destroy()
    /// ```
    pub fn destroy(&self) {
        self.socket.destroy()
    }

    getters!(
        pub get_socket(socket) -> Socket;
    );
}

/// struct for doing icmp requests, which needs connection, like echo
pub struct IcmpV4Connection<'p> {
    parent: &'p IcmpV4,
    sq: u16,
    id: u16
}

impl<'p> IcmpV4Connection<'p> {
    /// icmp echo request
    /// 
    /// # Examples
    /// ```
    /// use cursock::*;
    /// use std::net;
    /// 
    /// let icmp = IcmpV4::new("wlan0").expect("initialize error");
    /// 
    /// let ip = net::Ipv4Addr::new(8, 8, 8, 8);
    /// let mac = Mac::from([0xff; 6]);
    /// 
    /// let mut buffer = [0; 0xffff];
    /// let message = [0; 10];
    /// 
    /// let mut connection = icmp.new_connection().expect("connection error");
    /// let (ip_data, icmp_data) = connection.echo(&ip, &mac, &message, &mut buffer).expect("echo error");
    /// ```
    pub fn echo(&mut self, dst_ip: &net::Ipv4Addr, mac: &Mac, message: &[u8], recv_buffer: &mut [u8]) -> io::Result<(utils::IpData, utils::IcmpData)> {
        let data = IcmpData::new(IcmpType::EchoRequest, 0, 0, self.id, self.sq, message.to_vec());
        self.parent.send(dst_ip, mac, data)?;

        let result = self.parent.read(recv_buffer, |ip_data, icmp_data| {
            icmp_data.get_type().clone() == IcmpType::EchoReply && ip_data.get_src() == dst_ip && icmp_data.get_id() == &self.id && icmp_data.get_sq().to_be() == self.sq
        })?;

        self.sq += 1;
        
        Ok(result)
    }
}

fn checksum(header: *const u8, len: usize) -> u16 {
    let mut sum: i32 = 0;
    let mut left: usize = len;
    let words: *const u16 = header as *const u16; 

    let mut i: usize = 0;
    while left > 1 {
        sum += unsafe {
            *((words as usize + i) as *const u16)
        } as i32;

        left -= 2;
        i += 2
    }

    if left == 1 {            
        sum += unsafe {
            *((words as usize + i - 1) as *const u8)
        } as i32;
    }

    sum = (sum >> 16) + (sum & 0xffff); 
    sum += sum >> 16;

    (!sum) as u16
}