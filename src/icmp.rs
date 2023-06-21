use std::io;
use std::net;

use rand::Rng;

use crate::ip::IpPacket;
use crate::ip::V4;
use crate::*;

#[derive(Clone)]
pub struct Icmp {
    arp: Arp,
}

impl Icmp {
    /// Initializes icmp structure
    ///
    /// # Examples
    /// ```
    /// use cursock::*;
    ///
    /// #[cfg(target_os = "linux")]
    /// let icmp = Icmp::new("wlan0").expect("initialize error"); // Linux
    /// #[cfg(target_os = "windows")]
    /// let icmp = Icmp::new("10").expect("initialize error"); // Windows, id of the interface you can get running "route PRINT"
    /// ```
    pub fn new(interface: &str) -> io::Result<Self> {
        let arp = Arp::new(interface)?;

        Ok(Self { arp })
    }

    /// Creates icmp connection, can be used for icmp echo requests
    ///
    /// # Examples
    /// ```
    /// use cursock::*;
    ///
    /// let icmp = Icmp::new("wlan0").expect("initialize error");
    ///
    /// let connection = icmp.new_connection("192.168.1.1".parse().unwrap()).expect("connection error");
    /// ```
    pub fn new_connection<'p, 'd>(
        &'p mut self,
        dst_ip: &'d net::IpAddr,
    ) -> io::Result<IcmpConnection<'p, 'd>> {
        let mut rng = rand::thread_rng();

        Ok(IcmpConnection {
            sq: 1,
            id: rng.gen(),
            parent: self,
            dst_ip,
        })
    }

    /// Sends icmp request
    ///
    /// # Examples
    /// ```
    /// use cursock::*;
    /// use std::net;
    ///
    /// let icmp = Icmp::new("wlan0").expect("initialize error");
    ///
    /// let ip = net::Ipv4Addr::new(192, 168, 1, 1);
    ///
    /// let data = IcmpData::new(IcmpType::EchoRequest, 0, 0, 0x1234, 1, vec![0; 255]);
    /// icmp.send(&ip, data).expect("send error");
    /// ```
    pub fn send(&mut self, dst_ip: &net::IpAddr, icmp_data: IcmpData) -> io::Result<()> {
        let message = icmp_data.get_data();
        let buffer_len: usize = ICMP_HEADER_SIZE + message.len();
        let mut buffer: Vec<u8> = vec![0; ICMP_HEADER_SIZE + message.len()];

        let icmp_header: &mut IcmpHeader =
            unsafe { &mut *(buffer.as_mut_ptr() as usize as *mut _) };

        icmp_header.type_ = icmp_data.get_type().clone().into();
        icmp_header.id = icmp_data.get_id().clone();
        icmp_header.sq = icmp_data.get_sq().to_be();

        for i in 0..message.len() {
            buffer[i + ICMP_HEADER_SIZE] = message[i]
        }

        let icmp_checksum: u16 =
            checksum(icmp_header as *const IcmpHeader as *const u8, buffer_len);

        icmp_header.check = icmp_checksum;
        match dst_ip {
            net::IpAddr::V4(dst_v4) => {
                let adapter = self.arp.get_socket().get_adapter().clone();
                let ip_packet = IpPacket::<V4>::new(&adapter);
                let payload = ip_packet.bytes(&mut self.arp, dst_v4, ICMP_PROTO as u8, &buffer)?;

                self.arp.get_socket().send_raw_packet(&payload)
            }
            net::IpAddr::V6(dst_v6) => todo!(),
        }
    }

    /// Reads icmp request
    ///
    /// # Examples
    /// ```
    /// use cursock::*;
    /// use cursock::utils::*;
    /// use std::net::Ipv4Addr;
    ///
    /// let icmp = Icmp::new("wlan0").expect("initialize error");
    /// let mut buffer = [0u8; 65535];
    ///
    /// icmp.read(&mut buffer, |_, _| true).expect("read error");
    /// ```
    pub fn read<F>(&self, buffer: &mut [u8], mut closure: F) -> io::Result<(IpData, IcmpData)>
    where
        F: FnMut(&IpData, &IcmpData) -> bool,
    {
        let eth_header: &EthHeader = unsafe { &*(buffer.as_ptr() as *const EthHeader) };
        let ip_header: &IpV4Header =
            unsafe { &*((buffer.as_ptr() as usize + ETH_HEADER_SIZE) as *const IpV4Header) };
        let icmp_header: &IcmpHeader = unsafe {
            &*((buffer.as_mut_ptr() as usize + ETH_HEADER_SIZE + IPV4_HEADER_SIZE)
                as *const IcmpHeader)
        };

        loop {
            self.arp.get_socket().read_raw_packet(buffer)?;

            if eth_header.proto != u16::from_be(IPV4_PROTO)
                || ip_header.protocol != ICMP_PROTO as u8
            {
                continue;
            }
            let message_len =
                ip_header.tot_len.to_be() as usize - (IPV4_HEADER_SIZE + ICMP_HEADER_SIZE);

            let ip_data: IpData = IpData::new(
                ip_header.tot_len,
                ip_header.ttl,
                net::IpAddr::V4(net::Ipv4Addr::from(ip_header.saddr)),
                net::IpAddr::V4(net::Ipv4Addr::from(ip_header.daddr)),
            );
            let icmp_data: IcmpData = IcmpData::new(
                IcmpType::from(icmp_header.type_),
                icmp_header.code,
                icmp_header.check,
                icmp_header.id,
                icmp_header.sq,
                buffer[ETH_HEADER_SIZE + IPV4_HEADER_SIZE + ICMP_HEADER_SIZE
                    ..ETH_HEADER_SIZE + IPV4_HEADER_SIZE + ICMP_HEADER_SIZE + message_len]
                    .to_vec(),
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
    /// let icmp = Icmp::new("wlan0").expect("initialize error");
    ///
    /// icmp.destroy()
    /// ```
    pub fn destroy(&self) {
        self.arp.destroy()
    }
}

/// struct for doing icmp requests, which needs connection, like echo
pub struct IcmpConnection<'p, 'd> {
    dst_ip: &'d net::IpAddr,
    parent: &'p mut Icmp,
    sq: u16,
    id: u16,
}

impl<'p, 'd> IcmpConnection<'p, 'd> {
    /// icmp echo request
    ///
    /// # Examples
    /// ```
    /// use cursock::*;
    /// use std::net;
    ///
    /// let icmp = Icmp::new("wlan0").expect("initialize error");
    ///
    /// let ip = net::Ipv4Addr::new(8, 8, 8, 8);
    ///
    /// let mut buffer = [0; 0xffff];
    /// let message = [0; 10];
    ///
    /// let mut connection = icmp.new_connection(&ip).expect("connection error");
    /// let (ip_data, icmp_data) = connection.echo(&message, &mut buffer).expect("echo error");
    /// ```
    pub fn echo(
        &mut self,
        message: &[u8],
        recv_buffer: &mut [u8],
    ) -> io::Result<(utils::IpData, utils::IcmpData)> {
        let data = IcmpData::new(
            IcmpType::EchoRequest,
            0,
            0,
            self.id,
            self.sq,
            message.to_vec(),
        );
        self.parent.send(&self.dst_ip, data)?;

        let result = self.parent.read(recv_buffer, |ip_data, icmp_data| {
            icmp_data.get_type().clone() == IcmpType::EchoReply
                && ip_data.get_src() == self.dst_ip
                && icmp_data.get_id() == &self.id
                && icmp_data.get_sq().to_be() == self.sq
        })?;

        self.sq += 1;

        Ok(result)
    }
}
