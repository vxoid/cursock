use crate::*;
use std::time::Duration;

pub struct Icmp {
   socket: Socket 
}

impl Icmp {
    pub fn new(interface: &str, debug: bool) -> Result<Self, CursedErrorHandle> {
        let socket: Socket = match Socket::new(interface, debug) {
            Ok(socket) => socket,
            Err(err) => return Err(err),
        };

        Ok(Self { socket })
    }

    pub fn echo(&self, dst_ip: &Ipv4, gateway_mac: &Mac, message: &[u8], debug: bool) -> Result<(), CursedErrorHandle> {
        let buffer_len: usize = ETH_HEADER_SIZE+IP_HEADER_SIZE+ICMP_HEADER_SIZE+message.len();
        let mut buffer: Vec<u8> = vec![0; ETH_HEADER_SIZE+IP_HEADER_SIZE+ICMP_HEADER_SIZE+message.len()];

        let eth_header: &mut EthHeader = unsafe {
            &mut *(buffer.as_mut_ptr() as *mut EthHeader)
        };
        let ip_header: &mut IpHeader = unsafe {
            &mut *((buffer.as_mut_ptr() as usize + ETH_HEADER_SIZE) as *mut IpHeader)
        };
        let icmp_header: &mut IcmpHeader = unsafe {
            &mut *((buffer.as_mut_ptr() as usize + ETH_HEADER_SIZE + IP_HEADER_SIZE) as *mut IcmpHeader)
        };

        eth_header.source = self.socket.get_src_mac().to();
        eth_header.dest = gateway_mac.to();
        eth_header.proto = ccs::htons(IP_PROTO);

        ip_header.verihl = (4 << 4) + 5; // 4 - ip version - 5 header len (20)
        ip_header.tot_len = ccs::htons((IP_HEADER_SIZE+ICMP_HEADER_SIZE+message.len()) as u16);
        ip_header.ttl = 128;
        ip_header.protocol = ICMP_PROTO as u8;
        ip_header.saddr = self.socket.get_src_ip().to();
        ip_header.daddr = dst_ip.to();

        icmp_header.type_ = ICMP_ECHO_REQUEST;
        icmp_header.id = 0x0001;
        icmp_header.sq = 9;
        
        let message_start: usize = ETH_HEADER_SIZE+IP_HEADER_SIZE+ICMP_HEADER_SIZE;
        for i in message_start..buffer_len {
            buffer[i] = message[i-message_start].clone()
        }

        let icmp_checksum: u16 = Self::checksum(
            icmp_header as *const IcmpHeader as *const u8,
            buffer_len - (ETH_HEADER_SIZE + IP_HEADER_SIZE)
        );

        let ip_checksum: u16 = Self::checksum(
            ip_header as *const IpHeader as *const u8,
            IP_HEADER_SIZE
        );
        ip_header.check = ip_checksum;
        icmp_header.check = icmp_checksum;

        if debug {
            print!("Buffer: [ ");
            for byte in &buffer {
                print!("{:X} ", byte)
            }
            println!("]")
        }

        self.socket.send_raw_packet(&buffer, debug)
    }

    pub fn read(&self, buffer: &mut [u8], debug: bool) -> Result<(IpData, IcmpData), CursedErrorHandle> {
        let eth_header: &EthHeader = unsafe {
            &*(buffer.as_ptr() as *const EthHeader)
        };
        let ip_header: &IpHeader = unsafe {
            &*((buffer.as_ptr() as usize + ETH_HEADER_SIZE) as *const IpHeader)
        };
        let icmp_header: &IcmpHeader = unsafe {
            &*((buffer.as_mut_ptr() as usize + ETH_HEADER_SIZE + IP_HEADER_SIZE) as *const IcmpHeader)
        };
        
        loop {
            if let Err(err) = self.socket.read_raw_packet(buffer, debug) {
                return Err(err);
            }
        
            if eth_header.proto != ccs::htons(IP_PROTO) || ip_header.protocol != ICMP_PROTO as u8 {
                continue
            }

            let ip_data: IpData = IpData::new(
                ip_header.tot_len,
                ip_header.ttl,
                Handle::from(ip_header.saddr),
                Handle::from(ip_header.daddr)
            );
            let icmp_data: IcmpData = IcmpData::new(
                Handle::from(icmp_header.type_),
                icmp_header.code,
                icmp_header.check,
                buffer[ETH_HEADER_SIZE+IP_HEADER_SIZE+ICMP_HEADER_SIZE..].to_vec()
            );

            return Ok((ip_data, icmp_data));
        }
    }

    pub fn read_timeout(&self, buffer: &mut [u8], debug: bool, timeout: Duration) -> Result<(IpData, IcmpData), CursedErrorHandle> {
        match Self::read_with_timeout(Wrapper::new(self), Wrapper::new(buffer), debug, timeout) {
            Some(result) => result,
            None => return Err(
                CursedErrorHandle::new(CursedError::TimeOut, String::from("icmp read timed out!"))
            ),
        }
    }

    timeout!{
        read_with_timeout(
            icmp: Wrapper<Self> => Wrapper::reference,
            buffer: Wrapper<[u8]> => Wrapper::mut_reference,  
            debug: bool
        ) -> Result<(IpData, IcmpData), CursedErrorHandle>,
        Self::read
    }

    pub fn destroy(&self) {
        self.socket.destroy()
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
}