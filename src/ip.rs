use std::io;
use std::marker;
use std::net;

use crate::checksum;
use crate::Adapter;
use crate::Arp;
use crate::EthHeader;
use crate::IpV4Header;
use crate::ETH_HEADER_SIZE;
use crate::IPV4_HEADER_SIZE;
use crate::IPV4_PROTO;

pub struct V4;
pub struct V6;

pub struct IpPacket<'a, Version = V4> {
    adapter: &'a Adapter,
    version: marker::PhantomData<Version>,
}

impl<'a, T> IpPacket<'a, T> {
    pub fn new(adapter: &'a Adapter) -> Self {
        Self {
            adapter,
            version: marker::PhantomData,
        }
    }
}

impl<'a> IpPacket<'a, V4> {
    pub fn bytes(
        self,
        arp: &mut Arp,
        dst_ip: &net::Ipv4Addr,
        protocol: u8,
        payload: &[u8],
    ) -> io::Result<Vec<u8>> {
        let src_ip = self.adapter.get_ipv4().ok_or(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "To send ipv4 packets you need to have ipv4 source address ({})",
                self.adapter.to_string()
            ),
        ))?;

        let mut buffer = vec![0; ETH_HEADER_SIZE + IPV4_HEADER_SIZE + payload.len()];

        let eth_header: &mut EthHeader = unsafe { &mut *(buffer.as_mut_ptr() as *mut EthHeader) };
        let ip_header: &mut IpV4Header =
            unsafe { &mut *((buffer.as_mut_ptr() as usize + ETH_HEADER_SIZE) as *mut IpV4Header) };

        let gateway;
        let eth_ip = match dst_ip.is_private() {
            true => dst_ip,
            false => {
                gateway = self.adapter.get_gateway().ok_or(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "To send ipv4 packets you need to have ipv4 gateway ({})",
                        self.adapter.to_string()
                    ),
                ))?;
                &gateway
            }
        };

        let response = arp.who_has(eth_ip)?;

        eth_header.source = self.adapter.get_mac().clone().into();
        eth_header.dest = response.get_src_mac().clone().into();
        eth_header.proto = u16::from_be(IPV4_PROTO);

        ip_header.verihl = (4 << 4) + 5; // 4 - ip version - 5 header len (20)
        ip_header.tot_len = u16::from_be((IPV4_HEADER_SIZE + payload.len()) as u16);
        ip_header.ttl = 128;
        ip_header.protocol = protocol;
        ip_header.saddr = src_ip.octets();
        ip_header.daddr = dst_ip.octets();

        let ip_checksum: u16 = checksum(ip_header as *const _ as *const _, IPV4_HEADER_SIZE);

        ip_header.check = ip_checksum;

        for i in 0..payload.len() {
            buffer[ETH_HEADER_SIZE + IPV4_HEADER_SIZE + i] = payload[i]
        }

        Ok(buffer)
    }
}

// impl IpPacket<V6> {
//   pub fn bytes(payload: &[u8]) -> Vec<u8> {

//   }
// }
