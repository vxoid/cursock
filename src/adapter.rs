#[cfg(target_os = "linux")]
use std::ffi::CString;
use std::io;
use std::net;

use crate::*;

pub struct Adapter {
    #[cfg(target_os = "windows")]
    guid: String,
    #[cfg(target_os = "linux")]
    index: i32,
    name: String,
    ipv4: Option<net::Ipv4Addr>,
    ipv6: Option<net::Ipv6Addr>,
    gateway: Option<net::Ipv4Addr>,
    mac: Mac,
}

impl Adapter {
    /// initializes struct using interface id
    ///
    /// # Examples
    /// ```
    /// let interface = Adapter::get_by_id(10, IpVer::V4).expect("error finding adapter");
    /// ```
    #[cfg(target_os = "windows")]
    pub fn get_by_id(id: u32) -> io::Result<Self> {
        let (ipv4, ipv6, gateway, mac, guid, name) = get_interface_info(id)?;

        Ok(Self {
            name,
            ipv4,
            ipv6,
            gateway,
            mac,
            guid,
        })
    }

    /// initializes struct using interface name
    ///
    /// # Examples
    /// ```
    /// let adapter = Adapter::get_by_ifname("wlan0", IpVer::V4).expect("error finding adapter");
    ///
    /// ```
    #[cfg(target_os = "linux")]
    pub fn get_by_ifname(if_name: &str) -> io::Result<Self> {
        let cstr_if_name = CString::new(if_name)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;

        let (index, ipv4, ipv6, mac) = get_interface_info(cstr_if_name)?;
        let gateway = get_file_default_gateway();

        Ok(Self {
            index,
            name: if_name.to_string(),
            ipv4,
            ipv6,
            gateway,
            mac,
        })
    }

    getters!(
        pub get_ipv4(ipv4) -> Option<net::Ipv4Addr>;
        pub get_ipv6(ipv6) -> Option<net::Ipv6Addr>;
        pub get_gateway(gateway) -> Option<net::Ipv4Addr>;
        pub get_mac(mac) -> Mac;
        pub get_name(name) -> str;
    );

    #[cfg(target_os = "windows")]
    getters!(
        pub get_guid(guid) -> str;
    );

    #[cfg(target_os = "linux")]
    getters!(
        pub get_index(index) -> i32;
    );
}

impl ToString for Adapter {
    fn to_string(&self) -> String {
        let ip = self
            .ipv4
            .map(net::IpAddr::V4)
            .or_else(|| self.ipv6.map(net::IpAddr::V6));

        format!(
            "{} ({} - {:?} - {:?})",
            self.name, self.mac, ip, self.gateway
        )
    }
}

impl Clone for Adapter {
    #[cfg(target_os = "windows")]
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            ipv4: self.ipv4.clone(),
            ipv6: self.ipv6.clone(),
            gateway: self.gateway.clone(),
            mac: self.mac.clone(),
            guid: self.guid.clone(),
        }
    }

    #[cfg(target_os = "linux")]
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            ipv4: self.ipv4.clone(),
            ipv6: self.ipv6.clone(),
            gateway: self.gateway.clone(),
            mac: self.mac.clone(),
            index: self.index.clone(),
        }
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            ipv4: self.ipv4.clone(),
            ipv6: self.ipv6.clone(),
            gateway: self.gateway.clone(),
            mac: self.mac.clone(),
        }
    }
}

#[cfg(target_os = "linux")]
fn get_interface_info(
    if_name: CString,
) -> io::Result<(i32, Option<net::Ipv4Addr>, Option<net::Ipv6Addr>, Mac)> {
    let socketv4 = unsafe { ccs::socket(ccs::AF_INET, ccs::SOCK_DGRAM, 0) };
    if socketv4 < 0 {
        return Err(io::Error::last_os_error());
    }

    let ifru: ccs::ifreq_data = ccs::ifreq_data { ifru_ifindex: 0 };
    let mut if_request: ccs::ifreq = ccs::ifreq {
        ifr_name: [0; 16],
        ifr_ifru: ifru,
    };

    memcpy(
        if_request.ifr_name.as_mut_ptr(),
        if_name.as_ptr(),
        if_name.as_bytes_with_nul().len(),
    );

    let ifindex: i32 = get_if_index(socketv4, &mut if_request)?;

    let ipv4 = get_if_ipv4(socketv4, &mut if_request).map_or(None, |ipv4| Some(ipv4));

    let socketv6 = unsafe { ccs::socket(ccs::AF_INET6, ccs::SOCK_DGRAM, 0) };
    if socketv6 < 0 {
        return Err(io::Error::last_os_error());
    }

    let ipv6 = get_if_ipv6(socketv6, &mut if_request).map_or(None, |ipv6| Some(ipv6));

    let mac: Mac = get_if_mac(socketv4, &mut if_request)?;

    Ok((ifindex, ipv4, ipv6, mac))
}

#[cfg(target_os = "linux")]
fn get_if_index(socket: i32, ifr: *mut ccs::ifreq) -> io::Result<i32> {
    let err: i32 = unsafe { ccs::ioctl(socket, ccs::SIOCGIFINDEX, ifr) };
    if err == -1 {
        return Err(io::Error::last_os_error());
    }

    let index: i32 = unsafe { (*ifr).ifr_ifru.ifru_ifindex.clone() };

    Ok(index)
}

#[cfg(target_os = "linux")]
fn get_if_ipv4(socket: i32, ifr: *mut ccs::ifreq) -> io::Result<net::Ipv4Addr> {
    use std::mem;

    let err: i32;

    err = unsafe { ccs::ioctl(socket, ccs::SIOCGIFADDR, ifr) };

    if err == -1 {
        return Err(io::Error::last_os_error());
    }

    let addr: *const ccs::sockaddr_in =
        unsafe { &(*ifr).ifr_ifru.ifru_addr as *const ccs::sockaddr } as *const ccs::sockaddr_in;

    Ok(net::Ipv4Addr::from(unsafe {
        mem::transmute::<_, [u8; IPV4_LEN]>((*addr).sin_addr.s_addr)
    }))
}

#[cfg(target_os = "linux")]
fn get_if_ipv6(socket: i32, ifr: *mut ccs::ifreq) -> io::Result<net::Ipv6Addr> {
    let err: i32;

    err = unsafe { ccs::ioctl(socket, ccs::SIOCGIFADDR, ifr) };

    if err == -1 {
        return Err(io::Error::last_os_error());
    }

    let addr = unsafe {
        (*(&(*ifr).ifr_ifru.ifru_addr as *const _ as *const ccs::sockaddr_in6))
            .sin6_addr
            .s6_addr
    };

    Ok(net::Ipv6Addr::from(addr))
}

#[cfg(target_os = "linux")]
fn get_if_mac(socket: i32, ifr: *mut ccs::ifreq) -> io::Result<Mac> {
    let err: i32 = unsafe { ccs::ioctl(socket, ccs::SIOCGIFHWADDR, ifr) };

    if err == -1 {
        return Err(io::Error::last_os_error());
    }

    let sa_data: [i8; 14] = unsafe { (*ifr).ifr_ifru.ifru_hwaddr.sa_data };

    let mut mac: [u8; MAC_LEN] = [0; MAC_LEN];

    memcpy(
        mac.as_mut_ptr(),
        sa_data.as_ptr(),
        MAC_LEN,
    );

    Ok(Mac::from(mac))
}

#[cfg(target_os = "linux")]
fn get_file_default_gateway() -> Option<net::Ipv4Addr> {
    use std::mem;
    use std::{fs, io::BufRead};

    let file = fs::File::open("/proc/net/route").ok()?;
    let reader = io::BufReader::new(file);

    for line in reader.lines() {
        if let Ok(line) = line {
            let mut fields = line.split('\t');
            let interface = fields.next();
            let destination = fields.next();
            let gateway = fields.next();

            if let (Some(_), Some(destination), Some(gateway)) = (interface, destination, gateway) {
                if destination == "00000000" {
                    let gateway_ip = u32::from_str_radix(gateway, 16).ok()?;

                    return Some(net::Ipv4Addr::from(net::Ipv4Addr::from(unsafe {
                        mem::transmute::<_, [u8; IPV4_LEN]>(gateway_ip)
                    })));
                }
            }
        }
    }

    None
}

#[cfg(target_os = "windows")]
fn get_interface_info(
    if_id: u32,
) -> io::Result<(
    Option<net::Ipv4Addr>,
    Option<net::Ipv6Addr>,
    Option<net::Ipv4Addr>,
    Mac,
    String,
    String,
)> {
    use crate::ccs::AF_INET;
    use std::mem;

    let mut out_buf_len: u32 = 0;
    let flags = ccs::GAA_FLAG_INCLUDE_GATEWAYS;

    unsafe {
        ccs::GetAdaptersAddresses(
            ccs::AF_UNSPEC as u32,
            flags as u32,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut out_buf_len,
        )
    };

    let buffer_size = out_buf_len;
    let mut buffer: Vec<u8> = vec![0; buffer_size as usize];
    let addresses = buffer.as_mut_ptr() as *mut ccs::IP_ADAPTER_ADDRESSES;

    let result = unsafe {
        ccs::GetAdaptersAddresses(
            ccs::AF_UNSPEC as u32,
            flags as u32,
            std::ptr::null_mut(),
            addresses,
            &mut out_buf_len,
        )
    };

    if result != 0 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionReset,
            format!("unknown error occurred with {} error code, while running GetAdaptersAddresses ex call", result)
        ));
    }

    let mut output = None;

    let mut cur_addr = addresses;
    while !cur_addr.is_null() {
        let cur_addr_r = unsafe { &mut *cur_addr };

        if cur_addr_r.if_index == if_id {
            let mut ipv4 = None;
            let mut ipv6 = None;
            let mut gateway_ip = None;
            let mut mac = [0; MAC_LEN];
            memcpy(
                mac.as_mut_ptr(),
                cur_addr_r.physical_address.as_ptr(),
                MAC_LEN,
            );

            let mac = Mac::from(mac);

            let guid = str_from_cstr(cur_addr_r.adapter_name as *const i8);
            let slice = unsafe {
                std::slice::from_raw_parts(cur_addr_r.friendly_name, {
                    let mut len = 0;
                    while *cur_addr_r.friendly_name.add(len) != 0 {
                        len += 1;
                    }
                    len
                })
            };
            let name = slice
                .into_iter()
                .map(|u| std::char::from_u32(*u as u32).unwrap())
                .collect::<String>();

            let mut gateway = cur_addr_r.first_gateway_address;
            while !gateway.is_null() {
                let r_gateway = unsafe { &mut *gateway };

                let sockaddr =
                    unsafe { &*(r_gateway.address.lp_sockaddr as *const ccs::sockaddr_in) };

                if sockaddr.sin_family == AF_INET as i16 {
                    gateway_ip = Some(net::Ipv4Addr::from(unsafe {
                        mem::transmute::<_, [u8; IPV4_LEN]>(sockaddr.sin_addr.s_addr)
                    }));
                    break;
                }

                gateway = r_gateway.next;
            }

            let mut unicast_addr = cur_addr_r.first_unicast_address;
            while !unicast_addr.is_null() {
                let unicast_addr_r = unsafe { &mut *unicast_addr };

                let sockaddr =
                    unsafe { &*(unicast_addr_r.address.lp_sockaddr as *const ccs::sockaddr) };

                match sockaddr.sa_family as usize {
                    ccs::AF_INET => {
                        if let Some(_) = ipv4 {
                            unicast_addr = unicast_addr_r.next;
                            continue;
                        }

                        let sockaddr = unsafe {
                            &*(unicast_addr_r.address.lp_sockaddr as *const ccs::sockaddr_in)
                        };

                        ipv4 = Some(net::Ipv4Addr::from(unsafe { mem::transmute::<_, [u8; IPV4_LEN]>(sockaddr.sin_addr.s_addr) }))
                    }
                    ccs::AF_INET6 => {
                        if let Some(_) = ipv6 {
                            unicast_addr = unicast_addr_r.next;
                            continue;
                        }

                        let sockaddr = unsafe {
                            &*(unicast_addr_r.address.lp_sockaddr as *const ccs::sockaddr_in6)
                        };

                        ipv6 = Some(net::Ipv6Addr::from(unsafe { sockaddr.sin6_addr.s6_addr }))
                    }
                    _ => {}
                }

                unicast_addr = unicast_addr_r.next
            }

            output = Some((ipv4, ipv6, gateway_ip, mac, guid, name))
        }

        cur_addr = cur_addr_r.next
    }

    let output = match output {
        Some(output) => output,
        None => {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("there isn\'t any adapter with id {}", if_id),
            ))
        }
    };

    Ok(output)
}
