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
    ip: net::IpAddr,
    mac: Mac
}

impl Adapter {
    /// initializes struct using interface id
    /// 
    /// # Examples
    /// ```
    /// let interface = Adapter::get_by_id(10, IpVer::V4).expect("error finding adapter");
    /// ```
    #[cfg(target_os = "windows")]
    pub fn get_by_id(id: u32, ver: IpVer) -> io::Result<Self> {
        let (ipv4, ipv6, mac, guid, name) = get_interface_info(id)?;

        let result = ver.prefered(ipv4, ipv6)
            .map_or(Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("{} has no either v4 or v6 addresses", name)
            )), |ip| Ok(Self { name, ip, mac, guid }));

        result
    }

    /// initializes struct using interface name
    /// 
    /// # Examples
    /// ```
    /// let adapter = Adapter::get_by_ifname("wlan0", IpVer::V4).expect("error finding adapter");
    /// 
    /// ```
    #[cfg(target_os = "linux")]
    pub fn get_by_ifname(if_name: &str, ver: IpVer) -> io::Result<Self> {
        let cstr_if_name = CString::new(if_name)
            .map_err(|err| io::Error::new(
                io::ErrorKind::InvalidInput,
                err.to_string()
            ))?;

        let (index, ipv4, ipv6, mac) = get_interface_info(cstr_if_name)?;

        let result = ver.prefered(ipv4, ipv6)
            .map_or(Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("{} has no either v4 or v6 addresses", if_name)
            )), |ip| Ok(Self { name: if_name.to_string(), ip, mac, index }));

        result
    }

    getters!(
        pub get_ip(ip) -> net::IpAddr;
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
        format!("{} ({} - {})", self.name, self.mac, self.ip)
    }
}

impl Clone for Adapter {
    #[cfg(target_os = "windows")]
    fn clone(&self) -> Self {
        Self { name: self.name.clone(), ip: self.ip.clone(), mac: self.mac.clone(), guid: self.guid.clone() }
    }

    #[cfg(target_os = "linux")]
    fn clone(&self) -> Self {
        Self { name: self.name.clone(), ip: self.ip.clone(), mac: self.mac.clone(), index: self.index.clone() }
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    fn clone(&self) -> Self {
        Self { name: self.name.clone(), ip: self.ip.clone(), mac: self.mac.clone() }
    }
}

#[cfg(target_os = "linux")]
fn get_interface_info(
    if_name: CString
) -> io::Result<(i32, Option<net::Ipv4Addr>, Option<net::Ipv6Addr>, Mac)> {
    let socketv4 = unsafe {
        ccs::socket(ccs::AF_INET, ccs::SOCK_DGRAM, 0)
    };
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

    let ipv4 = get_if_ipv4(socketv4, &mut if_request)
        .map_or(None, |ipv4| Some(ipv4));

    let socketv6 = unsafe {
        ccs::socket(ccs::AF_INET6, ccs::SOCK_DGRAM, 0)
    };
    if socketv6 < 0 {
        return Err(io::Error::last_os_error());
    }

    let ipv6 = get_if_ipv6(socketv6, &mut if_request)
        .map_or(None, |ipv6| Some(ipv6));

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
    let err: i32;

    err = unsafe { ccs::ioctl(socket, ccs::SIOCGIFADDR, ifr) };

    if err == -1 {
        return Err(io::Error::last_os_error());
    }

    let addr: *const ccs::sockaddr_in =
        unsafe { &(*ifr).ifr_ifru.ifru_addr as *const ccs::sockaddr } as *const ccs::sockaddr_in;
    let mut ip: [u8; IPV4_LEN] = [0; IPV4_LEN];

    memcpy(
        ip.as_mut_ptr(),
        unsafe { &(*addr).sin_addr.s_addr },
        std::mem::size_of::<[u8; IPV4_LEN]>(),
    );

    Ok(net::Ipv4Addr::from(ip))
}

#[cfg(target_os = "linux")]
fn get_if_ipv6(socket: i32, ifr: *mut ccs::ifreq) -> io::Result<net::Ipv6Addr> {
    let err: i32;

    err = unsafe { ccs::ioctl(socket, ccs::SIOCGIFADDR, ifr) };

    if err == -1 {
        return Err(io::Error::last_os_error());
    }

    let addr =
        unsafe { &(*ifr).ifr_ifru.ifru_addr as *const ccs::sockaddr } as *const ccs::sockaddr_in6;
    let mut ip: [u8; IPV6_LEN] = [0; IPV6_LEN];

    memcpy(
        ip.as_mut_ptr(),
        unsafe { &(*addr).sin6_addr },
        IPV6_LEN,
    );

    Ok(net::Ipv6Addr::from(ip))
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
        std::mem::size_of::<[u8; MAC_LEN]>(),
    );

    Ok(Mac::from(mac))
}

#[cfg(target_os = "windows")]
fn get_interface_info(if_id: u32) -> io::Result<(Option<net::Ipv4Addr>, Option<net::Ipv6Addr>, Mac, String, String)> {
    let mut out_buf_len: u32 = 0;

    unsafe {
        ccs::GetAdaptersAddresses(
            0,
            ccs::GAA_FLAG_INCLUDE_PREFIX as u32,
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
            ccs::GAA_FLAG_INCLUDE_PREFIX as u32,
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
        let cur_addr_r = unsafe {
            &mut *cur_addr
        };

        if cur_addr_r.if_index == if_id {
            let mut unicast_addr = cur_addr_r.first_unicast_address;

            let mut ipv4 = None;
            let mut ipv6 = None;
            let mut mac = [0; MAC_LEN];
            memcpy(mac.as_mut_ptr(), cur_addr_r.physical_address.as_ptr(), MAC_LEN);

            let mac = Mac::from(mac);
            
            let guid = str_from_cstr(cur_addr_r.adapter_name as *const i8);
            let slice = unsafe { std::slice::from_raw_parts(cur_addr_r.friendly_name, {
                let mut len = 0;
                while *cur_addr_r.friendly_name.add(len) != 0 {
                    len += 1;
                }
                len
            }) };
            let name = slice
                .into_iter()
                .map(|u| std::char::from_u32(*u as u32).unwrap())
                .collect::<String>();

            while !unicast_addr.is_null() {
                let unicast_addr_r = unsafe {
                    &mut *unicast_addr
                };

                let sockaddr = unsafe {
                    &*(unicast_addr_r.address.lp_sockaddr as *const ccs::sockaddr)
                };

                match sockaddr.sa_family as usize {
                    ccs::AF_INET => {
                        if let Some(_) = ipv4 {
                            unicast_addr = unicast_addr_r.next;
                            continue
                        }

                        let sockaddr = unsafe {
                            &*(unicast_addr_r.address.lp_sockaddr as *const ccs::sockaddr_in)
                        };
                        let mut ip = [0u8; IPV4_LEN];
                        
                        memcpy(ip.as_mut_ptr(), &sockaddr.sin_addr, IPV4_LEN);

                        ipv4 = Some(net::Ipv4Addr::from(ip))
                    },
                    ccs::AF_INET6 => {
                        if let Some(_) = ipv6 {
                            unicast_addr = unicast_addr_r.next;
                            continue
                        }

                        let sockaddr = unsafe {
                            &*(unicast_addr_r.address.lp_sockaddr as *const ccs::sockaddr_in6)
                        };
                        let mut ip = [0u8; IPV6_LEN];
                        
                        memcpy(ip.as_mut_ptr(), &sockaddr.sin6_addr, IPV6_LEN);

                        ipv6 = Some(net::Ipv6Addr::from(ip))
                    },
                    _ => {}
                }

                unicast_addr = unicast_addr_r.next
            }

            output = Some((ipv4, ipv6, mac, guid, name))
        }

        cur_addr = cur_addr_r.next
    }

    let output = match output {
        Some(output) => output,
        None => return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("there isn\'t any adapter with id {}", if_id)
        )),
    };

    Ok(output)
}