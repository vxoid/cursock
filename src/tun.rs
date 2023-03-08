use crate::*;
#[cfg(any(target_os = "linux"))]
use std::ffi::CString;

pub struct Tun {
    #[cfg(target_os = "linux")]
    fd: i32,
    #[cfg(target_os = "linux")]
    interface: String,
    #[cfg(target_os = "windows")]
    index: u32,
    #[cfg(target_os = "windows")]
    adapter: ccs::WintunAdapterHandle,
    #[cfg(target_os = "windows")]
    session: ccs::WintunSessionHandle
}

impl Tun {
    pub fn create(interface: &str, debug: bool) -> Result<Self, CursedErrorHandle> {
        #[cfg(target_os = "linux")]
        {
            Self::create_linux(interface, debug)
        }
        #[cfg(target_os = "windows")]
        {
            Self::create_windows(interface, debug)
        }
        

        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            let _ = interface;
            let _ = debug;
            
            Err(CursedErrorHandle::new(
                CursedError::OS,
                format!("{} is not supported yet!", std::env::consts::OS),
            ))
        }
    }

    pub fn open(interface: &str, debug: bool) -> Result<Self, CursedErrorHandle> {
        #[cfg(target_os = "linux")]
        {
            Self::open_linux(interface, debug)
        }
        #[cfg(target_os = "windows")]
        {
            Self::open_windows(interface, debug)
        }
        

        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            let _ = interface;
            let _ = debug;
            
            Err(CursedErrorHandle::new(
                CursedError::OS,
                format!("{} is not supported yet!", std::env::consts::OS),
            ))
        }
    }

    pub fn setup(&self, setup: SetupTypes) -> Result<(), CursedErrorHandle> {
        match setup {
            SetupTypes::RouteAll(routes) => self.route_all(routes),
            SetupTypes::Separated => self.separated_network(),
        }       
    }

    pub fn write(&self, buffer: &[u8], debug: bool) -> Result<(), CursedErrorHandle> {
        #[cfg(target_os = "linux")]
        {
            self.write_linux(buffer, debug)
        }
        #[cfg(target_os = "windows")]
        {
            self.write_windows(buffer, debug)
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            let _ = buffer;
            let _ = debug;
            
            Err(CursedErrorHandle::new(
                CursedError::OS,
                format!("{} is not supported yet!", std::env::consts::OS),
            ))
        }
    }

    pub fn read(&self, buffer: &mut [u8], debug: bool) -> Result<usize, CursedErrorHandle> {
        #[cfg(target_os = "linux")]
        {
            self.read_linux(buffer, debug)
        }
        #[cfg(target_os = "windows")]
        {
            self.read_windows(buffer, debug)
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            let _ = buffer;
            let _ = debug;
            
            Err(CursedErrorHandle::new(
                CursedError::OS,
                format!("{} is not supported yet!", std::env::consts::OS),
            ))
        }
    }

    fn destroy(&self) {
        #[cfg(target_os = "linux")]
        {
            self.destroy_linux()
        }
        #[cfg(target_os = "windows")]
        {
            self.destroy_windows()
        }
    }

    #[cfg(target_os = "linux")]
    fn open_linux(interface: &str, debug: bool) -> Result<Self, CursedErrorHandle> {
        let _ = get_interface_info(interface, debug)?;
        
        const TUN_PATH: &'static str = "/dev/net/tun";

        let path: CString = match CString::new(TUN_PATH) {
            Ok(path) => path,
            Err(err) => {
                return Err(CursedErrorHandle::new(
                    CursedError::Parse,
                    format!(
                        "{} is not valid c string can\'t convert it due to {}",
                        TUN_PATH,
                        err.to_string()
                    ),
                ))
            }
        };

        let fd: i32 = unsafe {
            ccs::open(path.as_ptr() as *const i8, ccs::O_RDWR)
        };

        if fd < 0 {
            if debug {
                unsafe { ccs::perror(EMPTY_ARRAY.as_ptr()) }
            }

            return Err(CursedErrorHandle::new(CursedError::Sockets, format!("Can\'t open {} file", TUN_PATH)))
        }

        let cinterface: CString = match CString::new(interface) {
            Ok(interface) => interface,
            Err(err) => {
                return Err(CursedErrorHandle::new(
                    CursedError::Parse,
                    format!(
                        "{} is not valid c string can\'t convert it due to {}",
                        interface,
                        err.to_string()
                    ),
                ))
            }
        };

        let ifru: ccs::ifreq_data = ccs::ifreq_data { ifru_ifindex: 0 };

        let mut ifr: ccs::ifreq = ccs::ifreq { ifr_name: [0; 16], ifr_ifru: ifru };

        memcpy(ifr.ifr_name.as_mut_ptr(), cinterface.as_ptr(), cinterface.as_bytes_with_nul().len());

        ifr.ifr_ifru.ifru_flags = ccs::IFF_TUN as i16;

        let err: i32 = unsafe {
            ccs::ioctl(fd, ccs::TUNSETIFF as u64, &mut ifr as *mut ccs::ifreq as *mut std::os::raw::c_void)
        };

        if err < 0 {
            if debug {
                unsafe { ccs::perror(EMPTY_ARRAY.as_ptr()) }
            }

            return Err(CursedErrorHandle::new(CursedError::Sockets, "Can\'t open tun".to_string()))
        }

        Ok(Self { fd, interface: interface.to_string() })
    }

    #[cfg(target_os = "windows")]
    fn open_windows(interface: &str, debug: bool) -> Result<Self, CursedErrorHandle> {
        if debug {
            unsafe { ccs::WintunSetLogger(Some(logger)) };
        }

        let mut name: Vec<u16> = interface.encode_utf16().collect();
        name.push(0);

        let adapter: ccs::WintunAdapterHandle = unsafe {
            ccs::WintunOpenAdapter(name.as_ptr())
        };
        if adapter as usize == 0 {
            if debug {
                log()
            }

            return Err(CursedErrorHandle::new(CursedError::Sockets, String::from("Can\'t open adapter")));
        }

        let session: ccs::WintunSessionHandle = unsafe {
            ccs::WintunStartSession(adapter, 0x400000)
        };
        if session as usize == 0 {
            if debug {
                log()
            }

            return Err(CursedErrorHandle::new(CursedError::Sockets, String::from("Can\'t start session")));
        }

        let index: u32 = unsafe {
            ccs::WintunGetAdapterIndex(adapter)
        };

        Ok(Self { adapter, session, index })
    }
    
    #[cfg(target_os = "linux")]
    fn create_linux(interface: &str, debug: bool) -> Result<Self, CursedErrorHandle> {
        let ip_addr: Ipv4 = Handle::from([107, 0, 0, 0]);

        let interface_create_query: String = format!("ip tuntap add mode tun dev \"{}\"", interface);
        let addr_add_query: String = format!("ip addr add \"{}\"/1 dev \"{}\"", ip_addr, interface);
        let set_up_query: String = format!("ip link set dev \"{}\" up", interface);

        const QUERIES_SIZE: usize = 3;
        let queries: [&[&str]; QUERIES_SIZE] = [
            &["-c", &interface_create_query],
            &["-c", &addr_add_query],
            &["-c", &set_up_query]
        ];

        run_queries(&queries, "sh")?;

        Self::open(interface, debug)
    }

    #[cfg(target_os = "windows")]
    fn create_windows(interface: &str, debug: bool) -> Result<Self, CursedErrorHandle> {
        if debug {
            unsafe { ccs::WintunSetLogger(Some(logger)) };
        }
        
        let guid: u128 = random_in_range(0, u128::MAX).expect("Can\'t generated random guid");

        let guid: ccs::GUID = unsafe { std::mem::transmute(guid) };
        if debug {
            println!("{} is adapter's guid", guid)
        }

        let mut name: Vec<u16> = interface.encode_utf16().collect();
        let mut type_: Vec<u16> = "Wintun".encode_utf16().collect();
        name.push(0);
        type_.push(0);

        let adapter: ccs::WintunAdapterHandle = unsafe {
            ccs::WintunCreateAdapter(name.as_ptr(), type_.as_ptr(), &guid)
        };
        if adapter as usize == 0 {
            if debug {
                log()
            }

            return Err(CursedErrorHandle::new(CursedError::Sockets, String::from("Can\'t create adapter")));
        }

        let session: ccs::WintunSessionHandle = unsafe {
            ccs::WintunStartSession(adapter, 0x4000000)
        };
        if session as usize == 0 {
            if debug {
                log()
            }

            return Err(CursedErrorHandle::new(CursedError::Sockets, String::from("Can\'t start session")));
        }
        let guid: String = format!("{}", guid);
        let (_, _, _, index) = get_interface_by_guid(&guid)?;

        let ip_addr: Ipv4 = Handle::from([107, 0, 0, 0]);
        let addr_add_query: String = format!("netsh interface ip set address \"{}\" static \"{}\" 0.0.0.0", interface, ip_addr);

        const QUERIES_SIZE: usize = 1;
        let queries: [&[&str]; QUERIES_SIZE] = [
            &["/C", &addr_add_query]
        ];

        run_queries(&queries, "cmd")?;

        Ok(Self { adapter, session, index })
    }

    #[cfg(target_os = "linux")]
    fn read_linux(&self, buffer: &mut [u8], debug: bool) -> Result<usize, CursedErrorHandle> {
        let result: isize = unsafe {
            ccs::read(self.fd, buffer.as_mut_ptr() as *mut std::os::raw::c_void, buffer.len())
        };
        buffer.rotate_left(4);

        if debug {
            println!("{} bytes has been read", result);
        }
        
        Ok(result as usize)
    }

    #[cfg(target_os = "windows")]
    fn read_windows(&self, buffer: &mut [u8], debug: bool) -> Result<usize, CursedErrorHandle> {
        let mut size: u32 = 0;

        let packet: *mut u8 = unsafe {
            ccs::WintunReceivePacket(self.session, &mut size) 
        };
        if packet as usize == 0 {
            return Err(
                CursedErrorHandle::new(CursedError::NotEnought, String::from("no packets has been read"))
            );            
        }

        if debug {
            println!("{} has been read", size)
        }
        memcpy(buffer.as_mut_ptr(), packet, buffer.len());
        
        unsafe { ccs::WintunReleaseReceivePacket(self.session, packet) }

        Ok(size as usize)
    }

    #[cfg(target_os = "linux")]
    fn write_linux(&self, buffer: &[u8], debug: bool) -> Result<(), CursedErrorHandle> {
        let result: isize = unsafe {
            ccs::write(self.fd, buffer.as_ptr() as *const std::os::raw::c_void, buffer.len())
        };

        if debug {
            println!("{} bytes has been read", result)
        }

        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn write_windows(&self, buffer: &[u8], _: bool) -> Result<(), CursedErrorHandle> {
        let packet: *mut u8 = unsafe {
            ccs::WintunAllocateSendPacket(self.session, buffer.len() as u32)
        };
        if packet as usize == 0 {
            return Err(
                CursedErrorHandle::new(CursedError::NotEnought, String::from("can\'t allocate packet"))
            );
        }

        memcpy(packet, buffer.as_ptr(), buffer.len());

        unsafe {
            ccs::WintunSendPacket(self.session, packet)
        };
        
        Ok(())
    }

    fn separated_network(&self) -> Result<(), CursedErrorHandle> {
        // No need to setup
        
        Ok(())
    }

    fn route_all(&self, routes: &[(&Ipv4Addr, &str)]) -> Result<(), CursedErrorHandle> {
        #[cfg(target_os = "linux")]
        {
            self.route_all_linux(routes)
        }
        #[cfg(target_os = "windows")]
        {
            self.route_all_windows(routes)
        }
        

        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            let _ = routes;
            
            Err(CursedErrorHandle::new(
                CursedError::OS,
                format!("{} is not supported yet!", std::env::consts::OS),
            ))
        }
    }

    #[cfg(target_os = "linux")]
    fn route_all_linux(&self, routes: &[(&Ipv4Addr, &str)]) -> Result<(), CursedErrorHandle> {
        let route_add_128_query: String = format!("ip route add 128/1 dev \"{}\"", self.interface);
        let route_add_0_query: String = format!("ip route add 0/1 dev \"{}\"", self.interface);
        
        let sysctl_query: String = "sysctl -w net.ipv4.ip_forward=1".to_string();
        let postrouting_query: String = format!("iptables -t nat -A POSTROUTING -o \"{}\" -j MASQUERADE", self.interface);
        let forwarding_query: String = format!("iptables -I FORWARD 1 -i \"{}\" -m state --state RELATED,ESTABLISHED -j ACCEPT", self.interface);
        let accept_forwarding_query: String = format!("iptables -I FORWARD 1 -o \"{}\" -j ACCEPT", self.interface);

        const QUERIES_SIZE: usize = 6;
        let queries: [&[&str]; QUERIES_SIZE] = [
            &["-c", &route_add_128_query],
            &["-c", &route_add_0_query],
            &["-c", &sysctl_query],
            &["-c", &postrouting_query],
            &["-c", &forwarding_query],
            &["-c", &accept_forwarding_query]
        ];

        run_queries(&queries, "sh")?;

        for route in routes {
            let route_query: String = format!("-c ip route add \"{}\"/32 dev \"{}\"", route.0, route.1);
            if let Err(err) = std::process::Command::new("sh").arg(route_query).output() {
                return Err(
                    CursedErrorHandle::new(
                        CursedError::Sockets,
                        format!("can\'t create tun device due to \"{}\"", err.to_string())
                    )
                );
            }
        }

        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn route_all_windows(&self, routes: &[(&Ipv4Addr, &str)]) -> Result<(), CursedErrorHandle> {
        let route_query: String = format!("route add 0.0.0.0 MASK 0.0.0.0 0.0.0.0 IF {} METRIC 3", self.index); 

        const QUERIES_SIZE: usize = 1;
        let queries: [&[&str]; QUERIES_SIZE] = [
            &["/C", &route_query]
        ];

        run_queries(&queries, "cmd")?;

        for route in routes {
            let index: u32 = match route.1.parse() {
                Ok(index) => index,
                Err(err) => return Err(
                    CursedErrorHandle::new(
                        CursedError::Parse,
                        format!("can\'t parse {} as interface index due to \"{}\"", self.index, err.to_string()),
                    )
                ),
            };

            let route_add_query: String = format!("/C route add \"{}\" MASK 255.255.255.255 0.0.0.0 IF {} METRIC 3", route.0, index);
            if let Err(err) = std::process::Command::new("cmd").arg(route_add_query).output() {
                return Err(
                    CursedErrorHandle::new(
                        CursedError::Sockets,
                        format!("can\'t create tun device due to \"{}\"", err.to_string())
                    )
                );
            }
        }

        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn destroy_windows(&self) {
        unsafe { ccs::WintunEndSession(self.session) };
        unsafe { ccs::WintunCloseAdapter(self.adapter) };
    }

    #[cfg(target_os = "linux")]
    fn destroy_linux(&self) {
        let set_tun_down: String = format!("ip link set dev \"{}\" down", self.interface);

        let _ = run_queries(&[&["-c", &set_tun_down]], "sh");
    }
}

impl Drop for Tun {
    fn drop(&mut self) {
        self.destroy()
    }
}

unsafe impl Send for Tun {}
unsafe impl Sync for Tun {}

#[cfg(target_os = "windows")]
fn log() {
    let error: u32 = unsafe {
        ccs::GetLastError()
    };

    let system: *mut u16 = ccs::null_mut();

    unsafe {
        ccs::FormatMessageW(
            ccs::FORMAT_MESSAGE_FROM_SYSTEM | ccs::FORMAT_MESSAGE_ALLOCATE_BUFFER |
            ccs::FORMAT_MESSAGE_MAX_WIDTH_MASK,
            ccs::null(),
            error,
            (((0x01 as u16) << 10) | (0x00 as u16)) as u32,
            system,
            0,
            ccs::null_mut()
        );
    };
    if system as usize == 0 {
        return;
    }

    unsafe { logger(ccs::WINTUN_LOG_ERR, 0, system) }
}

#[cfg(target_os = "windows")]
unsafe extern "C" fn logger(level: i32, _: u64, line: *const u16) {
    let message: String = str_from_cutf16(line);

    let severity: &str = match level {
        ccs::WINTUN_LOG_ERR => "ERR",
        ccs::WINTUN_LOG_INFO => "INFO",
        ccs::WINTUN_LOG_WARN => "WARN",
        _ => "UNKNOWN"
    };

    println!("[{}] {}", severity, message)
}