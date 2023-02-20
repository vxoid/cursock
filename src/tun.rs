use crate::*;
#[cfg(any(target_os = "linux"))]
use std::ffi::CString;

pub struct Tun {
    #[cfg(target_os = "linux")]
    fd: i32,
    #[cfg(target_os = "windows")]
    session: ccs::WintunSessionHandle
}

impl Tun {
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

    pub fn read(&self, buffer: &mut [u8], debug: bool) -> Result<(), CursedErrorHandle> {
        #[cfg(target_os = "linux")]
        {
            self.read_linux(buffer, debug)
        }

        #[cfg(not(any(target_os = "linux")))]
        {
            let _ = buffer;
            let _ = debug;
            
            Err(CursedErrorHandle::new(
                CursedError::OS,
                format!("{} is not supported yet!", std::env::consts::OS),
            ))
        } 
    }

    #[cfg(target_os = "linux")]
    fn open_linux(interface: &str, debug: bool) -> Result<Self, CursedErrorHandle> {
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

        let interface: CString = match CString::new(interface) {
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

        memcpy(ifr.ifr_name.as_mut_ptr(), interface.as_ptr(), interface.as_bytes_with_nul().len());

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

        Ok(Self { fd })
    }

    #[cfg(target_os = "windows")]
    fn open_windows(interface: &str, debug: bool) -> Result<Self, CursedErrorHandle> {
        let guid: ccs::GUID = ccs::_GUID { data1: 0xdeadbabe, data2: 0xcafe, data3: 0xbeef, data4: [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef] };
        let name: Vec<u16> = "Demo".encode_utf16().collect();
        let type_: Vec<u16> = "Example".encode_utf16().collect();

        let adapter: ccs::WintunAdapterHandle = unsafe {
            ccs::WintunCreateAdapter(name.as_ptr(), type_.as_ptr(), &guid)
        };

        let session: ccs::WintunSessionHandle = unsafe {
            ccs::WintunStartSession(adapter, 0x400000)
        };

        Ok(Self { session })
    }
    
    #[cfg(target_os = "linux")]
    fn read_linux(&self, buffer: &mut [u8], debug: bool) -> Result<(), CursedErrorHandle> {
        let result: isize = unsafe {
            ccs::read(self.fd, buffer.as_mut_ptr() as *mut std::os::raw::c_void, buffer.len())
        };

        if debug {
            println!("{} bytes has been readen", result);
        }
        
        Ok(())
    }
}