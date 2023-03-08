//! # Cursock
//!
//! `cursock` is a crate that designed to help with socketing.

extern crate curerr;

pub mod ccs;
pub mod utils;

use std::net::{
    IpAddr,
    Ipv4Addr,
    Ipv6Addr,
};

mod arp;
mod tun;
mod icmp;
mod socket;

pub use tun::Tun;
pub use arp::Arp;
pub use icmp::Icmp;
pub use socket::Socket;

pub use curuam::*;
pub use curerr::*;
use curmacro::*;
use utils::*;
