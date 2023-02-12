//! # Cursock
//!
//! `cursock` is a crate that designed to help with socketing.

extern crate curerr;

pub mod ccs;
pub mod utils;

mod arp;
mod icmp;
mod socket;

pub use arp::Arp;
pub use icmp::Icmp;
pub use socket::Socket;

pub use curerr::*;
use utils::*;
