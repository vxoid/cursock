//! # Arpv
//!
//! `arpv` is a crate that designed to help with socketing.

extern crate curerr;

pub mod utils;
pub mod ccs;

mod arp;
mod socket;

pub use arp::Arp;
pub use socket::Socket;

pub use curerr::*;
use utils::*;