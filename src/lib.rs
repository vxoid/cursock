//! # Cursock
//!
//! `cursock` is a crate that designed to help with socketing.

extern crate curerr;

pub mod ccs;
pub mod utils;

mod arp;
mod socket;

pub use arp::Arp;
pub use socket::Socket;

pub use curerr::*;
use utils::*;
