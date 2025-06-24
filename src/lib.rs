#![doc = include_str!("../README.md")]
#![allow(non_upper_case_globals)]

mod acl;
mod pipe;
mod runas;
mod sid;
pub use runas::*;
