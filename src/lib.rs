#![doc = include_str!("../README.md")]
#![allow(clippy::upper_case_acronyms)]
#![allow(non_upper_case_globals)]

mod acl;
mod pipe;
mod runas;
mod sid;
pub use runas::*;
