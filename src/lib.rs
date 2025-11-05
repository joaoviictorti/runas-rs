// Copyright (c) 2025 joaoviictorti
// Licensed under the GNU General Public License v3.0 (GPL-3.0).
// See the LICENSE file in the project root for full license details.

#![doc = include_str!("../README.md")]
#![allow(clippy::upper_case_acronyms)]
#![allow(non_upper_case_globals)]

mod acl;
mod pipe;
mod sid;
mod runas;

pub use runas::*;
