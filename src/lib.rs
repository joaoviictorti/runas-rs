//! # runas-rs 🦀
//!
//! An offensive-oriented reimplementation of Windows `runas`, written in Rust.
//!
//! This crate provides both:
//! - A **library** for spawning processes as another user (with full control over tokens and privileges).
//! - A **CLI tool** (`runas.exe`) as a drop-in alternative to the Windows `runas` command, but with more features.
//!
//! ## Features
//! - Spawn processes as other users using **explicit credentials**.
//! - Selects the best Windows API automatically:  
//!   `CreateProcessAsUserW`, `CreateProcessWithTokenW`, or `CreateProcessWithLogonW`.
//! - Inspect and manipulate process tokens (privileges, integrity level).
//! - Support for loading full user profiles, custom environment blocks, or `netonly` logons.
//!
//! ## Example
//! ```no_run
//! use runas_rs::{Runas, Options};
//! use anyhow::Result;
//!
//! fn main() -> Result<()> {
//!     let output = Runas::new("user", "password", Some("DOMAIN"))
//!         .options(Options::Env | Options::Profile)?
//!         .run("cmd.exe /c whoami")?;
//!
//!     println!("Output: {}", output);
//!     Ok(())
//! }
//! ```
//!
//! For the full README, examples and CLI usage, check the [repository](https://github.com/joaoviictorti/runas-rs).
//!
//! ## License
//! Licensed under GPL-3.0. See [LICENSE](https://github.com/joaoviictorti/runas-rs/blob/main/LICENSE).

#![allow(clippy::upper_case_acronyms)]
#![allow(non_upper_case_globals)]

mod acl;
mod pipe;
mod sid;
mod runas;

pub use runas::*;
