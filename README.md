# runas-rs 🦀

![Rust](https://img.shields.io/badge/made%20with-Rust-red)
![crate](https://img.shields.io/crates/v/runas-rs.svg)
![docs](https://docs.rs/runas-rs/badge.svg)
![Forks](https://img.shields.io/github/forks/joaoviictorti/runas-rs)
![Stars](https://img.shields.io/github/stars/joaoviictorti/runas-rs)
![License](https://img.shields.io/github/license/joaoviictorti/runas-rs)

An offensive version of `runas` in Rust with extra features

This crate provides both a CLI and a Rust crate for spawning processes under different Windows user accounts, with support for privileges, secure token manipulation, profile/environment loading, and more.

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
    - [Creating and Running a Process as Another User](#creating-and-running-a-process-as-another-user)
    - [Checking Privileges and Token Integrity](#checking-privileges-and-token-integrity)
    - [Available Options](#available-options)
- [CLI](#cli)
    - [CLI Help](#cli-help)
- [Contributing to runas-rs](#contributing-to-runas-rs)
- [References](#references)
- [License](#license)

## Installation

Add `runas-rs` to your project by updating your `Cargo.toml`:

```powershell
cargo add runas-rs
```

## Usage

`runas-rs` offers fine-grained control over user impersonation and process spawning on Windows. It allows you to run commands under different user credentials, while dynamically selecting the most appropriate Windows API for process creation based on current privileges and token integrity.

### Creating and Running a Process as Another User

This crate chooses among `CreateProcessAsUserW`, `CreateProcessWithTokenW`, or `CreateProcessWithLogonW` depending on the privileges and integrity level available to the current process.

| API                        | Required Privilege                   | Required Integrity Level | 
|----------------------------|--------------------------------------|--------------------------|
| `CreateProcessAsUserW`     | `SeAssignPrimaryTokenPrivilege`      | Medium or higher         |
| `CreateProcessWithTokenW`  | `SeImpersonatePrivilege`             | High or System           |
| `CreateProcessWithLogonW`  | _None_                               | Any                      |

Example:

```rs
use runas_rs::{Runas, Options};
use anyhow::Result;

fn main() -> Result<()> {
    let output = Runas::new("username", "password", Some("DOMAIN"))
        .options(Options::Env | Options::Profile)?
        .run("cmd.exe /c whoami")?;

    println!("Output: {}", output);
    Ok(())
}
```

### Checking Privileges and Token Integrity

You can inspect and manipulate the current process token to determine what kind of impersonation is possible.

```rs
use runas_rs::Token;
use anyhow::Result;

fn main() -> Result<()> {
    // Check the current integrity level
    let level = Token::integrity_level()?;
    println!("Integrity Level: {}", level);

    // Check if privileges are available
    if Token::has_privilege("SeAssignPrimaryTokenPrivilege")? {
        println!("Privilege SeAssignPrimaryTokenPrivilege is available.");
    }

    if Token::has_privilege("SeImpersonatePrivilege")? {
        println!("Privilege SeImpersonatePrivilege is available.");
    }

    // Try enabling a privilege manually
    if Token::enable_privilege("SeImpersonatePrivilege")? {
        println!("Privilege SeImpersonatePrivilege successfully enabled.");
    } else {
        println!("Failed to enable SeImpersonatePrivilege.");
    }

    Ok(())
}
```

### Available Options

You can combine the following options using | (bitflags):

| Option               | Description                                                   |
|----------------------|---------------------------------------------------------------|
| `Options::Env`       | Use the current user's environment block.                     |
| `Options::Profile`   | Load the full user profile.                                   |
| `Options::NoProfile` | Do not load the user profile.                                 |
| `Options::NetOnly`   | Use credentials for remote access only (e.g., network shares).|

## CLI

The CLI binary lets you run processes as other users directly from the command line, similar to runas.exe.

Example:
```cmd
C:\> runas.exe -u joao -p joao -c "whoami" --profile
desktop-34dc0j2\joao
```

### CLI Help

```
Usage: runas.exe [OPTIONS] -u <USERNAME> -p <PASSWORD> --command <COMMAND> <--profile|--noprofile|--netonly>

Options:
  -u <USERNAME>            Username to run the command
  -p <PASSWORD>            Password for the user
  -d, --domain <DOMAIN>    Domain of the user (optional)
  -c, --command <COMMAND>  Command to execute as the specified user
  -e                       Use the environment of the current user
      --profile            Load user profile
      --noprofile          Do not load user profile
      --netonly            Use credentials for remote access only
  -h, --help               Print help
  -V, --version            Print version
```

## References

I want to express my gratitude to these projects that inspired me to create `runas-rs` and contribute with some features:

* [Pavel - CreateProcessAsUser vs. CreateProcessWithTokenW](https://www.youtube.com/watch?v=y42BsQJhd5w&t=816s)
* [Pavel - Window Stations and Desktops](https://scorpiosoftware.net/2023/06/20/window-stations-and-desktops/)
* [RunasCs](https://github.com/antonioCoco/RunasCs)

## License

This project is licensed under the [**GPL-3.0 license**](/LICENSE). See the LICENSE file for details.