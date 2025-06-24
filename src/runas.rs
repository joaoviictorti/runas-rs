use anyhow::{bail, Result};
use core::{
    ptr,
    ffi::c_void,
    ops::BitOr,
    mem::zeroed, 
    ptr::{null, null_mut},
};

use std::{
    ffi::OsStr, 
    os::windows::ffi::OsStrExt
};

use crate::{
    sid::get_user_sid,
    acl::{Acl, Object}, 
    pipe::Pipe,
};

use windows_sys::{
    core::w, 
    Win32::Storage::FileSystem::{
        READ_CONTROL, WRITE_DAC
    }
};
use windows_sys::Win32::{
    Security::*,
    Foundation::*,
    System::{
        Threading::*,
        SystemServices::*,
        StationsAndDesktops::*,
        Environment::{
            GetEnvironmentStringsW, 
            DestroyEnvironmentBlock,
            CreateEnvironmentBlock
        }, 
    },
};

/// Represents bitwise options for running processes with specific settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct Options(pub u32);

impl Options {
    /// Option to indicate that the environment should be loaded (`/env`).
    pub const Env: Options = Options(0b00000001);

    /// Option to specify that the user profile should not be loaded (`/noprofile`).
    pub const NoProfile: Options = Options(0b00000010);

    /// Option to specify that the user profile should be loaded (`/profile`).
    pub const Profile: Options = Options(0b0000100);

    /// Option to specify that credentials should only be used for remote access (`/netonly`).
    pub const NetOnly: Options = Options(0b00001000);

    /// Checks if the current [`Options`] instance contains the specified option.
    ///
    /// # Arguments
    ///
    /// * `other` - Another `Options` instance to check against.
    ///
    /// # Returns
    ///
    /// * `true` if the current instance includes the `other` option, `false` otherwise.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let opts = Options::Env | Options::NetOnly;
    /// assert!(opts.contains(Options::Env));
    /// assert!(opts.contains(Options::NetOnly));
    /// ``` 
    fn contains(self, other: Options) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl BitOr for Options {
    type Output = Self;

    /// Combines two [`Options`] instances using a bitwise OR operation.
    ///
    /// # Arguments
    ///
    /// * `rhs` - The right-hand side `Options` instance.
    ///
    /// # Returns
    ///
    /// * A new [`Options`] instance that represents the combination of both options.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let combined = Options::Env | Options::NetOnly;
    /// assert!(combined.contains(Options::Env));
    /// assert!(combined.contains(Options::NetOnly));
    /// ```
    fn bitor(self, rhs: Self) -> Self::Output {
        Options(self.0 | rhs.0)
    }
}

/// A struct to execute processes under a different user account.
/// 
/// This struct allows running commands as another user, setting up necessary permissions, 
/// and ensuring the security context is properly configured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Runas<'a> {
    /// The username of the target account.
    username: &'a str,
    
    /// The password for the account.
    password: &'a str,
    
    /// The domain of the user (optional, defaults to an empty string).
    domain: &'a str,

    /// If true, loads the user environment.
    env: *mut c_void,

    /// Flags for logon operations (such as `/netonly`, `/profile` or `/noprofile`).
    logon_flags: u32,

    /// The type of logon operation to perform.
    logon_type: u32,

    /// Specifies the logon provider.
    provider: u32,

    /// Flags for process creation (such as creating with environment variables).
    creation_flags: u32
}

impl Default for Runas<'_> {
    /// Provides a default-initialized `Runas`.
    ///
    /// # Returns
    ///
    /// * A default-initialized `Runas`.
    fn default() -> Self {
        Self {
            username: "",
            password: "",
            domain: ".",
            env: null_mut(),
            logon_flags: 0,
            creation_flags: 0,
            logon_type: LOGON32_LOGON_INTERACTIVE,
            provider: LOGON32_PROVIDER_DEFAULT
        }
    }
}

impl<'a> Runas<'a> {
    /// Creates a new [`Runas`] instance with user credentials.
    ///
    /// # Arguments
    ///
    /// * `username` - The name of the user account.
    /// * `password` - The password associated with the account.
    /// * `domain` - (Optional) The domain of the user. Defaults to an empty string.
    ///
    /// # Returns
    ///
    /// * Returns a new [`Runas`] instance configured with the given credentials.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let runas = Runas::new("example", "example", None);
    /// ```
    pub fn new(
        username: &'a str, 
        password: &'a str, 
        domain: Option<&'a str>
    ) -> Self {
        Self {
            username,
            password,
            domain: domain.unwrap_or("."),
            ..Default::default()
        }
    }
    
    /// Sets the options for the [`Runas`] instance.
    ///
    /// This function allows the user to configure environment loading and 
    /// saving credentials using the [`Options`] bitflags.
    ///
    /// # Arguments
    ///
    /// * `flags` - A combination of [`Options`] flags.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let runas = Runas::new("example", "example", None)
    ///     .options(Options::Env | Options::Profile)?;
    /// ```
    pub fn options(mut self, flags: Options) -> Result<Self> {
        if flags.contains(Options::Profile) && flags.contains(Options::NoProfile) {
            bail!("`/profile` is not compatible with `/noprofile`");
        }

        if flags.contains(Options::Profile) && flags.contains(Options::NetOnly) {
            bail!("`/profile` is not compatible with `/netonly`");
        }

        if flags.contains(Options::Profile) {
            self.logon_flags = LOGON_WITH_PROFILE;
        } else if flags.contains(Options::NoProfile) {
            self.logon_flags &= !LOGON_WITH_PROFILE;
        }

        if flags.contains(Options::NetOnly) {
            self.logon_flags |= LOGON_NETCREDENTIALS_ONLY;
            self.logon_type = LOGON32_LOGON_NEW_CREDENTIALS;
            self.provider = LOGON32_PROVIDER_WINNT50
        }

        if flags.contains(Options::Env) {
            self.env = unsafe { GetEnvironmentStringsW().cast() };
            self.creation_flags = CREATE_UNICODE_ENVIRONMENT;
        }

        Ok(self)
    }

    /// This function logs in with the provided credentials and runs the given command.
    ///
    /// # Arguments
    ///
    /// * `command` - The path to the executable that should be run.
    ///
    /// # Returns
    ///
    /// * `Ok(String)` - Command output (if available).
    /// * `Err(anyhow::Error)` - If any Windows API call fails.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// runas.run("cmd.exe /c whoami")?;
    /// ```
    pub fn run(&mut self, command: &str) -> Result<String> {
        unsafe {
            // Configure access control for the user's window station and desktop
            let desktop = self.configure()?;
            let mut desktop_wide = desktop.as_str().to_pwstr();

            // Create a pipe for interprocess communication (to capture output / error)
            let (read, write) = Pipe::create()?;
            let mut pi = zeroed::<PROCESS_INFORMATION>();
            let si = STARTUPINFOW {
                cb: size_of::<STARTUPINFOW>() as u32,
                lpDesktop: desktop_wide.as_mut_ptr(),
                hStdOutput: write,
                hStdError: write,
                dwFlags: STARTF_USESTDHANDLES,
                ..zeroed()
            };

            // Convert username, domain, password and command to wide strings (UTF-16)
            let username = self.username.to_pwstr();
            let domain = self.domain.to_pwstr();
            let password = self.password.to_pwstr();
            let mut command = command.to_pwstr();

            match self.default_process()? {
                CreateProcessFunction::CreateProcessAsUser => {
                    // Authenticate user and obtain token
                    let mut h_token = null_mut();
                    if LogonUserW(username.as_ptr(), domain.as_ptr(), password.as_ptr(), self.logon_type, self.provider, &mut h_token) == FALSE {
                        bail!("LogonUserW Failed With Error [CreateProcessAsUser]: {}", GetLastError());
                    }

                    // Enabling the privilege
                    if !Token::enable_privilege("SeAssignPrimaryTokenPrivilege")? {
                        bail!("Error enabling privilege SeAssignPrimaryTokenPrivilege");
                    }

                    // Duplicate the token to ensure it's a primary token
                    let mut h_duptoken = null_mut();
                    if DuplicateTokenEx(h_token, TOKEN_ALL_ACCESS, null(), SecurityImpersonation, TokenPrimary, &mut h_duptoken) == FALSE {
                        bail!("DuplicateTokenEx Failed With Error [CreateProcessAsUser]: {}", GetLastError());
                    }

                    // Create a new environment block for the user represented by the duplicated token.
                    if self.env.is_null() {
                        if CreateEnvironmentBlock(&mut self.env, h_duptoken, FALSE) == FALSE {
                            bail!("CreateEnvironmentBlock Failed With Error: {}", GetLastError());
                        }
                    }

                    // Launch the new process in the user's session using the duplicated token.
                    let dir = format!("{}\\System32", std::env::var("SystemRoot")?).as_str().to_pwstr();
                    if CreateProcessAsUserW(
                        h_duptoken, 
                        null(),
                        command.as_mut_ptr(), 
                        null_mut(), 
                        null_mut(), 
                        TRUE, 
                        CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT, 
                        self.env, 
                        dir.as_ptr(), 
                        &si, 
                        &mut pi
                    ) == FALSE {
                        bail!("CreateProcessAsUserW Failed With Error: {}", GetLastError());
                    }
                },
                CreateProcessFunction::CreateProcessWithToken => {
                    // Authenticate user and obtain token
                    let mut h_token = null_mut();
                    if LogonUserW(username.as_ptr(), domain.as_ptr(), password.as_ptr(), self.logon_type, self.provider, &mut h_token) == FALSE {
                        bail!("LogonUserW Failed With Error [CreateProcessWithToken]: {}", GetLastError());
                    }

                    // Enabling the privilege
                    if !Token::enable_privilege("SeImpersonatePrivilege")? {
                        bail!("Error enabling privilege SeImpersonatePrivilege");
                    }

                    // Duplicate the token to ensure it's a primary token
                    let mut h_duptoken = null_mut();
                    if DuplicateTokenEx(h_token, TOKEN_ALL_ACCESS, null(), SecurityImpersonation, TokenPrimary, &mut h_duptoken) == FALSE {
                        bail!("DuplicateTokenEx Failed With Error [CreateProcessWithToken]: {}", GetLastError());
                    }

                    // Launch the process with the duplicated token
                    if CreateProcessWithTokenW(
                        h_duptoken, 
                        self.logon_flags,
                        null(), 
                        command.as_mut_ptr(), 
                        CREATE_NO_WINDOW | self.creation_flags, 
                        self.env, 
                        null_mut(),
                        &si,
                        &mut pi,
                    ) == FALSE {
                        bail!("CreateProcessWithTokenW Failed With Error: {}", GetLastError());
                    }
                },
                CreateProcessFunction::CreateProcessWithLogon => {
                    // Create a new process using the specified user's credential
                    if CreateProcessWithLogonW(
                        username.as_ptr(),
                        domain.as_ptr(),
                        password.as_ptr(),
                        self.logon_flags,
                        null_mut(),
                        command.as_mut_ptr(),
                        CREATE_NO_WINDOW | self.creation_flags,
                        self.env,
                        null_mut(),
                        &si,
                        &mut pi,
                    ) == FALSE {               
                        bail!("CreateProcessWithLogonW Failed With Error: {}", GetLastError());
                    }
                }
            }

            CloseHandle(write);

            // Read the output from the process and return it as a string
            Ok(Pipe::read(read))
        }
    }

    /// Configures access control for the user's window station and desktop.
    ///
    /// This function ensures that the specified user has the necessary permissions
    /// to interact with the window station and desktop.
    ///
    /// # Returns
    ///
    /// * `Ok(String)` - The configured window station name.
    /// * `Err(anyhow::Error)` - If any API call fails.
    fn configure(&self) -> Result<String> {
        let name = self.get_windows_station()?;
        let station_name = name.as_str().to_pwstr();
        unsafe {
            // Get the handle of the current process's window station
            let old_hwinsta = GetProcessWindowStation();
            
            // Open the specified window station with READ_CONTROL and WRITE_DAC permissions
            let h_winsta = OpenWindowStationW(
                station_name.as_ptr(),
                FALSE,
                READ_CONTROL | WRITE_DAC,
            );

            if h_winsta.is_null() {
                bail!("OpenWindowStationW Failed With Error: {}", GetLastError());
            }

            // Set the opened window station as the current process's window station
            SetProcessWindowStation(h_winsta);

            // Open the default desktop with the necessary permissions
            let h_desktop = OpenDesktopW(
                w!("Default"),
                0,
                FALSE,
                DESKTOP_READ_CONTROL | DESKTOP_WRITE_DAC | DESKTOP_WRITEOBJECTS | DESKTOP_READOBJECTS,
            );

            if h_desktop.is_null() {
                bail!("OpenDesktopW Failed With Error: {}", GetLastError());
            }

            // Restore the original window station to the process
            SetProcessWindowStation(old_hwinsta);
            
            // Retrieve the security identifier (SID) for the user
            let mut user_sid = get_user_sid(&self.username, &self.domain)?;

            // Add the necessary access control entries (ACEs) for the window station and desktop (If it doesn't exist)
            let mut acl_station = Acl::new(h_winsta, &mut user_sid, Object::WindowsStation);
            if !acl_station.check_permissions()? {
                acl_station.add_ace()?;
            }

            let mut acl_desktop = Acl::new(h_desktop, &mut user_sid, Object::Desktop);
            if !acl_desktop.check_permissions()? {
                acl_desktop.add_ace()?;
            }

            CloseWindowStation(h_winsta);
            CloseDesktop(h_desktop);

            Ok(format!("{name}\\Default"))
        }
    }
    
    /// Decides which process creation API should be used based on privileges and integrity.
    /// 
    /// * [`CreateProcessAsUser`] — If `SeAssignPrimaryTokenPrivilege` is present and integrity is Medium or higher
    /// * [`CreateProcessWithToken`] — If `SeImpersonatePrivilege` is present and integrity is High or higher
    /// * [`CreateProcessWithLogon`] — Default/fallback method
    ///
    /// # Returns
    ///
    /// * `Ok(CreateProcessFunction)` - Enum indicating the best available API for process creation
    /// * `Err(anyhow::Error)` - If privilege or integrity detection fails
    fn default_process(&self) -> Result<CreateProcessFunction> {
        let integrity = Token::integrity_level()?;
        let se_impersonate = Token::has_privilege("SeImpersonatePrivilege")?;
        let se_assign = Token::has_privilege("SeAssignPrimaryTokenPrivilege")?;
        
        if se_assign && matches!(integrity, "Medium" | "High" | "System") {
            Ok(CreateProcessFunction::CreateProcessAsUser)
        } else if se_impersonate && matches!(integrity, "High" | "System") {
            Ok(CreateProcessFunction::CreateProcessWithToken)
        } else {
            Ok(CreateProcessFunction::CreateProcessWithLogon)
        }
    }

    /// Retrieves the name of the current Windows station.
    ///
    /// # Returns
    ///
    /// * `Ok(String)` - The name of the current Windows station.
    /// * `Err(anyhow::Error)` - If the function fails to retrieve the station name.
    fn get_windows_station(&self) -> Result<String> {
        // Get a handle to the current process's window station
        let h_winsta = unsafe { GetProcessWindowStation() };
        if h_winsta.is_null() {
            bail!("GetProcessWindowStation Failed With Error: {}", unsafe { GetLastError() });
        }

        // Retrieve the name of the window station using GetUserObjectInformationW
        let mut buffer = vec![0u16; 256];
        let mut len = 0;
        if unsafe { 
            GetUserObjectInformationW(
                h_winsta,
                UOI_NAME,
                buffer.as_mut_ptr().cast(),
                (buffer.len() * 2) as u32,
                &mut len,
            ) 
        } == FALSE {
            bail!("GetUserObjectInformationW Failed With Error: {}", unsafe { GetLastError() });
        }

        // Convert UTF-16 buffer into a Rust `String` and return
        let len = (len / 2) as usize - 1;
        buffer.truncate(len);

        Ok(String::from_utf16_lossy(&buffer))
    }
}

/// Implements the `Drop` trait to release env when `Runas` goes out of scope.
impl Drop for Runas<'_> {
    fn drop(&mut self) {
        if !self.env.is_null() {
            unsafe { DestroyEnvironmentBlock(self.env) };
        }
    }
}

/// Defines which Windows API will be used to spawn the process.
#[derive(Debug, Clone, Copy)]
enum CreateProcessFunction {
    /// https://learn.microsoft.com/pt-br/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasusera
    CreateProcessAsUser = 0,
    
    /// https://learn.microsoft.com/pt-br/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw
    CreateProcessWithToken = 1,
    
    // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithlogonw
    CreateProcessWithLogon = 2,
}

/// Represents a simple wrapper around Token on Windows. 
pub struct Token;

impl Token {
    /// Returns the integrity level of the current process token.
    ///
    /// # Returns
    ///
    /// * `Ok(&'static str)` - A string indicating the integrity level.
    /// * `Err(anyhow::Error)` - If any token API call fails.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let level = Token::integrity_level()?;
    /// println!("Integrity level: {}", level);
    /// ```
    pub fn integrity_level() -> Result<&'static str> {
        unsafe {
            // Get the process token for the current process
            let mut h_token = null_mut();
            if OpenProcessToken(-1isize as HANDLE, TOKEN_QUERY, &mut h_token) == FALSE {
                bail!("GetProcessWindowStation Failed With Error: {}", GetLastError());
            }
    
            // Make the first call to GetTokenInformation to get the size required
            let mut len = 0;
            GetTokenInformation(h_token, TokenIntegrityLevel, null_mut(), 0, &mut len);
            if GetLastError() != ERROR_INSUFFICIENT_BUFFER  {
                bail!("GetTokenInformation Failed With Error: {}", GetLastError());
            }
    
            // Allocate memory for the TOKEN_MANDATORY_LABEL structure
            let mut buffer = vec![0u8; len as usize];
            if GetTokenInformation(h_token, TokenIntegrityLevel, buffer.as_mut_ptr().cast(), len, &mut len) == FALSE {
                bail!("GetTokenInformation [2] Failed With Error: {}", GetLastError());
            }
    
            // Retrieve the actual integrity level information
            let til = buffer.as_ptr() as *const TOKEN_MANDATORY_LABEL;
            let count = GetSidSubAuthorityCount((*til).Label.Sid);
            if count.is_null() {
                bail!("GetSidSubAuthorityCount Failed With Error: {}", GetLastError());
            }
    
            // Extract the RID from the SID, which represents the integrity level
            let ptr = GetSidSubAuthority((*til).Label.Sid, (*count - 1) as u32);
            if ptr.is_null() {
                bail!("GetSidSubAuthority Failed With Error: {}", GetLastError());
            }
            
            // Interpret the integrity level RID and print a human-readable labe
            let level = ptr::read(ptr) as i32;
            let label = match level {
                SECURITY_MANDATORY_LOW_RID => "Low",
                SECURITY_MANDATORY_MEDIUM_RID => "Medium",
                SECURITY_MANDATORY_HIGH_RID => "High",
                SECURITY_MANDATORY_SYSTEM_RID => "System",
                _ => "Unknown",
            };
    
            Ok(label)
        }
    }

    /// Checks if the current process token has a specific privilege enabled.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the privilege to check.
    ///
    /// # Returns
    ///
    /// * `Ok(true)` if the privilege is found in the token.
    /// * `Ok(false)` if the privilege is not found.
    /// * `Err(anyhow::Error)` if the token query fails.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// if Token::has_privilege("SeImpersonatePrivilege")? {
    ///     println!("Privilege is enabled!");
    /// }
    /// ```
    pub fn has_privilege(name: &str) -> Result<bool> {
        unsafe {
            // Get the process token for the current process
            let mut h_token = null_mut();
            if OpenProcessToken(-1isize as HANDLE, TOKEN_QUERY, &mut h_token) == FALSE {
                bail!("OpenProcessToken Failed With Error: {}", GetLastError());
            }

            // Make the first call to GetTokenInformation to get the size required
            let mut len = 0;
            GetTokenInformation(h_token, TokenPrivileges, null_mut(), 0, &mut len);
            if GetLastError() != ERROR_INSUFFICIENT_BUFFER {
                bail!("GetTokenInformation Failed With Error: {}", GetLastError());
            }

            // Allocate memory for the TOKEN_PRIVILEGES structure
            let mut buffer = vec![0u8; len as usize];
            if GetTokenInformation(h_token, TokenPrivileges, buffer.as_mut_ptr().cast(), len, &mut len) == FALSE {
                bail!("GetTokenInformation [2] Failed With Error: {}", GetLastError());
            }

            let header = &*(buffer.as_ptr() as *const TOKEN_PRIVILEGES);
            let privs = &header.Privileges as *const LUID_AND_ATTRIBUTES;
            for i in 0..header.PrivilegeCount {
                let luid_attr = privs.add(i as usize);
                let luid = (*luid_attr).Luid;
                
                let mut buffer = vec![0u16; 128];
                let mut len = buffer.len() as u32;

                // Lookup the string name of the privilege from its LUID.
                if LookupPrivilegeNameW(null(), &luid, buffer.as_mut_ptr(), &mut len) == FALSE {
                    continue
                }

                // Convert UTF-16 buffer into a Rust `String`
                buffer.truncate(len as usize);
                let privilege = String::from_utf16_lossy(&buffer);

                // Compare the privilege name to the target; if it matches, return true
                if privilege == name {
                    return Ok(true)
                }
            }
        }

        Ok(false)
    }

    /// Enables a specific privilege on the current process token.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// Token::enable_privilege("SeDebugPrivilege")?;
    /// ```
    pub fn enable_privilege(name: &str) -> Result<bool> {
        unsafe {
            // Get the process token for the current process
            let mut h_token = null_mut();
            if OpenProcessToken(-1isize as HANDLE, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut h_token) == FALSE {
                bail!("OpenProcessToken Failed With Error: {}", GetLastError());
            }

            // Look up the LUID for the given privilege name 
            let mut token_priv = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES { Luid: zeroed(), Attributes: SE_PRIVILEGE_ENABLED}; 1],
            };
            if LookupPrivilegeValueW(null_mut(), name.to_pwstr().as_ptr(), &mut token_priv.Privileges[0].Luid as *mut LUID) == FALSE {
                bail!("LookupPrivilegeValueW Failed With Error: {}", GetLastError());
            }

            // Apply the adjusted privileges to the token.
            if AdjustTokenPrivileges(h_token, 0, &token_priv, 0, null_mut(), null_mut()) == FALSE {
                bail!("AdjustTokenPrivileges Failed With Error: {}", GetLastError());
            }
        }

        Ok(true)
    }
}

trait PWSTR {
    /// Converts a `&str` to a null-terminated UTF-16 wide string, suitable for Windows APIs.
    fn to_pwstr(&self) -> Vec<u16>;
}

impl PWSTR for &str {
    fn to_pwstr(&self) -> Vec<u16> {
        OsStr::new(self).encode_wide().chain(std::iter::once(0)).collect()
    }
}