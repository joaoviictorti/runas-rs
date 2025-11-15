use std::{ffi::CString, ptr::null_mut};
use anyhow::{Result, bail};
use windows_sys::Win32::{
    Foundation::{FALSE, GetLastError},
    Security::{LookupAccountNameA, SID_NAME_USE},
};

/// Retrieves the Security Identifier (SID) of a user account.
///
/// # Arguments
///
/// * `username` -  The name of the user.
/// * `domain` - The domain name (or `"."` for the local machine).
///
/// # Returns
///
/// Containing the SID bytes on success.
pub fn get_user_sid(username: &str, domain: &str) -> Result<Vec<u8>> {
    let full_account_name = if !domain.is_empty() && domain != "." {
        format!("{}\\{}", domain, username)
    } else {
        username.to_string()
    };

    let faqn = CString::new(full_account_name)?;
    let sid = null_mut();
    let mut cbsid = 0;
    let mut len = 0;
    let mut sid_name = SID_NAME_USE::default();

    unsafe {
        // First call to determine required SID buffer size
        LookupAccountNameA(
            null_mut(),
            faqn.as_ptr().cast(),
            sid,
            &mut cbsid,
            null_mut(),
            &mut len,
            &mut sid_name,
        );

        // Second call to actually retrieve the SID
        let mut sid = vec![0u8; cbsid as usize];
        let mut domain_buffer = vec![0u8; len as usize];
        if LookupAccountNameA(
            null_mut(),
            faqn.as_ptr().cast(),
            sid.as_mut_ptr().cast(),
            &mut cbsid,
            domain_buffer.as_mut_ptr(),
            &mut len,
            &mut sid_name,
        ) == FALSE
        {
            bail!("LookupAccountNameA Failed With Error: {}", GetLastError());
        }

        Ok(sid)
    }
}
