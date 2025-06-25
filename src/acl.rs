use std::{ffi::c_void, mem::zeroed, ptr::null_mut};
use anyhow::{Result, bail};
use windows_sys::Win32::{
    Foundation::*,
    Security::*,
    Storage::FileSystem::*,
    System::StationsAndDesktops::*,
    UI::WindowsAndMessaging::*,
};

/// Represents the type of Windows object to modify when adding an Access Control Entry (ACE).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Object {
    /// Represents a Windows Station object.
    WindowsStation,

    /// Represents a Desktop object.
    Desktop,
}

/// Required standard rights for system objects.
const STANDARD_RIGHTS_REQUIRED: u32 = 0x000F0000;

/// Full access permissions for a Windows Desktop object.
const DESKTOP_ALL: u32 = DESKTOP_READOBJECTS
    | DESKTOP_CREATEWINDOW
    | DESKTOP_CREATEMENU
    | DESKTOP_HOOKCONTROL
    | DESKTOP_JOURNALRECORD
    | DESKTOP_JOURNALPLAYBACK
    | DESKTOP_ENUMERATE
    | DESKTOP_WRITEOBJECTS
    | DESKTOP_SWITCHDESKTOP
    | STANDARD_RIGHTS_REQUIRED;

/// Full access permissions for a Windows Station object.
const WINSTA_ALL: u32 = (WINSTA_ACCESSCLIPBOARD
    | WINSTA_ACCESSGLOBALATOMS
    | WINSTA_CREATEDESKTOP
    | WINSTA_ENUMDESKTOPS
    | WINSTA_ENUMERATE
    | WINSTA_EXITWINDOWS
    | WINSTA_READATTRIBUTES
    | WINSTA_READSCREEN
    | WINSTA_WRITEATTRIBUTES
    | DELETE as i32
    | READ_CONTROL as i32
    | WRITE_DAC as i32
    | WRITE_OWNER as i32) as u32;

/// A helper structure to manage Access Control Entries (ACEs) on Windows Station or Desktop objects.
pub struct Acl<'a> {
    /// A handle to the Windows Station or Desktop.
    h_object: *mut c_void,

    /// The security identifier (SID) of the user.
    sid: &'a mut Vec<u8>,

    /// Specifies whether modifying a `WindowsStation` or `Desktop`.
    object: Object,
}

impl<'a> Acl<'a> {
    /// Creates a new [`Acl`] instance.
    ///
    /// # Arguments
    ///
    /// * `h_object` - A handle to the Windows Station or Desktop.
    /// * `sid` - The security identifier (SID) of the user.
    /// * `object` - Specifies whether modifying a `WindowsStation` or `Desktop`.
    ///
    /// # Return
    ///
    /// * Returning a new [`Acl`] instance.
    pub fn new(h_object: *mut c_void, sid: &'a mut Vec<u8>, object: Object) -> Self {
        Self { h_object, sid, object }
    }

    /// Adds an Access Control Entry (ACE) to a specified Windows Station or Desktop.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the operation is successful.
    /// * `Err(anyhow::Error)` - If any Windows API call fails.
    pub fn add_ace(&mut self) -> Result<()> {
        unsafe {
            // Retrieve the required buffer size for the security descriptor
            let mut len = 0;
            let requested = DACL_SECURITY_INFORMATION;
            GetUserObjectSecurity(self.h_object, &requested, null_mut(), 0, &mut len);

            // Allocate the buffer for the security descriptor
            let mut psid = vec![0u8; len as usize];
            if GetUserObjectSecurity(
                self.h_object, 
                &requested, 
                psid.as_mut_ptr().cast(), 
                len, 
                &mut len
            ) == FALSE 
            {
                bail!("Failed to get user object security (error {})", GetLastError());
            }

            // Retrieve the DACL from the security descriptor
            let mut dacl = zeroed();
            let mut dacl_exist = 0;
            let mut dacl_present = 0;
            if GetSecurityDescriptorDacl(
                psid.as_mut_ptr().cast(), 
                &mut dacl_present, 
                &mut dacl, 
                &mut dacl_exist
            ) == FALSE 
            {
                bail!("Failed to get security descriptor DACL (error {})", GetLastError());
            }

            // Obtain ACL size information
            let mut acl_info = zeroed::<ACL_SIZE_INFORMATION>();
            if GetAclInformation(
                dacl,
                (&mut acl_info as *mut ACL_SIZE_INFORMATION).cast::<c_void>(),
                size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            ) == FALSE
            {
                bail!("Failed to get ACL information (error {})", GetLastError());
            }

            // Initialize a new security descriptor
            let mut security_descriptor = zeroed::<SECURITY_DESCRIPTOR>();
            if InitializeSecurityDescriptor((&mut security_descriptor as *mut SECURITY_DESCRIPTOR).cast::<c_void>(), 1) == FALSE {
                bail!("Failed to initialize security descriptor (error {})", GetLastError());
            }

            // Calculate the size needed for the new ACE and updated ACL
            let new_size_ace = size_of::<ACCESS_ALLOWED_ACE>() + self.sid.len() - size_of::<u32>();
            let new_size_acl = if acl_info.AclBytesInUse == 0 {
                (size_of::<ACL>() + (new_size_ace * 2)) as u32
            } else {
                acl_info.AclBytesInUse + (new_size_ace * 2) as u32
            };

            // Allocate and initialize a new DACL
            let mut new_dacl_buffer = vec![0u8; new_size_acl as usize];
            let new_dacl = new_dacl_buffer.as_mut_ptr() as *mut ACL;
            if InitializeAcl(new_dacl, new_size_acl, ACL_REVISION) == FALSE {
                bail!("Failed to initialize ACL (error {})", GetLastError());
            }

            // Copy existing ACEs from the original DACL to the new DACL, if present
            if dacl_present != 0 {
                for i in 0..acl_info.AceCount {
                    let mut ace = null_mut();
                    if GetAce(dacl, i, &mut ace) == FALSE {
                        bail!("Failed to get ACE (error {})", GetLastError());
                    }

                    // Add the ACE to the new DACL at the end of the list (0xffffffff indicates the end position)
                    let ace_header = ace as *mut ACE_HEADER;
                    if AddAce(new_dacl, ACL_REVISION, u32::MAX, ace, (*ace_header).AceSize as u32) == FALSE {
                        bail!("Failed to add existing ACE (error {})", GetLastError());
                    }
                }
            }

            // Add new ACE based on the object type
            match self.object {
                Object::WindowsStation => {
                    // Adds an ACE to the DACL with generic permissions and inheritance
                    if AddAccessAllowedAceEx(
                        new_dacl,
                        ACL_REVISION,
                        CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE | OBJECT_INHERIT_ACE,
                        GENERIC_ALL,
                        self.sid.as_mut_ptr().cast(),
                    ) == FALSE
                    {
                        bail!("Failed to add ACE to Windows Station (error {})", GetLastError());
                    }

                    // Adds another ACE to DACL with no inheritance propagation and full window station access
                    if AddAccessAllowedAceEx(
                        new_dacl, 
                        ACL_REVISION, 
                        NO_PROPAGATE_INHERIT_ACE, 
                        WINSTA_ALL, 
                        self.sid.as_mut_ptr().cast()
                    ) == FALSE 
                    {
                        bail!("Failed to add non-propagating ACE to Windows Station (error {})", GetLastError());
                    }
                }
                Object::Desktop => {
                    if AddAccessAllowedAce(new_dacl, ACL_REVISION, DESKTOP_ALL, self.sid.as_mut_ptr().cast()) == FALSE {
                        bail!("Failed to add ACE to Desktop (error {})", GetLastError());
                    }
                }
            }

            // Sets the DACL in the security descriptor
            if SetSecurityDescriptorDacl(
                (&mut security_descriptor as *mut SECURITY_DESCRIPTOR).cast::<c_void>(), 
                TRUE, 
                new_dacl, 
                FALSE
            ) == FALSE 
            {
                bail!("Failed to set security descriptor DACL (error {})", GetLastError());
            }

            // Applies the security descriptor to the window station or desktop
            if SetUserObjectSecurity(
                self.h_object, 
                &requested, 
                (&mut security_descriptor as *mut SECURITY_DESCRIPTOR).cast::<c_void>()
            ) == FALSE 
            {
                bail!("Failed to set user object security (error {})", GetLastError());
            }

            Ok(())
        }
    }

    /// Verifies whether the necessary ACEs are already present in the security descriptor
    /// of the specified Windows Station or Desktop.
    ///
    /// # Return
    ///
    /// * `Ok(true)` if all required ACEs are found with correct permissions and flags.
    /// * `Ok(false)` if any expected ACE is missing or incorrectly configured.
    /// * `Err(anyhow::Error)` if any Windows API call fails during permission inspection.
    pub fn check_permissions(&mut self) -> Result<bool> {
        unsafe {
            // Retrieve the required buffer size for the security descriptor
            let mut len = 0;
            let requested = DACL_SECURITY_INFORMATION;
            GetUserObjectSecurity(self.h_object, &requested, null_mut(), 0, &mut len);

            // Allocate the buffer for the security descriptor
            let mut psid = vec![0u8; len as usize];
            if GetUserObjectSecurity(
                self.h_object, 
                &requested, 
                psid.as_mut_ptr().cast(), 
                len, 
                &mut len
            ) == FALSE 
            {
                bail!("Failed to get user object security (error {})", GetLastError());
            }

            // Retrieve the DACL from the security descriptor
            let mut dacl = zeroed();
            let mut dacl_exist = 0;
            let mut dacl_present = 0;
            if GetSecurityDescriptorDacl(
                psid.as_mut_ptr().cast(), 
                &mut dacl_present, 
                &mut dacl, 
                &mut dacl_exist
            ) == FALSE 
            {
                bail!("Failed to get security descriptor DACL (error {})", GetLastError());
            }

            // Obtain ACL size information
            let mut acl_info = zeroed::<ACL_SIZE_INFORMATION>();
            if GetAclInformation(
                dacl,
                (&mut acl_info as *mut ACL_SIZE_INFORMATION).cast::<c_void>(),
                size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            ) == FALSE
            {
                bail!("Failed to get ACL information (error {})", GetLastError());
            }

            // Flags to track if expected ACEs exist
            let mut ace_win_inherit = false;
            let mut ace_win_nonprop = false;
            let mut ace_desktop = false;

            // Loop through ACEs and match against expected permissions
            if dacl_present != 0 {
                for i in 0..acl_info.AceCount {
                    let mut ace = null_mut();
                    if GetAce(dacl, i, &mut ace) == FALSE {
                        bail!("Failed to get ACE (error {})", GetLastError());
                    }

                    // Only process ACCESS_ALLOWED_ACE_TYPE entries
                    let ace_header = ace as *mut ACE_HEADER;
                    if (*ace_header).AceType == 0 {
                        let ace = ace as *mut ACCESS_ALLOWED_ACE;
                        let ace_sid = (&mut (*ace).SidStart as *mut u32).cast::<c_void>();

                        // Check if the ACE belongs to our SID
                        if EqualSid(ace_sid, self.sid.as_mut_ptr().cast()) != FALSE {
                            let mask = (*ace).Mask;
                            let flags = (*ace).Header.AceFlags as u32;

                            // Match ACE mask and flags to expected permissions
                            match self.object {
                                Object::WindowsStation => {
                                    if mask == GENERIC_ALL && flags & 
                                        (CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE | OBJECT_INHERIT_ACE) != 0 
                                    {
                                        ace_win_inherit = true;
                                    }

                                    if mask == WINSTA_ALL && flags & NO_PROPAGATE_INHERIT_ACE != 0 {
                                        ace_win_nonprop = true;
                                    }
                                }
                                Object::Desktop => {
                                    if mask == DESKTOP_ALL {
                                        ace_desktop = true;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            Ok(match self.object {
                Object::WindowsStation => ace_win_inherit && ace_win_nonprop,
                Object::Desktop => ace_desktop,
            })
        }
    }
}
