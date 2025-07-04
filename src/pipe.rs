use std::ptr::null_mut;
use windows_sys::Win32::Foundation::FALSE;
use windows_sys::Win32::{
    Foundation::HANDLE,
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::ReadFile,
    System::Pipes::CreatePipe,
};

/// Represents a simple wrapper around anonymous pipes on Windows.
pub struct Pipe;

impl Pipe {
    /// Creates an anonymous pipe and returns both read and write handles.
    ///
    /// # Returns
    ///
    /// * Returns a tuple `(HANDLE, HANDLE)`, where:
    /// - The first element is the read handle.
    /// - The second element is the write handle.
    pub fn create() -> anyhow::Result<(HANDLE, HANDLE)> {
        unsafe {
            let mut h_read = null_mut();
            let mut h_write = null_mut();
            let sa = SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                bInheritHandle: 1,
                lpSecurityDescriptor: null_mut(),
            };

            if CreatePipe(&mut h_read, &mut h_write, &sa, 0) == 0 {
                return Err(anyhow::anyhow!("Error creating the pipe"));
            }

            Ok((h_read, h_write))
        }
    }

    /// Reads data from an anonymous pipe until there's nothing left to read.
    ///
    /// This function reads from the pipe's read handle and returns the data as a `String`.
    ///
    /// # Arguments
    ///
    /// * `h_read` - The read handle of the pipe.
    ///
    /// # Returns
    ///
    /// * Returns a `String` containing the data read from the pipe.
    pub fn read(h_read: HANDLE) -> String {
        let mut buffer = [0u8; 1 << 12];
        let mut bytes_read = 0;
        let mut output = String::new();

        unsafe {
            while ReadFile(
                h_read, 
                buffer.as_mut_ptr(), 
                buffer.len() as u32, 
                &mut bytes_read, 
                null_mut()
            ) != FALSE 
            {
                output.push_str(&String::from_utf8_lossy(&buffer[..bytes_read as usize]));
            }
        }

        output
    }
}
