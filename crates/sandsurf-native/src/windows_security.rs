//! Owned, aligned Windows security identities shared by files, VM owners and sockets.
use std::io;
use std::mem::size_of;
use windows_sys::Win32::Security::Isolation::DeriveAppContainerSidFromAppContainerName;
use windows_sys::Win32::Security::{CopySid, FreeSid, GetLengthSid, PSID};

pub(crate) struct Sid(Vec<usize>);
impl Sid {
    pub(crate) fn derive(name: &str) -> io::Result<Self> {
        let name: Vec<u16> = name.encode_utf16().chain([0]).collect();
        let mut original = std::ptr::null_mut();
        // SAFETY: terminated name and writable SID output. No profile is created:
        // a default writable AppContainer home is outside the owned volume.
        let result =
            unsafe { DeriveAppContainerSidFromAppContainerName(name.as_ptr(), &mut original) };
        if result < 0 {
            return Err(io::Error::from_raw_os_error(result));
        }
        if original.is_null() {
            return Err(invalid("native AppContainer SID is absent"));
        }
        let value = Self::copy(original);
        // SAFETY: the original allocation came from AppContainer SID derivation.
        unsafe { FreeSid(original) };
        value
    }
    pub(crate) fn copy(original: PSID) -> io::Result<Self> {
        if original.is_null() {
            return Err(invalid("native SID is absent"));
        }
        // SAFETY: caller retains a successful native SID allocation.
        let bytes = unsafe { GetLengthSid(original) };
        if !(8..=68).contains(&bytes) {
            return Err(invalid("native SID exceeds bound"));
        }
        let value = Self(vec![0; (bytes as usize).div_ceil(size_of::<usize>())]);
        // SAFETY: bounded aligned destination and retained native SID.
        if unsafe { CopySid(bytes, value.raw(), original) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(value)
    }
    pub(crate) fn raw(&self) -> PSID {
        self.0.as_ptr().cast_mut().cast()
    }
    pub(crate) fn well_known(
        kind: windows_sys::Win32::Security::WELL_KNOWN_SID_TYPE,
    ) -> io::Result<Self> {
        let value = Self(vec![0; 68usize.div_ceil(size_of::<usize>())]);
        let mut bytes = 68;
        // SAFETY: aligned maximum SID storage and exact initialized size.
        if unsafe {
            windows_sys::Win32::Security::CreateWellKnownSid(
                kind,
                std::ptr::null_mut(),
                value.raw(),
                &mut bytes,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(value)
    }
    pub(crate) fn text(&self) -> io::Result<String> {
        crate::local::sid_text(self.raw())
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
