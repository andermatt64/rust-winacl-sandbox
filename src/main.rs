#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]

extern crate winapi;
extern crate kernel32;
extern crate field_offset;
extern crate libc;
extern crate widestring;

mod secapi;

use widestring::WideString;
use secapi::{PACE_HEADER, ACCESS_ALLOWED_ACE, ACCESS_DENIED_ACE};
use winapi::{PSECURITY_DESCRIPTOR, PACL, DACL_SECURITY_INFORMATION, PSID};
use winapi::{DWORD, LPVOID, BOOL, LPWSTR, HLOCAL};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;
use std::iter::once;
use std::process;

#[allow(unused_imports)]
use field_offset::*;

struct AccessControlEntry {
    entryType: u8,
    flags: u8,
    mask: u32,
    size: u16,
    sid: String,
}

fn sid_to_string(pSid: PSID) -> Result<String, DWORD> {
    let mut rawStringSid: LPWSTR = 0 as LPWSTR;

    if unsafe { secapi::ConvertSidToStringSidW(pSid, &mut rawStringSid) } == 0 ||
       rawStringSid == (0 as LPWSTR) {
        return Err(unsafe { kernel32::GetLastError() });
    }

    let rawStringSidLen = unsafe { libc::wcslen(rawStringSid) };
    let out = unsafe { WideString::from_ptr(rawStringSid, rawStringSidLen) };

    unsafe { kernel32::LocalFree(rawStringSid as HLOCAL) };

    Ok(out.to_string_lossy())
}

fn get_dacl(path: &str) -> Result<(Vec<u8>, PACL), DWORD> {
    let wPath: Vec<u16> = OsStr::new(path).encode_wide().chain(once(0)).collect();
    let mut bufSize: DWORD = 0;
    let mut status = unsafe {
        secapi::GetFileSecurityW(wPath.as_ptr(),
                                 DACL_SECURITY_INFORMATION,
                                 null_mut(),
                                 0,
                                 &mut bufSize)
    };
    if status != 0 {
        return Err(unsafe { kernel32::GetLastError() });
    }

    let mut securityDesc: Vec<u8> = Vec::with_capacity(bufSize as usize);
    status = unsafe {
        secapi::GetFileSecurityW(wPath.as_ptr(),
                                 DACL_SECURITY_INFORMATION,
                                 securityDesc.as_mut_ptr() as LPVOID,
                                 bufSize,
                                 &mut bufSize)
    };

    if status == 0 {
        return Err(unsafe { kernel32::GetLastError() });
    }

    let mut pDacl: PACL = 0 as PACL;
    let mut daclPresent: BOOL = 0;
    let mut daclDefault: BOOL = 0;

    let status = unsafe {
        secapi::GetSecurityDescriptorDacl(securityDesc.as_ptr() as PSECURITY_DESCRIPTOR,
                                          &mut daclPresent,
                                          &mut pDacl,
                                          &mut daclDefault)
    };

    if status == 0 || daclPresent == 0 {
        return Err(unsafe { kernel32::GetLastError() });
    }

    Ok((securityDesc, pDacl))
}

macro_rules! add_entry {
    ($z: ident, $x: ident => $y: path) => {
        {
            let entry: *mut $y = $x as *mut $y;
            let pSid = offset_of!($y => SidStart);
            $z.push(AccessControlEntry {
                entryType: unsafe { (*$x).AceType },
                flags: unsafe { (*$x).AceFlags },
                mask: unsafe { (*entry).Mask},
                size: unsafe { (*$x).AceSize },
                sid: sid_to_string(pSid.apply_ptr_mut(entry) as PSID)?,
            })
        }
    };
}

fn get_acl_entries(path: &str) -> Result<Vec<AccessControlEntry>, DWORD> {
    let (securityDesc, pDacl) = get_dacl(path)?;

    let mut hdr: PACE_HEADER = 0 as PACE_HEADER;
    let mut entries: Vec<AccessControlEntry> = Vec::new();

    for i in 0..unsafe { (*pDacl).AceCount } {
        if unsafe { secapi::GetAce(pDacl, i as u32, &mut hdr) } == 0 {
            return Err(unsafe { kernel32::GetLastError() });
        }

        match unsafe { (*hdr).AceType } {
            0 => add_entry!(entries, hdr => ACCESS_ALLOWED_ACE),
            1 => add_entry!(entries, hdr => ACCESS_DENIED_ACE),
            _ => continue,
        }
    }

    Ok(entries)
}

fn main() {
    let results = match get_acl_entries("C:\\tools\\HxD.exe") {
        Ok(x) => x,
        Err(x) => {
            println!("Failed to get ACL entries: {:}", x);
            process::exit(-1)
        }
    };

    for item in results {
        match item.entryType {
            0 => {
                println!("Type=AccessAllowed Size={:04x} Flags={:08x} Mask={:08x} Sid={:}",
                         item.size,
                         item.flags,
                         item.mask,
                         item.sid);
            }
            1 => {
                println!("Type=AccessDenied  Size={:04x} Flags={:08x} Mask={:08x} Sid={:}",
                         item.size,
                         item.flags,
                         item.mask,
                         item.sid);
            }
            _ => {}
        }
    }
}
