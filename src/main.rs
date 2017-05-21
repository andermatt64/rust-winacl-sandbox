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
use secapi::{SECURITY_DESCRIPTOR_REVISION, PACE_HEADER, ACCESS_ALLOWED_ACE, ACCESS_DENIED_ACE,
             SECURITY_DESCRIPTOR_MIN_LENGTH, ACL_REVISION};
use winapi::{PSECURITY_DESCRIPTOR, PACL, DACL_SECURITY_INFORMATION, PSID, ACL};
use winapi::{DWORD, LPVOID, BOOL, LPWSTR, HLOCAL, SOCKET, PCWSTR, PSID_AND_ATTRIBUTES,
             SID_AND_ATTRIBUTES, ERROR_SUCCESS, ERROR_ALREADY_EXISTS, HRESULT};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;
use std::iter::once;
use std::process;
use std::mem;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

#[allow(unused_imports)]
use field_offset::*;

pub const DEFAULT_PROFILE_NAME: &'static str = "appjaillauncher_default";

struct AccessControlEntry {
    entryType: u8,
    flags: u8,
    mask: u32,
    sid: String,
}

struct SidPtr {
    raw_ptr: PSID,
}

impl Drop for SidPtr {
    fn drop(&mut self) {
        if self.raw_ptr != (0 as PSID) {
            unsafe {
                secapi::FreeSid(self.raw_ptr);
            }
        }
    }
}

fn string_to_sid(StringSid: &str) -> Result<SidPtr, DWORD> {
    let mut pSid: PSID = 0 as PSID;
    let wSid: Vec<u16> = OsStr::new(StringSid)
        .encode_wide()
        .chain(once(0))
        .collect();

    if unsafe { secapi::ConvertStringSidToSidW(wSid.as_ptr(), &mut pSid) } == 0 {
        return Err(unsafe { kernel32::GetLastError() });
    }

    Ok(SidPtr { raw_ptr: pSid })
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
                mask: unsafe { (*entry).Mask },
                sid: sid_to_string(pSid.apply_ptr_mut(entry) as PSID)?,
            })
        }
    };
}

#[allow(dead_code)]
struct SimpleDacl {
    entries: Vec<AccessControlEntry>,
}

#[allow(dead_code)]
impl SimpleDacl {
    fn new() -> SimpleDacl {
        SimpleDacl { entries: Vec::new() }
    }

    fn from_path(path: &str) -> Result<SimpleDacl, DWORD> {
        #[allow(unused_variables)]
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
                _ => return Err(0xffffffff),
            }
        }

        Ok(SimpleDacl { entries: entries })
    }

    fn get_entries(&self) -> &Vec<AccessControlEntry> {
        &self.entries
    }

    fn add_entry(&mut self, entry: AccessControlEntry) -> bool {
        let target: usize;
        match entry.entryType {
            0 => {
                // We are assuming that the list is proper: that denied ACEs are placed
                // prior to allow ACEs
                match self.entries.iter().position(|&ref x| x.entryType != 1) {
                    Some(x) => {
                        target = x;
                    }
                    None => {
                        target = 0xffffffff;
                    }
                }
            }
            1 => {
                target = 0;
            }
            _ => return false,
        }

        match string_to_sid(&entry.sid) {
            Err(_) => return false,
            Ok(_) => {}
        }

        if target == 0xffffffff {
            self.entries.push(entry)
        } else {
            self.entries.insert(target, entry)
        }

        true
    }

    fn apply_to_path(&self, path: &str) -> Result<usize, DWORD> {
        let wPath: Vec<u16> = OsStr::new(path).encode_wide().chain(once(0)).collect();
        let mut securityDesc: Vec<u8> = Vec::with_capacity(SECURITY_DESCRIPTOR_MIN_LENGTH);

        if unsafe {
               secapi::InitializeSecurityDescriptor(securityDesc.as_mut_ptr() as LPVOID,
                                                    SECURITY_DESCRIPTOR_REVISION)
           } == 0 {
            return Err(unsafe { kernel32::GetLastError() });
        }

        let mut aclSize = mem::size_of::<ACL>();
        for entry in &self.entries {
            let sid = string_to_sid(&entry.sid)?;
            aclSize += unsafe { secapi::GetLengthSid(sid.raw_ptr) } as usize;

            match entry.entryType {
                0 => aclSize += mem::size_of::<ACCESS_ALLOWED_ACE>() - mem::size_of::<DWORD>(),
                1 => aclSize += mem::size_of::<ACCESS_DENIED_ACE>() - mem::size_of::<DWORD>(),
                _ => return Err(0xffffffff),
            }
        }

        let mut aclBuffer: Vec<u8> = Vec::with_capacity(aclSize);
        if unsafe {
               secapi::InitializeAcl(aclBuffer.as_mut_ptr() as PACL,
                                     aclSize as DWORD,
                                     ACL_REVISION)
           } == 0 {
            return Err(unsafe { kernel32::GetLastError() });
        }

        for entry in &self.entries {
            let sid = string_to_sid(&entry.sid)?;

            match entry.entryType {
                0 => {
                    if unsafe {
                           secapi::AddAccessAllowedAce(aclBuffer.as_mut_ptr() as PACL,
                                                       ACL_REVISION,
                                                       entry.mask,
                                                       sid.raw_ptr)
                       } == 0 {
                        return Err(unsafe { kernel32::GetLastError() });
                    }
                }
                1 => {
                    if unsafe {
                           secapi::AddAccessDeniedAce(aclBuffer.as_mut_ptr() as PACL,
                                                      ACL_REVISION,
                                                      entry.mask,
                                                      sid.raw_ptr)
                       } == 0 {
                        return Err(unsafe { kernel32::GetLastError() });
                    }
                }
                _ => return Err(0xffffffff),
            }
        }

        if unsafe {
               secapi::SetSecurityDescriptorDacl(securityDesc.as_mut_ptr() as PSECURITY_DESCRIPTOR,
                                                 1,
                                                 aclBuffer.as_ptr() as PACL,
                                                 0)
           } == 0 {
            return Err(unsafe { kernel32::GetLastError() });
        }

        if unsafe {
               secapi::SetFileSecurityW(wPath.as_ptr(),
                                        DACL_SECURITY_INFORMATION,
                                        securityDesc.as_ptr() as PSECURITY_DESCRIPTOR)
           } == 0 {
            return Err(unsafe { kernel32::GetLastError() });
        }

        Ok(0)
    }
}

struct AppContainerProfile {
    profile: String,
    childPath: String,
    outboundNetwork: bool,
    debug: bool,
    sid: PSID,
}

impl AppContainerProfile {
    fn new(profile: &str, path: &str) -> AppContainerProfile {
        let mut pSid: PSID = 0 as PSID;
        let profile_name: Vec<u16> = OsStr::new(profile)
            .encode_wide()
            .chain(once(0))
            .collect();

        // TODO: CreateAppContainerProfile
        let mut hr = unsafe {
            secapi::CreateAppContainerProfile(profile_name.as_ptr(),
                                              profile_name.as_ptr(),
                                              profile_name.as_ptr(),
                                              0 as PSID_AND_ATTRIBUTES,
                                              0 as DWORD,
                                              &mut pSid)
        };

        if hr == (ERROR_SUCCESS as HRESULT) {}
        println!("hr = {:08x}", hr);
        // TODO: if ERROR_ALREADY_EXISTS, DeriveAppContainerSidFromAppContainerName

        AppContainerProfile {
            profile: profile.to_string(),
            childPath: path.to_string(),
            outboundNetwork: true,
            debug: false,
            sid: pSid,
        }
    }

    fn enable_outbound_network(&mut self, has_outbound_network: bool) {
        self.outboundNetwork = has_outbound_network;
    }

    fn enable_debug(&mut self, is_debug: bool) {
        self.debug = is_debug;
    }

    fn launch(&self, client: SOCKET) {}
}

fn main() {
    let mut newAcl = SimpleDacl::new();

    let mut fd = match File::create("test.txt") {
        Ok(x) => x,
        _ => return,
    };
    {
        fd.write_all(b"w00t").unwrap();
    }

    newAcl.add_entry(AccessControlEntry {
                         sid: String::from("S-1-1-0"),
                         mask: 0x001f01ff,
                         entryType: 0,
                         flags: 0,
                     });
    newAcl.apply_to_path("test.txt").unwrap();

    let acl = match SimpleDacl::from_path("test.txt") {
        Ok(x) => x,
        Err(x) => {
            println!("Failed to get ACL entries: {:}", x);
            process::exit(-1)
        }
    };

    for item in acl.get_entries() {
        match item.entryType {
            0 => {
                println!("Type=AccessAllowed Flags={:08x} Mask={:08x} Sid={:}",
                         item.flags,
                         item.mask,
                         item.sid);
            }
            1 => {
                println!("Type=AccessDenied  Flags={:08x} Mask={:08x} Sid={:}",
                         item.flags,
                         item.mask,
                         item.sid);
            }
            _ => {}
        }
    }

    let profile = AppContainerProfile::new("default_profile_appjail", "C:\\blah\\cool.exe");
}
