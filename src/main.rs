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
             SECURITY_DESCRIPTOR_MIN_LENGTH, ACL_REVISION, HRESULT_FROM_WIN32, SE_GROUP_ENABLED,
             PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, STARTUPINFOEXW};
use winapi::{PSECURITY_DESCRIPTOR, PACL, DACL_SECURITY_INFORMATION, PSID, ACL};
use winapi::{DWORD, LPVOID, BOOL, LPWSTR, HLOCAL, SOCKET, PCWSTR, PSID_AND_ATTRIBUTES,
             SID_AND_ATTRIBUTES, ERROR_SUCCESS, ERROR_ALREADY_EXISTS, HRESULT,
             SECURITY_CAPABILITIES, LPPROC_THREAD_ATTRIBUTE_LIST, PPROC_THREAD_ATTRIBUTE_LIST,
             SIZE_T, PSIZE_T, PVOID, PSECURITY_CAPABILITIES, STARTUPINFOW, HANDLE, WORD, LPBYTE,
             STARTF_USESTDHANDLES, STARTF_USESHOWWINDOW, SW_HIDE};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;
use std::iter::once;
use std::process;
use std::mem;
use std::fs::File;
use std::io::prelude::*;

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
    sid: SidPtr,
}

impl AppContainerProfile {
    fn new(profile: &str, path: &str) -> Result<AppContainerProfile, HRESULT> {
        let mut pSid: PSID = 0 as PSID;
        let profile_name: Vec<u16> = OsStr::new(profile)
            .encode_wide()
            .chain(once(0))
            .collect();

        let mut hr = unsafe {
            secapi::CreateAppContainerProfile(profile_name.as_ptr(),
                                              profile_name.as_ptr(),
                                              profile_name.as_ptr(),
                                              0 as PSID_AND_ATTRIBUTES,
                                              0 as DWORD,
                                              &mut pSid)
        };

        if hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS) {
            hr = unsafe {
                secapi::DeriveAppContainerSidFromAppContainerName(profile_name.as_ptr(), &mut pSid)
            };
            if hr != (ERROR_SUCCESS as HRESULT) {
                return Err(hr);
            }
        }

        Ok(AppContainerProfile {
               profile: profile.to_string(),
               childPath: path.to_string(),
               outboundNetwork: true,
               debug: false,
               sid: SidPtr { raw_ptr: pSid },
           })
    }

    fn remove(profile: &str) -> bool {
        let profile_name: Vec<u16> = OsStr::new(profile)
            .encode_wide()
            .chain(once(0))
            .collect();
        let mut pSid: PSID = 0 as PSID;

        let mut hr = unsafe {
            secapi::DeriveAppContainerSidFromAppContainerName(profile_name.as_ptr(), &mut pSid)
        };

        if hr == (ERROR_SUCCESS as HRESULT) {
            hr = unsafe { secapi::DeleteAppContainerProfile(profile_name.as_ptr()) };
            return hr == (ERROR_SUCCESS as HRESULT);
        }

        false
    }

    fn enable_outbound_network(&mut self, has_outbound_network: bool) {
        self.outboundNetwork = has_outbound_network;
    }

    fn enable_debug(&mut self, is_debug: bool) {
        self.debug = is_debug;
    }

    fn launch(&self, client: SOCKET) -> bool {
        let network_allow_sid = match string_to_sid("S-1-15-3-1") {
            Ok(x) => x,
            Err(_) => return false,
        };
        let mut capabilities = SECURITY_CAPABILITIES {
            AppContainerSid: self.sid.raw_ptr,
            Capabilities: 0 as PSID_AND_ATTRIBUTES,
            CapabilityCount: 0,
            Reserved: 0,
        };
        let mut attrs;
        let mut si = STARTUPINFOEXW {
            StartupInfo: STARTUPINFOW {
                cb: 0 as DWORD,
                lpReserved: 0 as LPWSTR,
                lpDesktop: 0 as LPWSTR,
                lpTitle: 0 as LPWSTR,
                dwX: 0 as DWORD,
                dwY: 0 as DWORD,
                dwXSize: 0 as DWORD,
                dwYSize: 0 as DWORD,
                dwXCountChars: 0 as DWORD,
                dwYCountChars: 0 as DWORD,
                dwFillAttribute: 0 as DWORD,
                dwFlags: 0 as DWORD,
                wShowWindow: 0 as WORD,
                cbReserved2: 0 as WORD,
                lpReserved2: 0 as LPBYTE,
                hStdInput: 0 as HANDLE,
                hStdOutput: 0 as HANDLE,
                hStdError: 0 as HANDLE,
            },
            lpAttributeList: 0 as PPROC_THREAD_ATTRIBUTE_LIST,
        };

        if !self.debug {

            // TODO: If outbound network is enabled, create capabilities list structure
            if !self.outboundNetwork {
                attrs = SID_AND_ATTRIBUTES {
                    Sid: network_allow_sid.raw_ptr,
                    Attributes: SE_GROUP_ENABLED,
                };

                capabilities.CapabilityCount = 1;
                capabilities.Capabilities = &mut attrs;
            }

            let mut listSize: SIZE_T = 0;
            if unsafe {
                   kernel32::InitializeProcThreadAttributeList(0 as LPPROC_THREAD_ATTRIBUTE_LIST,
                                                               1,
                                                               0,
                                                               &mut listSize)
               } !=
               0 {
                return false;
            }

            let mut attrBuf: Vec<u8> = Vec::with_capacity(listSize as usize);
            if unsafe {
                   kernel32::InitializeProcThreadAttributeList(attrBuf.as_mut_ptr() as
                                                               LPPROC_THREAD_ATTRIBUTE_LIST,
                                                               1,
                                                               0,
                                                               &mut listSize)
               } ==
               0 {
                return false;
            }

            if unsafe {
                kernel32::UpdateProcThreadAttribute(attrBuf.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST, 
                                                    0, 
                                                    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, 
                                                    unsafe { mem::transmute::<PSECURITY_CAPABILITIES, LPVOID>(&mut capabilities) }, 
                                                    mem::size_of::<SECURITY_CAPABILITIES>() as SIZE_T, 
                                                    0 as PVOID, 
                                                    0 as PSIZE_T) } == 0 {
                return false
            }

            si.StartupInfo.cb = mem::size_of::<STARTUPINFOEXW>();
            si.lpAttributeList = attrBuf.as_mut_ptr() as PPROC_THREAD_ATTRIBUTE_LIST;

            // TODO: add EXTENDED_STARTUPINFO_PRESENT to dwCreationFlags
        } else {
            si.StartupInfo.cb = mem::size_of::<STARTUPINFOW>();
        }

        si.StartupInfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        // TODO: Redirect STDIN/STDOUT/STDERR to the socket
        siStartupInfo.wShowWindow = SW_HIDE;

        // TODO: Make sure dwCreationFlags has the right flags (EXTENDED_STARTUPINFO_PRESENT for non-debug)
        // TODO: CreateProcess
        false
    }
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

    AppContainerProfile::remove("default_profile_appjail");
}
