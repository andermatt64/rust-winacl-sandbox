#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![cfg(windows)]

extern crate winapi;
extern crate kernel32;
extern crate field_offset;
extern crate libc;
extern crate widestring;

use super::winffi;

use super::winffi::{HRESULT_FROM_WIN32, SE_GROUP_ENABLED, string_to_sid, sid_to_string,
                    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, STARTUPINFOEXW, LPSTARTUPINFOEXW,
                    HandlePtr};
use self::winapi::{DWORD, LPVOID, LPWSTR, PSID, SOCKET, PSID_AND_ATTRIBUTES, SID_AND_ATTRIBUTES,
                   ERROR_SUCCESS, ERROR_ALREADY_EXISTS, HRESULT, SECURITY_CAPABILITIES,
                   LPPROC_THREAD_ATTRIBUTE_LIST, PPROC_THREAD_ATTRIBUTE_LIST, SIZE_T, PSIZE_T,
                   PVOID, PSECURITY_CAPABILITIES, STARTUPINFOW, LPSTARTUPINFOW, HANDLE, WORD,
                   LPBYTE, STARTF_USESTDHANDLES, STARTF_USESHOWWINDOW, SW_HIDE,
                   ERROR_FILE_NOT_FOUND, PROCESS_INFORMATION, EXTENDED_STARTUPINFO_PRESENT,
                   LPSECURITY_ATTRIBUTES, INFINITE, WAIT_OBJECT_0};
use std::path::{Path, PathBuf};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::iter::once;
use std::mem;
use std::env;

#[allow(dead_code)]
pub struct Profile {
    profile: String,
    childPath: String,
    outboundNetwork: bool,
    debug: bool,
    sid: String,
}

impl Profile {
    fn new(profile: &str, path: &str) -> Result<Profile, HRESULT> {
        let mut pSid: PSID = 0 as PSID;
        let profile_name: Vec<u16> = OsStr::new(profile)
            .encode_wide()
            .chain(once(0))
            .collect();

        if !Path::new(path).exists() {
            return Err(HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND));
        }

        let mut hr = unsafe {
            winffi::CreateAppContainerProfile(profile_name.as_ptr(),
                                              profile_name.as_ptr(),
                                              profile_name.as_ptr(),
                                              0 as PSID_AND_ATTRIBUTES,
                                              0 as DWORD,
                                              &mut pSid)
        };

        if hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS) {
            hr = unsafe {
                winffi::DeriveAppContainerSidFromAppContainerName(profile_name.as_ptr(), &mut pSid)
            };
            if hr != (ERROR_SUCCESS as HRESULT) {
                return Err(hr);
            }
        }

        Ok(Profile {
               profile: profile.to_string(),
               childPath: path.to_string(),
               outboundNetwork: true,
               debug: false,
               sid: match sid_to_string(pSid) {
                   Ok(x) => x,
                   _ => return Err(-1),
               },
           })
    }

    fn remove(profile: &str) -> bool {
        let profile_name: Vec<u16> = OsStr::new(profile)
            .encode_wide()
            .chain(once(0))
            .collect();
        let mut pSid: PSID = 0 as PSID;

        let mut hr = unsafe {
            winffi::DeriveAppContainerSidFromAppContainerName(profile_name.as_ptr(), &mut pSid)
        };

        if hr == (ERROR_SUCCESS as HRESULT) {
            hr = unsafe { winffi::DeleteAppContainerProfile(profile_name.as_ptr()) };
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

    fn launch(&self, client: SOCKET, dirPath: &str) -> Result<HandlePtr, DWORD> {
        let network_allow_sid = match string_to_sid("S-1-15-3-1") {
            Ok(x) => x,
            Err(_) => return Err(0xffffffff),
        };
        let sid = string_to_sid(&self.sid)?;
        let mut capabilities = SECURITY_CAPABILITIES {
            AppContainerSid: sid.raw_ptr,
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
        let mut dwCreationFlags: DWORD = 0 as DWORD;

        if !self.debug {
            if self.outboundNetwork {
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
                return Err(unsafe { kernel32::GetLastError() });
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
                return Err(unsafe { kernel32::GetLastError() });
            }

            if unsafe {
                kernel32::UpdateProcThreadAttribute(attrBuf.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST, 
                                                    0, 
                                                    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, 
                                                    mem::transmute::<PSECURITY_CAPABILITIES, LPVOID>(&mut capabilities), 
                                                    mem::size_of::<SECURITY_CAPABILITIES>() as SIZE_T, 
                                                    0 as PVOID, 
                                                    0 as PSIZE_T) } == 0 {
                return Err(unsafe { kernel32::GetLastError() })
            }

            si.StartupInfo.cb = mem::size_of::<STARTUPINFOEXW>() as DWORD;
            si.lpAttributeList = attrBuf.as_mut_ptr() as PPROC_THREAD_ATTRIBUTE_LIST;

            dwCreationFlags |= EXTENDED_STARTUPINFO_PRESENT;
        } else {
            si.StartupInfo.cb = mem::size_of::<STARTUPINFOW>() as DWORD;
        }

        si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;

        if (client as DWORD) != 0xffffffff {
            si.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
            si.StartupInfo.hStdInput = client as HANDLE;
            si.StartupInfo.hStdOutput = client as HANDLE;
            si.StartupInfo.hStdError = client as HANDLE;
        }

        si.StartupInfo.wShowWindow = SW_HIDE as WORD;

        let currentDir: Vec<u16> = OsStr::new(&dirPath.to_string())
            .encode_wide()
            .chain(once(0))
            .collect();
        let mut cmdLine: Vec<u16> = OsStr::new(&self.childPath)
            .encode_wide()
            .chain(once(0))
            .collect();
        let mut pi = PROCESS_INFORMATION {
            hProcess: 0 as HANDLE,
            hThread: 0 as HANDLE,
            dwProcessId: 0 as DWORD,
            dwThreadId: 0 as DWORD,
        };

        if unsafe {
               kernel32::CreateProcessW(0 as LPWSTR,
                                        cmdLine.as_mut_ptr(),
                                        0 as LPSECURITY_ATTRIBUTES,
                                        0 as LPSECURITY_ATTRIBUTES,
                                        0,
                                        dwCreationFlags,
                                        0 as LPVOID,
                                        currentDir.as_ptr(),
                                        mem::transmute::<LPSTARTUPINFOEXW, LPSTARTUPINFOW>(&mut si),
                                        &mut pi)
           } == 0 {
            return Err(unsafe { kernel32::GetLastError() });
        }

        unsafe { kernel32::CloseHandle(pi.hThread) };

        Ok(HandlePtr::new(pi.hProcess))
    }
}

#[test]
fn test_profile_sid() {
    {
        let result = Profile::new("default_profile", "INVALID_FILE");
        assert!(result.is_err());
    }

    {
        let mut result = Profile::new("cmd_profile", "\\Windows\\System32\\cmd.exe");
        assert!(result.is_ok());

        let profile = result.unwrap();

        result = Profile::new("cmd_profile", "\\Windows\\System32\\cmd.exe");
        assert!(result.is_ok());

        let same_profile = result.unwrap();
        assert_eq!(profile.sid, same_profile.sid);

        assert!(Profile::remove("cmd_profile"));

        result = Profile::new("cmd_profile1", "\\Windows\\System32\\cmd.exe");
        assert!(result.is_ok());

        let new_profile = result.unwrap();
        assert!(profile.sid != new_profile.sid);
    }
}

#[cfg(test)]
fn get_unittest_support_path() -> Option<PathBuf> {
    let mut dir_path = match env::current_exe() {
        Ok(x) => x,
        Err(_) => return None,
    };

    while dir_path.pop() {
        dir_path.push("unittest_support");
        if dir_path.exists() && dir_path.is_dir() {
            return Some(dir_path);
        }
        dir_path.pop();
    }

    None
}

#[cfg(test)]
const OUTBOUND_CONNECT_MASK: u32 = 0x00000001;
#[cfg(test)]
const FILE_READ_MASK: u32 = 0x00000002;
#[cfg(test)]
const FILE_WRITE_MASK: u32 = 0x00000004;
#[cfg(test)]
const REGISTRY_READ_MASK: u32 = 0x00000008;
#[cfg(test)]
const REGISTRY_WRITE_MASK: u32 = 0x00000010;

#[test]
fn test_appcontainer() {
    let result = get_unittest_support_path();
    assert!(!result.is_none());

    let mut child_path = result.unwrap();
    let dir_path = child_path.clone();
    child_path.push("sandbox-test.exe");

    Profile::remove("default_appjail");
    if let Ok(mut profile) = Profile::new("default_appjail", child_path.to_str().unwrap()) {
        {
            let launch_result = profile.launch(0xffffffff as SOCKET, dir_path.to_str().unwrap());
            assert!(launch_result.is_ok());

            let hProcess = launch_result.unwrap();
            assert_eq!(unsafe { kernel32::WaitForSingleObject(hProcess.raw, INFINITE) },
                       WAIT_OBJECT_0);

            let mut dwExitCode: DWORD = 0 as DWORD;
            assert!(unsafe { kernel32::GetExitCodeProcess(hProcess.raw, &mut dwExitCode) } != 0);

            assert!((dwExitCode & OUTBOUND_CONNECT_MASK) == 0);
            assert!((dwExitCode & FILE_READ_MASK) != 0);
            assert!((dwExitCode & FILE_WRITE_MASK) != 0);
            assert!((dwExitCode & REGISTRY_READ_MASK) == 0);
            assert!((dwExitCode & REGISTRY_WRITE_MASK) != 0);
        }

        profile.enable_outbound_network(false);

        {
            let launch_result = profile.launch(0xffffffff as SOCKET, dir_path.to_str().unwrap());
            assert!(launch_result.is_ok());

            let hProcess = launch_result.unwrap();
            assert_eq!(unsafe { kernel32::WaitForSingleObject(hProcess.raw, INFINITE) },
                       WAIT_OBJECT_0);

            let mut dwExitCode: DWORD = 0 as DWORD;
            assert!(unsafe { kernel32::GetExitCodeProcess(hProcess.raw, &mut dwExitCode) } != 0);

            assert!((dwExitCode & OUTBOUND_CONNECT_MASK) != 0);
            assert!((dwExitCode & FILE_READ_MASK) != 0);
            assert!((dwExitCode & FILE_WRITE_MASK) != 0);
            assert!((dwExitCode & REGISTRY_READ_MASK) == 0);
            assert!((dwExitCode & REGISTRY_WRITE_MASK) != 0);
        }

        profile.enable_outbound_network(true);
        profile.enable_debug(true);

        {
            let launch_result = profile.launch(0xffffffff as SOCKET, dir_path.to_str().unwrap());
            assert!(launch_result.is_ok());

            let hProcess = launch_result.unwrap();
            assert_eq!(unsafe { kernel32::WaitForSingleObject(hProcess.raw, INFINITE) },
                       WAIT_OBJECT_0);

            let mut dwExitCode: DWORD = 0 as DWORD;
            assert!(unsafe { kernel32::GetExitCodeProcess(hProcess.raw, &mut dwExitCode) } != 0);

            assert!((dwExitCode & OUTBOUND_CONNECT_MASK) == 0);
            assert!((dwExitCode & FILE_READ_MASK) == 0);
            assert!((dwExitCode & FILE_WRITE_MASK) == 0);
            assert!((dwExitCode & REGISTRY_READ_MASK) == 0);
            assert!((dwExitCode & REGISTRY_WRITE_MASK) == 0);
        }

        Profile::remove("default_appjail");
    } else {
        assert!(false);
    }
}
