#![allow(dead_code)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
extern crate winapi;

use self::winapi::*;

pub const SECURITY_DESCRIPTOR_MIN_LENGTH: usize = 64;
pub const SECURITY_DESCRIPTOR_REVISION: DWORD = 1;
pub const ACL_REVISION: DWORD = 2;
pub const SE_GROUP_ENABLED: DWORD = 4;

const PROC_THREAD_ATTRIBUTE_NUMBER: DWORD = 0x0000ffff;
const PROC_THREAD_ATTRIBUTE_THREAD: DWORD = 0x00010000;
const PROC_THREAD_ATTRIBUTE_INPUT: DWORD = 0x00020000;
const PROC_THREAD_ATTRIBUTE_ADDITIVE: DWORD = 0x00040000;

const ProcThreadAttributeSecurityCapabilities: DWORD = 9;
pub const PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES: SIZE_T =
    ((ProcThreadAttributeSecurityCapabilities & PROC_THREAD_ATTRIBUTE_NUMBER) |
     PROC_THREAD_ATTRIBUTE_INPUT) as SIZE_T;


const FACILITY_WIN32: DWORD = 7;

pub fn HRESULT_FROM_WIN32(code: DWORD) -> HRESULT {
    if (code as HRESULT) <= 0 {
        code as HRESULT
    } else {
        ((code & 0x0000ffff) | ((FACILITY_WIN32 as DWORD) << 16) | 0x80000000) as HRESULT
    }
}

macro_rules! DEF_STRUCT {
    {$(#[$attrs:meta])* nodebug struct $name:ident { $($field:ident: $ftype:ty,)+ }} => {
        #[repr(C)] $(#[$attrs])*
        pub struct $name {
            $(pub $field: $ftype,)+
        }
        impl Copy for $name {}
        impl Clone for $name { fn clone(&self) -> $name { *self } }
    };
    {$(#[$attrs:meta])* struct $name:ident { $($field:ident: $ftype:ty,)+ }} => {
        #[repr(C)] #[derive(Debug)] $(#[$attrs])*
        pub struct $name {
            $(pub $field: $ftype,)+
        }
        impl Copy for $name {}
        impl Clone for $name { fn clone(&self) -> $name { *self } }
    };
}

macro_rules! DEF_ENUM {
    {enum $name:ident { $($variant:ident = $value:expr,)+ }} => {
        pub type $name = u32;
        $(pub const $variant: $name = $value;)+
    };
    {enum $name:ident { $variant:ident = $value:expr, $($rest:tt)* }} => {
        pub type $name = u32;
        pub const $variant: $name = $value;
        DEF_ENUM!{@gen $name $variant, $($rest)*}
    };
    {enum $name:ident { $variant:ident, $($rest:tt)* }} => {
        DEF_ENUM!{enum $name { $variant = 0, $($rest)* }}
    };
    {@gen $name:ident $base:ident,} => {};
    {@gen $name:ident $base:ident, $variant:ident = $value:expr, $($rest:tt)*} => {
        pub const $variant: $name = $value;
        DEF_ENUM!{@gen $name $variant, $($rest)*}
    };
    {@gen $name:ident $base:ident, $variant:ident, $($rest:tt)*} => {
        pub const $variant: $name = $base + 1u32;
        DEF_ENUM!{@gen $name $variant, $($rest)*}
    };
}

DEF_ENUM!{enum ACL_INFORMATION_CLASS {
    AclRevisionInformation = 1,
    AclSizeInformation,
}}

DEF_STRUCT!{struct ACE_HEADER {
    AceType: BYTE,
    AceFlags: BYTE,
    AceSize: WORD,
}}

DEF_STRUCT!{struct ACCESS_ALLOWED_ACE {
    Header: ACE_HEADER,
    Mask: ACCESS_MASK,
    SidStart: DWORD,
}}

DEF_STRUCT!{struct ACCESS_DENIED_ACE {
    Header: ACE_HEADER,
    Mask: ACCESS_MASK,
    SidStart: DWORD,
}}

DEF_STRUCT!{struct ACL_SIZE_INFORMATION {
    AceCount: DWORD,
    AclBytesInUse: DWORD,
    AclBytesFree: DWORD,
}}

DEF_STRUCT!{struct STARTUPINFOEXW {
    StartupInfo: STARTUPINFOW,
    lpAttributeList: PPROC_THREAD_ATTRIBUTE_LIST,
}}

pub type PACE_HEADER = *mut ACE_HEADER;
pub type PACCESS_ALLOWED_ACE = *mut ACCESS_ALLOWED_ACE;
pub type PACCESS_DENIED_ACE = *mut ACCESS_DENIED_ACE;
pub type PACL_SIZE_INFORMATION = *mut ACL_SIZE_INFORMATION;

#[link(name = "advapi32")]
extern "system" {
    pub fn GetFileSecurityW(lpFileName: LPCWSTR,
                            RequestedInformation: SECURITY_INFORMATION,
                            pSecurityDescriptor: PSECURITY_DESCRIPTOR,
                            nLength: DWORD,
                            lpnLengthNeeded: LPDWORD)
                            -> BOOL;
    pub fn InitializeSecurityDescriptor(pSecurityDescriptor: PSECURITY_DESCRIPTOR,
                                        dwRevision: DWORD)
                                        -> BOOL;
    pub fn GetSecurityDescriptorDacl(pSecurityDescriptor: PSECURITY_DESCRIPTOR,
                                     lpbDaclPresent: LPBOOL,
                                     pDacl: *mut PACL,
                                     lpbDaclDefaulted: LPBOOL)
                                     -> BOOL;
    pub fn GetAclInformation(pAcl: PACL,
                             pAclInformation: LPVOID,
                             nAclInformationLength: DWORD,
                             dwAclInformationClass: ACL_INFORMATION_CLASS)
                             -> BOOL;
    pub fn InitializeAcl(pAcl: PACL, nAclLength: DWORD, dwAclRevision: DWORD) -> BOOL;
    pub fn GetAce(pAcl: PACL, dwAceIndex: DWORD, pAce: *mut PACE_HEADER) -> BOOL;
    pub fn ConvertSidToStringSidW(Sid: PSID, StringSid: *mut LPWSTR) -> BOOL;
    pub fn ConvertStringSidToSidW(StringSid: LPCWSTR, Sid: *mut PSID) -> BOOL;
    pub fn EqualSid(pSid1: PSID, pSid2: PSID) -> BOOL;
    pub fn AddAce(pAcl: PACL,
                  dwAcerevision: DWORD,
                  dwStartingAceIndex: DWORD,
                  pAceList: LPVOID,
                  nAceListLength: DWORD)
                  -> BOOL;
    pub fn AddAccessAllowedAce(pAcl: PACL,
                               dwAceRevision: DWORD,
                               AccessMask: DWORD,
                               pSid: PSID)
                               -> BOOL;
    pub fn AddAccessDeniedAce(pAcl: PACL,
                              dwAceRevision: DWORD,
                              AccessMask: DWORD,
                              pSid: PSID)
                              -> BOOL;
    pub fn SetSecurityDescriptorDacl(pSecurityDescriptor: PSECURITY_DESCRIPTOR,
                                     bDaclPresent: BOOL,
                                     pDacl: PACL,
                                     pDaclDefaulted: BOOL)
                                     -> BOOL;
    pub fn SetFileSecurityW(lpFileName: LPCWSTR,
                            SecurityInformation: SECURITY_INFORMATION,
                            pSecurityDescriptor: PSECURITY_DESCRIPTOR)
                            -> BOOL;
    pub fn GetLengthSid(pSid: PSID) -> DWORD;
    pub fn FreeSid(pSid: PSID) -> PVOID;
}

#[link(name = "userenv")]
extern "system" {
    pub fn CreateAppContainerProfile(pszAppContainerName: PCWSTR,
                                     pszDisplayName: PCWSTR,
                                     pszDescription: PCWSTR,
                                     pCapabilities: PSID_AND_ATTRIBUTES,
                                     dwCapabilityCount: DWORD,
                                     ppSidAppContainerSid: *mut PSID)
                                     -> HRESULT;
    pub fn DeriveAppContainerSidFromAppContainerName(pszAppContainerName: PCWSTR,
                                                     ppsidAppContainerSid: *mut PSID)
                                                     -> HRESULT;
    pub fn DeleteAppContainerProfile(pszAppContainerName: PCWSTR) -> HRESULT;
}