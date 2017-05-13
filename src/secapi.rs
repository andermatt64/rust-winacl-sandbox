#![allow(dead_code)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
extern crate winapi;

use self::winapi::*;

macro_rules! STRUCT {
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

ENUM!{enum ACL_INFORMATION_CLASS {
    AclRevisionInformation = 1,
    AclSizeInformation,
}}

STRUCT!{struct ACE_HEADER {
    AceType: BYTE,
    AceFlags: BYTE,
    AceSize: WORD,
}}

STRUCT!{struct ACCESS_ALLOWED_ACE {
    Header: ACE_HEADER,
    Mask: ACCESS_MASK,
    SidStart: DWORD,
}}

STRUCT!{struct ACCESS_DENIED_ACE {
    Header: ACE_HEADER,
    Mask: ACCESS_MASK,
    SidStart: DWORD,
}}

pub type PACE_HEADER = *mut ACE_HEADER;
pub type PACCESS_ALLOWED_ACE = *mut ACCESS_ALLOWED_ACE;
pub type PACCESS_DENIED_ACE = *mut ACCESS_DENIED_ACE;

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
    pub fn EqualSid();
    pub fn AddAce();
    pub fn AddAccessAllowedAce();
    pub fn SetSecurityDescriptorDacl();
    pub fn SetFileSecurity();
}