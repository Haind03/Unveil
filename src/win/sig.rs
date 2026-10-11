//! Authenticode verification (embedded signature, then system catalogs). Offline: no revocation fetch.

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::Mutex;

use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{GENERIC_READ, HANDLE};
use windows_sys::Win32::Security::Cryptography::Catalog::{
    CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2, CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext,
    CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext, CATALOG_INFO,
};
use windows_sys::Win32::Security::Cryptography::{CertGetNameStringW, CERT_NAME_SIMPLE_DISPLAY_TYPE};
use windows_sys::Win32::Security::WinTrust::{
    WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO,
    WINTRUST_DATA, WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_CATALOG, WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE,
    WTD_STATEACTION_VERIFY, WTD_UI_NONE,
};
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING};

use super::{from_wide, wide, Handle};
use crate::core::SigStatus;

const TRUST_E_NOSIGNATURE: i32 = 0x800B0100u32 as i32;
const TRUST_E_SUBJECT_FORM_UNKNOWN: i32 = 0x800B0003u32 as i32;
const TRUST_E_PROVIDER_UNKNOWN: i32 = 0x800B0001u32 as i32;
const TRUST_E_BAD_DIGEST: i32 = 0x80096010u32 as i32;
const CERT_E_REVOKED: i32 = 0x800B010Cu32 as i32;
const CERT_E_UNTRUSTEDROOT: i32 = 0x800B0109u32 as i32;
const CERT_E_EXPIRED: i32 = 0x800B0101u32 as i32;
const TRUST_E_EXPLICIT_DISTRUST: i32 = 0x800B0111u32 as i32;
const CERT_E_CHAINING: i32 = 0x800B010Au32 as i32;

static CACHE: Mutex<Option<HashMap<String, SigStatus>>> = Mutex::new(None);

pub fn check(path: &str) -> SigStatus {
    let key = path.to_ascii_lowercase();
    if let Some(s) = CACHE.lock().unwrap().get_or_insert_with(HashMap::new).get(&key) {
        return s.clone();
    }
    let s = verify(path);
    CACHE.lock().unwrap().get_or_insert_with(HashMap::new).insert(key, s.clone());
    s
}

fn verify(path: &str) -> SigStatus {
    let wpath = wide(path);
    let mut fi = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: wpath.as_ptr(),
        ..Default::default()
    };
    let mut wd = base_data();
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.Anonymous.pFile = &mut fi;
    let (st, signer) = run(&mut wd);
    match st {
        0 => SigStatus::Signed(signer),
        TRUST_E_NOSIGNATURE | TRUST_E_SUBJECT_FORM_UNKNOWN | TRUST_E_PROVIDER_UNKNOWN => catalog(path).unwrap_or(SigStatus::Unsigned),
        other => map_error(other, signer),
    }
}

fn map_error(st: i32, signer: Option<String>) -> SigStatus {
    let who = signer.clone().map(|s| format!(" (signer: {s})")).unwrap_or_default();
    match st {
        CERT_E_EXPIRED => SigStatus::Signed(signer.map(|s| format!("{s} [expired, not timestamped]"))),
        TRUST_E_BAD_DIGEST => SigStatus::Invalid(format!("hash mismatch: file modified after signing{who}")),
        CERT_E_REVOKED => SigStatus::Invalid(format!("certificate revoked{who}")),
        CERT_E_UNTRUSTEDROOT => SigStatus::Invalid(format!("untrusted root / self-signed{who}")),
        CERT_E_CHAINING => SigStatus::Invalid(format!("certificate chain cannot be built{who}")),
        TRUST_E_EXPLICIT_DISTRUST => SigStatus::Invalid(format!("certificate explicitly distrusted{who}")),
        other => SigStatus::Invalid(format!("WinVerifyTrust 0x{:08x}{who}", other as u32)),
    }
}

fn base_data() -> WINTRUST_DATA {
    WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
        ..Default::default()
    }
}

/// Verify, pull the leaf signer name, close the state.
fn run(wd: &mut WINTRUST_DATA) -> (i32, Option<String>) {
    let mut action: GUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let st = unsafe { WinVerifyTrust(std::ptr::null_mut(), &mut action, wd as *mut _ as *mut c_void) };
    let signer = unsafe { signer_name(wd.hWVTStateData) };
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    unsafe { WinVerifyTrust(std::ptr::null_mut(), &mut action, wd as *mut _ as *mut c_void) };
    (st, signer)
}

unsafe fn signer_name(state: HANDLE) -> Option<String> {
    if state.is_null() {
        return None;
    }
    let prov = WTHelperProvDataFromStateData(state);
    if prov.is_null() {
        return None;
    }
    let sgnr = WTHelperGetProvSignerFromChain(prov, 0, 0, 0);
    if sgnr.is_null() || (*sgnr).csCertChain == 0 || (*sgnr).pasCertChain.is_null() {
        return None;
    }
    let cert = (*(*sgnr).pasCertChain).pCert;
    if cert.is_null() {
        return None;
    }
    let mut buf = vec![0u16; 256];
    let n = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, std::ptr::null(), buf.as_mut_ptr(), buf.len() as u32);
    (n > 1).then(|| from_wide(&buf))
}

fn catalog(path: &str) -> Option<SigStatus> {
    let wpath = wide(path);
    let file = Handle::new(unsafe {
        CreateFileW(
            wpath.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    })?;
    let mut admin: isize = 0;
    let sha256 = wide("SHA256");
    if unsafe { CryptCATAdminAcquireContext2(&mut admin, std::ptr::null(), sha256.as_ptr(), std::ptr::null(), 0) } == 0 {
        return None;
    }
    struct Admin(isize);
    impl Drop for Admin {
        fn drop(&mut self) {
            unsafe { CryptCATAdminReleaseContext(self.0, 0) };
        }
    }
    let admin = Admin(admin);

    let mut hash = vec![0u8; 64];
    let mut n = hash.len() as u32;
    if unsafe { CryptCATAdminCalcHashFromFileHandle2(admin.0, file.0, &mut n, hash.as_mut_ptr(), 0) } == 0 {
        return None;
    }
    hash.truncate(n as usize);
    let cat = unsafe { CryptCATAdminEnumCatalogFromHash(admin.0, hash.as_ptr(), n, 0, std::ptr::null_mut()) };
    if cat == 0 {
        return None;
    }
    let mut ci = CATALOG_INFO { cbStruct: std::mem::size_of::<CATALOG_INFO>() as u32, wszCatalogFile: [0; 260] };
    let got = unsafe { CryptCATCatalogInfoFromContext(cat, &mut ci, 0) } != 0;
    let result = if got {
        let tag = wide(&hash.iter().map(|b| format!("{b:02X}")).collect::<String>());
        let mut wci = WINTRUST_CATALOG_INFO {
            cbStruct: std::mem::size_of::<WINTRUST_CATALOG_INFO>() as u32,
            pcwszCatalogFilePath: ci.wszCatalogFile.as_ptr(),
            pcwszMemberTag: tag.as_ptr(),
            pcwszMemberFilePath: wpath.as_ptr(),
            hMemberFile: file.0,
            pbCalculatedFileHash: hash.as_mut_ptr(),
            cbCalculatedFileHash: n,
            hCatAdmin: admin.0,
            ..Default::default()
        };
        let mut wd = base_data();
        wd.dwUnionChoice = WTD_CHOICE_CATALOG;
        wd.Anonymous.pCatalog = &mut wci;
        let (st, signer) = run(&mut wd);
        Some(if st == 0 { SigStatus::Signed(signer.map(|s| format!("{s} (catalog)"))) } else { map_error(st, signer) })
    } else {
        None
    };
    unsafe { CryptCATAdminReleaseCatalogContext(admin.0, cat, 0) };
    result
}
