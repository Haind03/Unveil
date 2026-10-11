//! Windows collectors. Everything here gathers raw data and hands it to `crate::core` rules.

pub mod hidden;
pub mod hooks;
pub mod memory;
pub mod persist;
pub mod procs;
pub mod sig;
pub mod ui;
pub mod wmi_sub;
#[cfg(feature = "yara")]
pub mod yara;

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::OnceLock;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE, LUID};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, GetTokenInformation, LookupPrivilegeValueW, TokenElevation, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_ELEVATION, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows_sys::Win32::Storage::FileSystem::{GetFileAttributesW, GetLogicalDriveStringsW, QueryDosDeviceW, INVALID_FILE_ATTRIBUTES};
use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows_sys::Win32::System::Environment::ExpandEnvironmentStringsW;
use windows_sys::Win32::System::SystemInformation::{ComputerNameDnsHostname, GetComputerNameExW, GetLocalTime};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

pub fn from_wide(buf: &[u16]) -> String {
    let n = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..n])
}

/// Owned kernel handle.
pub struct Handle(pub HANDLE);

impl Handle {
    pub fn new(h: HANDLE) -> Option<Handle> {
        (!h.is_null() && h != INVALID_HANDLE_VALUE).then_some(Handle(h))
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}

pub fn read_mem(h: HANDLE, addr: u64, len: usize) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; len];
    let mut got = 0usize;
    let ok = unsafe { ReadProcessMemory(h, addr as *const c_void, buf.as_mut_ptr() as *mut c_void, len, &mut got) };
    if ok == 0 && got == 0 {
        return None;
    }
    buf.truncate(got);
    Some(buf)
}

/// Read page by page; unreadable pages become `None` bytes.
pub fn read_mem_sparse(h: HANDLE, addr: u64, len: usize) -> Vec<Option<u8>> {
    let mut out = Vec::with_capacity(len);
    let mut cur = addr;
    let end = addr + len as u64;
    while cur < end {
        let page_end = ((cur & !0xfff) + 0x1000).min(end);
        let n = (page_end - cur) as usize;
        match read_mem(h, cur, n) {
            Some(b) if b.len() == n => out.extend(b.into_iter().map(Some)),
            _ => out.extend(std::iter::repeat_n(None, n)),
        }
        cur = page_end;
    }
    out
}

pub fn read_u64(h: HANDLE, addr: u64) -> Option<u64> {
    let b = read_mem(h, addr, 8)?;
    (b.len() == 8).then(|| u64::from_le_bytes(b.try_into().unwrap()))
}

pub fn read_u32(h: HANDLE, addr: u64) -> Option<u32> {
    let b = read_mem(h, addr, 4)?;
    (b.len() == 4).then(|| u32::from_le_bytes(b.try_into().unwrap()))
}

fn device_map() -> &'static Vec<(String, String)> {
    static MAP: OnceLock<Vec<(String, String)>> = OnceLock::new();
    MAP.get_or_init(|| {
        let mut v = Vec::new();
        let mut buf = vec![0u16; 512];
        let n = unsafe { GetLogicalDriveStringsW(buf.len() as u32, buf.as_mut_ptr()) } as usize;
        for drive in String::from_utf16_lossy(&buf[..n.min(buf.len())]).split('\0').filter(|s| !s.is_empty()) {
            let letter = drive.trim_end_matches('\\').to_string(); // "C:"
            let mut target = vec![0u16; 1024];
            let w = wide(&letter);
            if unsafe { QueryDosDeviceW(w.as_ptr(), target.as_mut_ptr(), target.len() as u32) } != 0 {
                v.push((from_wide(&target), letter));
            }
        }
        v
    })
}

/// `\Device\HarddiskVolume3\Windows\x.dll` -> `C:\Windows\x.dll`
pub fn device_to_dos(p: &str) -> String {
    for (dev, letter) in device_map() {
        if let Some(rest) = p.strip_prefix(dev.as_str()) {
            if rest.starts_with('\\') {
                return format!("{letter}{rest}");
            }
        }
    }
    if let Some(rest) = p.strip_prefix("\\SystemRoot\\") {
        return format!("{}\\{rest}", expand_env("%SystemRoot%"));
    }
    if let Some(rest) = p.strip_prefix("\\??\\") {
        return rest.to_string();
    }
    p.to_string()
}

pub fn expand_env(s: &str) -> String {
    if !s.contains('%') {
        return s.to_string();
    }
    let w = wide(s);
    let mut buf = vec![0u16; 4096];
    let n = unsafe { ExpandEnvironmentStringsW(w.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
    if n == 0 || n as usize > buf.len() {
        return s.to_string();
    }
    from_wide(&buf)
}

pub fn file_exists(p: &str) -> bool {
    let w = wide(p);
    unsafe { GetFileAttributesW(w.as_ptr()) != INVALID_FILE_ATTRIBUTES }
}

/// Resolve a bare program name (`cmd.exe`, `rundll32`) the way the loader would for system tools.
pub fn resolve_path(p: &str) -> String {
    let p = expand_env(p.trim().trim_matches('"'));
    let lower = p.to_ascii_lowercase();
    if lower.contains('\\') {
        if let Some(rest) = lower.strip_prefix("\\systemroot\\") {
            return format!("{}\\{}", expand_env("%SystemRoot%"), &p[p.len() - rest.len()..]);
        }
        if lower.starts_with("system32\\") {
            return format!("{}\\{}", expand_env("%SystemRoot%"), p);
        }
        return p.trim_start_matches("\\??\\").to_string();
    }
    let sysroot = expand_env("%SystemRoot%");
    let with_ext = if lower.contains('.') { p.clone() } else { format!("{p}.exe") };
    for dir in [format!("{sysroot}\\System32"), sysroot.clone(), format!("{sysroot}\\System32\\wbem")] {
        let c = format!("{dir}\\{with_ext}");
        if file_exists(&c) {
            return c;
        }
    }
    p
}

pub fn enable_debug_privilege() -> bool {
    unsafe {
        let mut tok: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut tok) == 0 {
            return false;
        }
        let tok = Handle(tok);
        let mut luid = LUID { LowPart: 0, HighPart: 0 };
        let name = wide("SeDebugPrivilege");
        if LookupPrivilegeValueW(std::ptr::null(), name.as_ptr(), &mut luid) == 0 {
            return false;
        }
        let mut tp: TOKEN_PRIVILEGES = std::mem::zeroed();
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(tok.0, 0, &tp, 0, std::ptr::null_mut(), std::ptr::null_mut()) != 0
            && windows_sys::Win32::Foundation::GetLastError() == 0
    }
}

pub fn is_elevated() -> bool {
    unsafe {
        let mut tok: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok) == 0 {
            return false;
        }
        let tok = Handle(tok);
        let mut e = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut len = 0u32;
        GetTokenInformation(tok.0, TokenElevation, &mut e as *mut _ as *mut c_void, std::mem::size_of::<TOKEN_ELEVATION>() as u32, &mut len) != 0
            && e.TokenIsElevated != 0
    }
}

pub fn hostname() -> String {
    let mut buf = vec![0u16; 256];
    let mut n = buf.len() as u32;
    if unsafe { GetComputerNameExW(ComputerNameDnsHostname, buf.as_mut_ptr(), &mut n) } != 0 {
        from_wide(&buf)
    } else {
        std::env::var("COMPUTERNAME").unwrap_or_default()
    }
}

pub fn local_time() -> (String, String) {
    let mut t = unsafe { std::mem::zeroed() };
    unsafe { GetLocalTime(&mut t) };
    (
        format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond),
        format!("{:04}{:02}{:02}-{:02}{:02}{:02}", t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond),
    )
}

/// Read a file while it may be in use (images of running processes are share-read).
pub fn read_file(path: &str) -> Option<Vec<u8>> {
    std::fs::read(path).ok()
}

/// Small cache of parsed-on-disk module bytes, shared across processes (ntdll, kernel32... are the same file).
#[derive(Default)]
pub struct FileCache {
    files: HashMap<String, Option<std::sync::Arc<Vec<u8>>>>,
}

impl FileCache {
    pub fn get(&mut self, path: &str) -> Option<std::sync::Arc<Vec<u8>>> {
        let key = path.to_ascii_lowercase();
        self.files.entry(key).or_insert_with(|| read_file(path).map(std::sync::Arc::new)).clone()
    }
}
