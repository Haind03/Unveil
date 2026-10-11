//! Process and thread enumeration through the native API (harder to fool than Toolhelp).

use std::ffi::c_void;

use windows_sys::Wdk::System::SystemInformation::NtQuerySystemInformation;
use windows_sys::Wdk::System::Threading::{NtQueryInformationProcess, NtQueryInformationThread};
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Threading::{
    IsWow64Process, OpenProcess, OpenThread, QueryFullProcessImageNameW, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_VM_READ, THREAD_QUERY_INFORMATION,
};

use super::{from_wide, read_u64, Handle};
use crate::core::ProcInfo;

const SYSTEM_PROCESS_INFORMATION: i32 = 5;
const PROCESS_BASIC_INFORMATION: i32 = 0;
const PROCESS_COMMAND_LINE_INFORMATION: i32 = 60;
const THREAD_QUERY_SET_WIN32_START_ADDRESS: i32 = 9;
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004u32 as i32;

#[derive(Debug, Clone)]
pub struct RawProc {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub session: u32,
    pub create_time: u64,
    pub threads: Vec<u32>,
}

fn rd<T: Copy>(b: &[u8], off: usize) -> T {
    assert!(off + std::mem::size_of::<T>() <= b.len());
    unsafe { std::ptr::read_unaligned(b.as_ptr().add(off) as *const T) }
}

/// Snapshot of all processes from SystemProcessInformation (x64 layout).
pub fn snapshot() -> Vec<RawProc> {
    let mut size = 1 << 20;
    let buf = loop {
        let mut buf = vec![0u8; size];
        let mut ret = 0u32;
        let st = unsafe { NtQuerySystemInformation(SYSTEM_PROCESS_INFORMATION, buf.as_mut_ptr() as *mut c_void, size as u32, &mut ret) };
        if st == STATUS_INFO_LENGTH_MISMATCH {
            size = (ret as usize).max(size) + (256 << 10);
            continue;
        }
        if st < 0 {
            return Vec::new();
        }
        buf.truncate(ret as usize);
        break buf;
    };

    let mut out = Vec::new();
    let mut off = 0usize;
    loop {
        if off + 256 > buf.len() {
            break;
        }
        let e = &buf[off..];
        let next: u32 = rd(e, 0);
        let nthreads: u32 = rd(e, 4);
        let create_time: u64 = rd(e, 32);
        let name_len: u16 = rd(e, 56);
        let name_ptr: usize = rd(e, 64);
        let pid: usize = rd(e, 80);
        let ppid: usize = rd(e, 88);
        let session: u32 = rd(e, 100);
        let name = if name_ptr == 0 || name_len == 0 {
            if pid == 0 { "System Idle Process".into() } else { "System".into() }
        } else {
            // The buffer points inside our own allocation.
            let s = unsafe { std::slice::from_raw_parts(name_ptr as *const u16, name_len as usize / 2) };
            String::from_utf16_lossy(s)
        };
        let mut threads = Vec::with_capacity(nthreads as usize);
        for i in 0..nthreads as usize {
            let t = 256 + i * 80;
            if t + 80 > e.len() {
                break;
            }
            let tid: usize = rd(e, t + 48);
            threads.push(tid as u32);
        }
        out.push(RawProc { pid: pid as u32, ppid: ppid as u32, name, session, create_time, threads });
        if next == 0 {
            break;
        }
        off += next as usize;
    }
    out
}

pub fn open(pid: u32, deep: bool) -> Option<Handle> {
    let access = if deep { PROCESS_QUERY_INFORMATION | PROCESS_VM_READ } else { PROCESS_QUERY_LIMITED_INFORMATION };
    Handle::new(unsafe { OpenProcess(access, 0, pid) })
}

pub fn image_path(h: HANDLE) -> Option<String> {
    let mut buf = vec![0u16; 1024];
    let mut n = buf.len() as u32;
    (unsafe { QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut n) } != 0).then(|| from_wide(&buf[..n as usize]))
}

pub fn command_line(h: HANDLE) -> Option<String> {
    let mut len = 0u32;
    let mut buf = vec![0u8; 4096];
    let mut st = unsafe { NtQueryInformationProcess(h, PROCESS_COMMAND_LINE_INFORMATION, buf.as_mut_ptr() as *mut c_void, buf.len() as u32, &mut len) };
    if st == STATUS_INFO_LENGTH_MISMATCH || (st < 0 && len as usize > buf.len()) {
        buf = vec![0u8; len as usize + 16];
        st = unsafe { NtQueryInformationProcess(h, PROCESS_COMMAND_LINE_INFORMATION, buf.as_mut_ptr() as *mut c_void, buf.len() as u32, &mut len) };
    }
    if st < 0 || buf.len() < 16 {
        return None;
    }
    let n: u16 = rd(&buf, 0);
    let ptr: usize = rd(&buf, 8);
    if ptr == 0 || n == 0 {
        return None;
    }
    // UNICODE_STRING.Buffer points right after the header, inside `buf`.
    let base = buf.as_ptr() as usize;
    if ptr < base || ptr + n as usize > base + buf.len() {
        return None;
    }
    let s = unsafe { std::slice::from_raw_parts(ptr as *const u16, n as usize / 2) };
    Some(String::from_utf16_lossy(s))
}

pub fn is_wow64(h: HANDLE) -> bool {
    let mut w = 0;
    unsafe { IsWow64Process(h, &mut w) != 0 && w != 0 }
}

/// PEB address and PEB->ImageBaseAddress.
pub fn peb_image_base(h: HANDLE) -> Option<(u64, u64)> {
    let mut pbi = [0u8; 48];
    let mut len = 0u32;
    let st = unsafe { NtQueryInformationProcess(h, PROCESS_BASIC_INFORMATION, pbi.as_mut_ptr() as *mut c_void, 48, &mut len) };
    if st < 0 {
        return None;
    }
    let peb: u64 = rd(&pbi, 8);
    if peb == 0 {
        return None;
    }
    Some((peb, read_u64(h, peb + 0x10)?))
}

pub fn thread_start(tid: u32) -> Option<u64> {
    let th = Handle::new(unsafe { OpenThread(THREAD_QUERY_INFORMATION, 0, tid) })?;
    let mut addr = 0usize;
    let mut len = 0u32;
    let st = unsafe {
        NtQueryInformationThread(th.0, THREAD_QUERY_SET_WIN32_START_ADDRESS, &mut addr as *mut usize as *mut c_void, 8, &mut len)
    };
    (st >= 0).then_some(addr as u64)
}

/// Build ProcInfo for every process. Signature checks are filled later (they are slow).
pub fn collect(raw: &[RawProc]) -> Vec<ProcInfo> {
    raw.iter()
        .map(|r| {
            let mut p = ProcInfo {
                pid: r.pid,
                ppid: r.ppid,
                name: r.name.clone(),
                session: r.session,
                threads: r.threads.clone(),
                create_time: r.create_time,
                image_exists: true,
                ..Default::default()
            };
            if r.pid > 4 {
                if let Some(h) = open(r.pid, false) {
                    p.path = image_path(h.0);
                    p.cmdline = command_line(h.0);
                    p.wow64 = is_wow64(h.0);
                    if let Some(path) = &p.path {
                        p.image_exists = super::file_exists(path);
                    }
                }
            }
            p
        })
        .collect()
}
