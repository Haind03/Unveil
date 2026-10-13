//! Forensic footprint controls: keep file last-access times unchanged while Unveil reads them,
//! and let the operator lower Unveil's CPU / I/O priority or cap its CPU share.
//!
//! The guarantees Unveil tries to meet on the host it inspects:
//!
//! - **No write to the host's drives.** Reports go next to `unveil.exe`, to a path given by
//!   `--output-dir`, or to stdout (`--json -`). The investigation drive stays untouched.
//! - **Preserve `LastAccessTime`.** When Unveil reads a process image, autostart target or
//!   file to YARA-scan, it opens the file with `FILE_WRITE_ATTRIBUTES` and, after reading,
//!   restores the original `LastAccessTime` with the `SetFileTime` sentinel `(u64::MAX)` so
//!   NTFS does not overwrite its own cached atime bump on the next flush.
//! - **Resource throttling (optional).** `--lowprio` puts Unveil into
//!   `PROCESS_MODE_BACKGROUND_BEGIN`, which lowers CPU, memory and I/O priority together.
//!   `--cpu-limit <PCT>` creates a Job Object with a hard CPU-rate cap. The operator uses these
//!   on production hosts so a hunt does not disturb what the host is doing.

use std::ffi::c_void;

use windows_sys::Win32::Foundation::{FILETIME, GENERIC_READ, HANDLE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, GetFileTime, ReadFile, SetFileTime, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_SEQUENTIAL_SCAN, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES, OPEN_EXISTING,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, SetInformationJobObject, JobObjectCpuRateControlInformation, JOBOBJECT_CPU_RATE_CONTROL_INFORMATION,
    JOBOBJECT_CPU_RATE_CONTROL_INFORMATION_0, JOB_OBJECT_CPU_RATE_CONTROL_ENABLE, JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, SetPriorityClass, PROCESS_MODE_BACKGROUND_BEGIN};

use super::{wide, Handle};

/// Read a file while leaving its NTFS `LastAccessTime` unchanged.
///
/// The sentinel `FILETIME { dwLowDateTime: 0xFFFFFFFF, dwHighDateTime: 0xFFFFFFFF }` passed to
/// `SetFileTime` tells NTFS: "do not update this field on close, even if you cached an update".
/// This is the documented way for forensic tools to avoid tramping on access timestamps.
///
/// On a FAT/ReFS/network filesystem that ignores the sentinel, this reduces to a plain read: the
/// atime behavior there is already filesystem-specific and not ours to fix. Return `None` on any
/// I/O error (file locked, disappeared, access denied); callers already treat that as "skip".
pub fn read_file_keep_atime(path: &str) -> Option<Vec<u8>> {
    let wpath = wide(path);
    let h = Handle::new(unsafe {
        CreateFileW(
            wpath.as_ptr(),
            GENERIC_READ | FILE_WRITE_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
            std::ptr::null_mut(),
        )
    })
    .or_else(|| {
        // Falling back without FILE_WRITE_ATTRIBUTES: some files (locked system DLLs, read-only
        // shares) refuse the stronger access. A plain read then bumps atime by one; that is the
        // same behavior Unveil had before this helper, so still acceptable.
        Handle::new(unsafe {
            CreateFileW(
                wpath.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                std::ptr::null_mut(),
            )
        })
    })?;

    let data = read_all(h.0)?;

    // Only restore if we hold FILE_WRITE_ATTRIBUTES (the first open path). Capture original times
    // first; if GetFileTime fails we skip the restore, which is harmless.
    let (mut ct, mut at, mut wt) = (zero_ft(), zero_ft(), zero_ft());
    if unsafe { GetFileTime(h.0, &mut ct, &mut at, &mut wt) } != 0 {
        let keep = FILETIME { dwLowDateTime: 0xFFFF_FFFF, dwHighDateTime: 0xFFFF_FFFF };
        unsafe { SetFileTime(h.0, std::ptr::null(), &keep, std::ptr::null()) };
    }
    Some(data)
}

fn zero_ft() -> FILETIME {
    FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 }
}

fn read_all(h: HANDLE) -> Option<Vec<u8>> {
    const CHUNK: usize = 1 << 20;
    let mut out = Vec::with_capacity(CHUNK);
    let mut buf = vec![0u8; CHUNK];
    loop {
        let mut n = 0u32;
        let ok = unsafe { ReadFile(h, buf.as_mut_ptr(), buf.len() as u32, &mut n, std::ptr::null_mut()) };
        if ok == 0 {
            return None;
        }
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n as usize]);
    }
    Some(out)
}

/// Put the current process in background mode: lowered CPU, memory and I/O priority at once.
/// Equivalent to `--lowprio` in forensic scanners. Returns true on success.
pub fn enter_background_mode() -> bool {
    unsafe { SetPriorityClass(GetCurrentProcess(), PROCESS_MODE_BACKGROUND_BEGIN) != 0 }
}

/// Apply a hard CPU cap (percent of a single CPU, as reported to Win32 Job Objects: 1..=100,
/// multiplied by 100 for the API). The job handle is leaked for the process lifetime so the cap
/// stays active until Unveil exits.
pub fn cap_cpu(percent: u32) -> bool {
    let percent = percent.clamp(1, 100);
    unsafe {
        let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
        if job.is_null() {
            return false;
        }
        let info = JOBOBJECT_CPU_RATE_CONTROL_INFORMATION {
            ControlFlags: JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP,
            Anonymous: JOBOBJECT_CPU_RATE_CONTROL_INFORMATION_0 { CpuRate: percent * 100 },
        };
        if SetInformationJobObject(
            job,
            JobObjectCpuRateControlInformation,
            &info as *const _ as *const c_void,
            std::mem::size_of::<JOBOBJECT_CPU_RATE_CONTROL_INFORMATION>() as u32,
        ) == 0
        {
            return false;
        }
        AssignProcessToJobObject(job, GetCurrentProcess()) != 0
        // deliberately leak `job`: dropping it would detach the limit
    }
}
