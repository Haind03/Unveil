//! Cross-view process detection: brute-force PIDs with OpenProcess and compare with the
//! NtQuerySystemInformation list. A live process that only one view sees is hidden by a hook
//! or by DKOM (unlinked EPROCESS).

use std::collections::HashSet;

use windows_sys::Win32::System::Threading::{GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

use super::{procs, Handle};
use crate::core::report::{Category, Finding, Severity};

const STILL_ACTIVE: u32 = 259;
const MAX_PID: u32 = 1 << 20;

fn alive(pid: u32) -> Option<Handle> {
    let h = Handle::new(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) })?;
    let mut code = 0u32;
    (unsafe { GetExitCodeProcess(h.0, &mut code) } != 0 && code == STILL_ACTIVE).then_some(h)
}

pub fn scan(listed: &HashSet<u32>) -> Vec<Finding> {
    let mut candidates = Vec::new();
    for pid in (8..MAX_PID).step_by(4) {
        if listed.contains(&pid) {
            continue;
        }
        if alive(pid).is_some() {
            candidates.push(pid);
        }
    }
    if candidates.is_empty() {
        return Vec::new();
    }
    // Re-snapshot to rule out processes that started during the brute-force pass.
    let again: HashSet<u32> = procs::snapshot().iter().map(|p| p.pid).collect();
    let mut out = Vec::new();
    for pid in candidates {
        if again.contains(&pid) {
            continue;
        }
        let Some(h) = alive(pid) else { continue };
        let path = procs::image_path(h.0);
        let mut f = Finding::new(Severity::Critical, Category::Rootkit, "Hidden process (not in the system process list)")
            .detail("OpenProcess succeeds on this PID but NtQuerySystemInformation does not return it")
            .detail("typical of a user-mode hook on NtQuerySystemInformation or kernel DKOM")
            .mitre(&["T1014", "T1564"]);
        f.pid = Some(pid);
        f.process = Some(path.as_deref().map(crate::core::paths::file_name).unwrap_or("?").to_string());
        if let Some(p) = path {
            f = f.path(p);
        }
        out.push(f);
    }
    out
}
