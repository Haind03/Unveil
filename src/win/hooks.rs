//! Inline hook / patch detection: diff executable sections in memory against the file on disk.

use windows_sys::Win32::Foundation::HANDLE;

use super::memory::ProcMem;
use super::{read_mem, read_mem_sparse, read_u32, read_u64, FileCache};
use crate::core::hookrules::{self, HookCtx, Target};
use crate::core::pecmp::{self, DiskImage};
use crate::core::report::Finding;
use crate::core::{is_exec, Module, ProcInfo, SigStatus, MEM_IMAGE};

/// Modules whose code is checked in every process. Covers syscall stubs, ETW, AMSI and Win32 APIs.
const ALWAYS: &[&str] = &["ntdll.dll", "kernel32.dll", "kernelbase.dll", "amsi.dll", "advapi32.dll", "sechost.dll", "user32.dll", "ws2_32.dll", "wldp.dll"];

/// Upper bound per section so a huge module cannot stall the scan.
const MAX_SECTION: u32 = 16 << 20;

pub fn analyze(p: &ProcInfo, h: HANDLE, pm: &ProcMem, cache: &mut FileCache, deep: bool, self_pid: u32) -> Vec<Finding> {
    let mut out = Vec::new();
    let main_base = super::procs::peb_image_base(h).map(|(_, b)| b);
    for m in &pm.images {
        if m.path.is_empty() {
            continue;
        }
        let name = m.name();
        if !(deep || ALWAYS.contains(&name.as_str()) || Some(m.base) == main_base) {
            continue;
        }
        out.extend(scan_module(p, h, pm, m, cache, self_pid));
    }
    out
}

fn scan_module(p: &ProcInfo, h: HANDLE, pm: &ProcMem, m: &Module, cache: &mut FileCache, self_pid: u32) -> Vec<Finding> {
    let Some(data) = cache.get(&m.path) else { return Vec::new() };
    let Some(img) = DiskImage::parse(&data) else { return Vec::new() };
    // The file on disk was replaced since load (update pending reboot): comparison is meaningless.
    let soi = img.size_of_image() as u64;
    if soi == 0 || (soi + 0xfff) & !0xfff != (m.size + 0xfff) & !0xfff {
        return Vec::new();
    }
    if let Some(hdr) = read_mem(h, m.base, 0x400) {
        if let Some(mi) = DiskImage::parse(&hdr) {
            if mi.timestamp() != img.timestamp() {
                return Vec::new();
            }
        }
    }

    let relocs = img.relocations();
    let volatile = img.volatile_ranges();
    let mut patches = Vec::new();
    for s in img.exec_sections() {
        let len = s.size.min(MAX_SECTION) as usize;
        let mem = read_mem_sparse(h, m.base + s.rva as u64, len);
        if mem.iter().all(|b| b.is_none()) {
            continue;
        }
        let exp = img.expected(s.rva, len, m.base, &relocs);
        patches.extend(pecmp::diff(s.rva, &mem, &exp, &volatile));
    }
    if patches.is_empty() {
        return Vec::new();
    }

    let exports = img.exports();
    let is64 = img.is_64();
    let read_ptr = |a: u64| if is64 { read_u64(h, a) } else { read_u32(h, a).map(u64::from) };
    let target_of = |addr: u64| -> Option<(u64, Target)> {
        // Re-read from the function start so the decoder sees the whole instruction.
        let b = read_mem(h, addr, 16)?;
        let dest = hookrules::decode_jump(&b, addr, is64, &read_ptr)?;
        if let Some(t) = pm.image_of(dest) {
            let signer = match super::sig::check(&t.path) {
                SigStatus::Signed(s) => Some(s.unwrap_or_else(|| "signed".into())),
                _ => None,
            };
            return Some((dest, Target::Module(t.name(), signer)));
        }
        match pm.region_of(dest) {
            Some(r) if r.kind != MEM_IMAGE && is_exec(r.protect) => Some((dest, Target::Unbacked)),
            _ => Some((dest, Target::Unknown)),
        }
    };
    let ctx = HookCtx {
        pid: p.pid,
        process: &p.name,
        module: &m.path,
        module_base: m.base,
        exports: &exports,
        self_scan: p.pid == self_pid,
    };
    hookrules::classify(&ctx, &patches, &target_of)
}
