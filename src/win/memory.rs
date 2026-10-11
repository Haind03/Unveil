//! Per-process memory collection: VAD walk, image list from VAD and from the loader, thread starts.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::c_void;

use windows_sys::Win32::Foundation::{HANDLE, HMODULE};
use windows_sys::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION};
use windows_sys::Win32::System::ProcessStatus::{EnumProcessModulesEx, GetMappedFileNameW, GetModuleFileNameExW, GetModuleInformation, LIST_MODULES_ALL, MODULEINFO};

use super::{device_to_dos, from_wide, read_mem};
use crate::core::memrules::{self, MemView};
use crate::core::pecmp::DiskImage;
use crate::core::report::{Category, Finding, Severity};
use crate::core::{is_exec, Module, ProcInfo, Region, ThreadInfo, MEM_COMMIT, MEM_IMAGE};

pub struct ProcMem {
    pub regions: Vec<Region>,
    /// Images found in the VAD (ground truth), with their mapped file.
    pub images: Vec<Module>,
    /// Modules the loader reports (PEB lists). Malware can unlink entries here.
    pub loader: Vec<Module>,
}

impl ProcMem {
    pub fn region_of(&self, a: u64) -> Option<&Region> {
        let i = self.regions.partition_point(|r| r.base + r.size <= a);
        self.regions.get(i).filter(|r| a >= r.base)
    }

    pub fn image_of(&self, a: u64) -> Option<&Module> {
        self.images.iter().find(|m| m.contains(a))
    }
}

pub fn mapped_file(h: HANDLE, addr: u64) -> Option<String> {
    let mut buf = vec![0u16; 1024];
    let n = unsafe { GetMappedFileNameW(h, addr as *const c_void, buf.as_mut_ptr(), buf.len() as u32) };
    (n > 0).then(|| device_to_dos(&from_wide(&buf[..n as usize])))
}

pub fn collect(h: HANDLE) -> ProcMem {
    let mut regions = Vec::new();
    let mut addr: u64 = 0;
    let limit: u64 = 0x7FFF_FFFF_FFFF;
    while addr < limit {
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        let n = unsafe { VirtualQueryEx(h, addr as *const c_void, &mut mbi, std::mem::size_of::<MEMORY_BASIC_INFORMATION>()) };
        if n == 0 {
            break;
        }
        let base = mbi.BaseAddress as u64;
        let size = mbi.RegionSize as u64;
        if mbi.State == MEM_COMMIT {
            regions.push(Region {
                base,
                alloc_base: mbi.AllocationBase as u64,
                size,
                state: mbi.State,
                protect: mbi.Protect,
                alloc_protect: mbi.AllocationProtect,
                kind: mbi.Type,
            });
        }
        let next = base.saturating_add(size);
        if next <= addr {
            break;
        }
        addr = next;
    }

    // Images from the VAD: group MEM_IMAGE regions by allocation base.
    let mut spans: BTreeMap<u64, u64> = BTreeMap::new();
    for r in regions.iter().filter(|r| r.kind == MEM_IMAGE) {
        let e = spans.entry(r.alloc_base).or_insert(0);
        *e = (*e).max(r.base + r.size - r.alloc_base);
    }
    let images = spans
        .into_iter()
        .map(|(base, size)| Module { base, size, path: mapped_file(h, base).unwrap_or_default() })
        .collect();

    ProcMem { regions, images, loader: loader_modules(h) }
}

fn loader_modules(h: HANDLE) -> Vec<Module> {
    let mut mods: Vec<HMODULE> = vec![std::ptr::null_mut(); 1024];
    let mut needed = 0u32;
    let cb = (mods.len() * std::mem::size_of::<HMODULE>()) as u32;
    if unsafe { EnumProcessModulesEx(h, mods.as_mut_ptr(), cb, &mut needed, LIST_MODULES_ALL) } == 0 {
        return Vec::new();
    }
    let count = (needed as usize / std::mem::size_of::<HMODULE>()).min(mods.len());
    let mut out = Vec::with_capacity(count);
    for &m in &mods[..count] {
        let mut info: MODULEINFO = unsafe { std::mem::zeroed() };
        if unsafe { GetModuleInformation(h, m, &mut info, std::mem::size_of::<MODULEINFO>() as u32) } == 0 {
            continue;
        }
        let mut buf = vec![0u16; 1024];
        let n = unsafe { GetModuleFileNameExW(h, m, buf.as_mut_ptr(), buf.len() as u32) };
        out.push(Module {
            base: info.lpBaseOfDll as u64,
            size: info.SizeOfImage as u64,
            path: device_to_dos(&from_wide(&buf[..n as usize])),
        });
    }
    out
}

/// LoadLibrary* entry points inside this process (for thread-start checks).
fn loadlibrary_addrs(pm: &ProcMem, cache: &super::FileCache) -> Vec<u64> {
    let mut out = Vec::new();
    for m in &pm.images {
        let n = m.name();
        if n != "kernel32.dll" && n != "kernelbase.dll" {
            continue;
        }
        let Some(data) = cache.get(&m.path) else { continue };
        let Some(img) = DiskImage::parse(&data) else { continue };
        for f in ["LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW"] {
            if let Some(rva) = img.export_rva(f) {
                out.push(m.base + rva as u64);
            }
        }
    }
    out
}

pub fn analyze(p: &ProcInfo, h: HANDLE, pm: &ProcMem, cache: &super::FileCache) -> Vec<Finding> {
    let threads: Vec<ThreadInfo> =
        p.threads.iter().filter_map(|&tid| super::procs::thread_start(tid).map(|start| ThreadInfo { tid, start })).collect();

    // Peek at the start of every executable non-image region (and its allocation base).
    let mut peeks: HashMap<u64, Vec<u8>> = HashMap::new();
    let mut seen_alloc = HashSet::new();
    for r in pm.regions.iter().filter(|r| r.kind != MEM_IMAGE && is_exec(r.protect)) {
        if let Some(b) = read_mem(h, r.base, 0x1000) {
            peeks.insert(r.base, b);
        }
        if r.alloc_base != r.base && seen_alloc.insert(r.alloc_base) {
            if let Some(b) = read_mem(h, r.alloc_base, 0x1000) {
                peeks.insert(r.alloc_base, b);
            }
        }
    }

    let peb = super::procs::peb_image_base(h);
    let peb_image_base = peb.map(|(_, ib)| ib);
    let peb_image_file = peb_image_base.and_then(|ib| mapped_file(h, ib));
    let loadlib = loadlibrary_addrs(pm, cache);
    let jit = memrules::is_jit_process(&p.name, &pm.images);

    let view = MemView {
        pid: p.pid,
        name: &p.name,
        image_path: p.path.as_deref(),
        regions: &pm.regions,
        modules: &pm.images,
        threads: &threads,
        peeks: &peeks,
        peb_image_base,
        peb_image_file,
        loadlib: &loadlib,
        jit,
    };
    let mut out = memrules::analyze(&view);

    // Images present in the VAD but missing from the loader lists: unlinked (hidden) DLLs.
    if !pm.loader.is_empty() && !jit {
        let known: HashSet<u64> = pm.loader.iter().map(|m| m.base).collect();
        for m in &pm.images {
            if known.contains(&m.base) || Some(m.base) == peb_image_base {
                continue;
            }
            let n = m.name();
            let lp = m.path.to_ascii_lowercase();
            // WOW64 plumbing and .NET native images are mapped without loader entries.
            if (p.wow64 && (n == "ntdll.dll" || n.starts_with("wow64")))
                || lp.contains("\\assembly\\")
                || lp.contains("\\microsoft.net\\")
                || n.ends_with(".ni.dll")
                || n.ends_with(".mui")
            {
                continue;
            }
            if m.path.is_empty() {
                out.push(
                    Finding::new(Severity::High, Category::Memory, "Image mapping with no backing file")
                        .proc(p.pid, &p.name)
                        .addr(m.base)
                        .detail(format!("{} KiB image, file deleted or transacted (phantom DLL / doppelganging)", m.size / 1024))
                        .mitre(&["T1055.013"]),
                );
                continue;
            }
            out.push(
                Finding::new(Severity::Medium, Category::Memory, "Mapped image hidden from the loader module list")
                    .proc(p.pid, &p.name)
                    .path(m.path.clone())
                    .addr(m.base)
                    .detail("present in the VAD but not in PEB/LDR lists: unlinked DLL or manual SEC_IMAGE mapping")
                    .mitre(&["T1055", "T1564"]),
            );
        }
    }

    // Main image header vs disk: catches herpaderping / overwritten images.
    if let (Some(ib), Some(path)) = (peb_image_base, p.path.as_deref()) {
        if let (Some(mem), Some(disk)) = (read_mem(h, ib, 0x1000), cache.get(path)) {
            if let (Some(mi), Some(di)) = (DiskImage::parse(&mem), DiskImage::parse(&disk)) {
                let mut diffs = Vec::new();
                if mi.entry_rva() != di.entry_rva() {
                    diffs.push(format!("entry point rva 0x{:x} in memory vs 0x{:x} on disk", mi.entry_rva(), di.entry_rva()));
                }
                if mi.size_of_image() != di.size_of_image() {
                    diffs.push(format!("SizeOfImage 0x{:x} vs 0x{:x}", mi.size_of_image(), di.size_of_image()));
                }
                if mi.timestamp() != di.timestamp() {
                    diffs.push(format!("TimeDateStamp 0x{:x} vs 0x{:x}", mi.timestamp(), di.timestamp()));
                }
                if !diffs.is_empty() {
                    let mut f = Finding::new(Severity::Critical, Category::Memory, "Main image in memory differs from the file on disk")
                        .proc(p.pid, &p.name)
                        .path(path.to_string())
                        .addr(ib)
                        .mitre(&["T1055.012", "T1055.013"]);
                    for d in diffs {
                        f = f.detail(d);
                    }
                    out.push(f);
                }
            } else if DiskImage::parse(&disk).is_some() && !mem.starts_with(b"MZ") {
                out.push(
                    Finding::new(Severity::High, Category::Memory, "Main image PE header wiped in memory")
                        .proc(p.pid, &p.name)
                        .addr(ib)
                        .detail(format!("first bytes: {}", memrules::hex(&mem[..16.min(mem.len())])))
                        .mitre(&["T1055.012", "T1027"]),
                );
            }
        }
    }
    out
}
