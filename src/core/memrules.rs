//! Memory heuristics: injected code, reflective PE, hollowing, unbacked threads, DLL injection.

use std::collections::{BTreeMap, HashMap};

use super::paths::{normalize, suspicious_dir};
use super::report::{Category, Finding, Severity};
use super::{is_exec, prot_str, Module, Region, ThreadInfo, MEM_COMMIT, MEM_IMAGE, PAGE_EXECUTE_READWRITE};

/// Everything the memory rules need for one process.
pub struct MemView<'a> {
    pub pid: u32,
    pub name: &'a str,
    pub image_path: Option<&'a str>,
    pub regions: &'a [Region],
    pub modules: &'a [Module],
    pub threads: &'a [ThreadInfo],
    /// First bytes of each executable non-image region, keyed by region base.
    pub peeks: &'a HashMap<u64, Vec<u8>>,
    /// PEB->ImageBaseAddress.
    pub peb_image_base: Option<u64>,
    /// Mapped file of the image at peb_image_base (None = could not resolve).
    pub peb_image_file: Option<String>,
    /// Addresses of LoadLibraryA/W/ExA/ExW in this process.
    pub loadlib: &'a [u64],
    /// Process hosts a JIT (CLR, JVM, V8, ...), so private RX code is expected.
    pub jit: bool,
}

const JIT_MODULES: &[&str] = &[
    "clr.dll", "coreclr.dll", "mscorwks.dll", "jvm.dll", "chrome.dll", "msedge.dll", "xul.dll", "libcef.dll",
    "v8.dll", "node.dll", "electron.exe", "mono-2.0-bdwgc.dll", "jscript9.dll", "chakra.dll", "luajit.dll",
];

pub fn is_jit_process(name: &str, modules: &[Module]) -> bool {
    let n = name.to_ascii_lowercase();
    if ["chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "node.exe", "java.exe", "javaw.exe", "code.exe"]
        .contains(&n.as_str())
    {
        return true;
    }
    modules.iter().any(|m| JIT_MODULES.contains(&m.name().as_str()))
}

fn has_pe_header(b: &[u8]) -> Option<&'static str> {
    if b.len() >= 0x40 && &b[0..2] == b"MZ" {
        let lfanew = u32::from_le_bytes([b[0x3c], b[0x3d], b[0x3e], b[0x3f]]) as usize;
        if lfanew + 4 <= b.len() && &b[lfanew..lfanew + 4] == b"PE\0\0" {
            return Some("full PE header (MZ + PE)");
        }
    }
    // Header-stomped loaders wipe "MZ" but keep a recognisable NT header.
    let lim = b.len().min(0x400);
    for i in (0..lim.saturating_sub(6)).step_by(4) {
        if &b[i..i + 4] == b"PE\0\0" {
            let machine = u16::from_le_bytes([b[i + 4], b[i + 5]]);
            if machine == 0x8664 || machine == 0x014c {
                return Some("NT header without MZ (stomped PE header)");
            }
        }
    }
    None
}

/// Known first bytes of common shellcode stubs.
pub fn shellcode_signature(b: &[u8]) -> Option<&'static str> {
    const SIGS: &[(&[u8], &str)] = &[
        (&[0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8], "Metasploit/Cobalt Strike x64 stager prologue"),
        (&[0xFC, 0xE8, 0x82, 0x00, 0x00, 0x00], "Metasploit x86 block_api prologue"),
        (&[0xFC, 0xE8, 0x89, 0x00, 0x00, 0x00], "Metasploit/Cobalt Strike x86 stager prologue"),
        (&[0xFC, 0x48, 0x89, 0xCE], "Metasploit x64 reverse stager"),
        (&[0x4D, 0x5A, 0x41, 0x52, 0x55, 0x48, 0x89, 0xE5], "Cobalt Strike reflective beacon (MZARUH)"),
        (&[0x4D, 0x5A, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B], "Reflective DLL bootstrap (MZ call $+5)"),
        (&[0xE8, 0x00, 0x00, 0x00, 0x00, 0x59, 0x49, 0x89, 0xC8], "Donut/sRDI loader prologue"),
        (&[0x56, 0x48, 0x89, 0xE6, 0x48, 0x83, 0xE4, 0xF0], "sRDI / PIC x64 stack-align prologue"),
    ];
    SIGS.iter().find(|(s, _)| b.starts_with(s)).map(|(_, n)| *n)
}

pub fn analyze(v: &MemView) -> Vec<Finding> {
    let mut out = Vec::new();
    let mk = |sev, title: &str| Finding::new(sev, Category::Memory, title).proc(v.pid, v.name);

    let in_module = |a: u64| v.modules.iter().find(|m| m.contains(a));
    let region_of = |a: u64| v.regions.iter().find(|r| a >= r.base && a < r.base + r.size);

    // Executable non-image memory, grouped by allocation.
    struct Alloc {
        exec_size: u64,
        rwx: bool,
        prots: Vec<&'static str>,
        first_exec: u64,
        mapped: bool,
    }
    let mut allocs: BTreeMap<u64, Alloc> = BTreeMap::new();
    for r in v.regions.iter().filter(|r| r.state == MEM_COMMIT && r.kind != MEM_IMAGE && is_exec(r.protect)) {
        let a = allocs.entry(r.alloc_base).or_insert(Alloc {
            exec_size: 0,
            rwx: false,
            prots: Vec::new(),
            first_exec: r.base,
            mapped: r.kind == super::MEM_MAPPED,
        });
        a.exec_size += r.size;
        a.rwx |= r.protect & 0xff == PAGE_EXECUTE_READWRITE;
        let p = prot_str(r.protect);
        if !a.prots.contains(&p) {
            a.prots.push(p);
        }
        a.first_exec = a.first_exec.min(r.base);
    }

    for (base, a) in &allocs {
        let threads: Vec<&ThreadInfo> =
            v.threads.iter().filter(|t| region_of(t.start).is_some_and(|r| r.alloc_base == *base && r.kind != MEM_IMAGE)).collect();
        let peek = v.peeks.get(&a.first_exec).or_else(|| v.peeks.get(base));
        let pe = peek.and_then(|b| has_pe_header(b));
        let sc = peek.and_then(|b| shellcode_signature(b));

        let mut sev;
        let title;
        if let Some(sig) = sc {
            sev = Severity::Critical;
            title = format!("Known shellcode in {} memory: {sig}", if a.mapped { "mapped" } else { "private" });
        } else if let Some(kind) = pe {
            sev = if a.rwx { Severity::Critical } else { Severity::High };
            title = format!("Executable PE in unbacked memory ({kind}) - reflective / manual-mapped module");
        } else if !threads.is_empty() {
            sev = Severity::Critical;
            title = "Thread executing from unbacked memory".to_string();
        } else if v.jit {
            if !a.rwx {
                continue;
            }
            sev = Severity::Low;
            title = "RWX memory in JIT process".to_string();
        } else if a.rwx {
            sev = Severity::High;
            title = "RWX unbacked memory".to_string();
        } else {
            sev = Severity::Medium;
            title = "Executable unbacked memory".to_string();
        }
        if !threads.is_empty() && sev < Severity::Critical {
            sev = Severity::Critical;
        }
        let mut f = mk(sev, &title)
            .addr(*base)
            .detail(format!("{} KiB executable, protection {}", a.exec_size / 1024, a.prots.join("/")))
            .mitre(&["T1055"]);
        if pe.is_some() {
            f = f.mitre(&["T1620"]);
        }
        for t in &threads {
            f = f.detail(format!("thread {} starts at 0x{:x}", t.tid, t.start));
        }
        if let Some(b) = peek {
            f = f.detail(format!("first bytes: {}", hex(&b[..b.len().min(16)])));
        }
        out.push(f);
    }

    // Image pages flipped to RWX (inline patching, module stomping in progress).
    let mut seen = std::collections::HashSet::new();
    for r in v.regions.iter().filter(|r| r.state == MEM_COMMIT && r.kind == MEM_IMAGE && r.protect & 0xff == PAGE_EXECUTE_READWRITE) {
        if !seen.insert(r.alloc_base) {
            continue;
        }
        let m = in_module(r.base).map(|m| m.path.clone()).unwrap_or_else(|| "?".into());
        if v.jit {
            continue;
        }
        out.push(
            mk(Severity::Medium, "Image code page made writable (RWX)")
                .addr(r.base)
                .path(m)
                .detail("image sections are never RWX on disk; something called VirtualProtect on code")
                .mitre(&["T1055", "T1562.001"]),
        );
    }

    // Main image checks (hollowing / ghosting / doppelganging).
    if let Some(ib) = v.peb_image_base {
        match region_of(ib) {
            Some(r) if r.kind != MEM_IMAGE => out.push(
                mk(Severity::Critical, "Process hollowing: PEB image base points to non-image memory")
                    .addr(ib)
                    .detail(format!("region type 0x{:x}, protection {}", r.kind, prot_str(r.protect)))
                    .mitre(&["T1055.012"]),
            ),
            Some(_) => match (&v.peb_image_file, v.image_path) {
                (None, _) => out.push(
                    mk(Severity::High, "Main image is not backed by a resolvable file")
                        .addr(ib)
                        .detail("file deleted, in a rolled-back transaction, or ghosted")
                        .mitre(&["T1055.013", "T1055.012"]),
                ),
                (Some(mapped), Some(img)) if normalize(mapped) != normalize(img) => out.push(
                    mk(Severity::Critical, "Main image mapped from a different file than the process path")
                        .addr(ib)
                        .detail(format!("process path: {img}"))
                        .detail(format!("mapped file:  {mapped}"))
                        .mitre(&["T1055.012", "T1055.013"]),
                ),
                _ => {}
            },
            None => out.push(
                mk(Severity::High, "PEB image base is unmapped")
                    .addr(ib)
                    .detail("original image was unmapped (NtUnmapViewOfSection) - hollowing")
                    .mitre(&["T1055.012"]),
            ),
        }
    }

    // Thread start addresses.
    for t in v.threads {
        if t.start == 0 {
            continue;
        }
        if v.loadlib.contains(&t.start) {
            out.push(
                mk(Severity::High, "Thread started at LoadLibrary (remote DLL injection)")
                    .addr(t.start)
                    .detail(format!("thread {}", t.tid))
                    .mitre(&["T1055.001"]),
            );
            continue;
        }
        let r = region_of(t.start);
        if r.is_none() || r.is_some_and(|r| r.state != MEM_COMMIT) {
            out.push(
                mk(Severity::High, "Thread start address is not in committed memory")
                    .addr(t.start)
                    .detail(format!("thread {} (memory freed after start, or start address spoofed)", t.tid))
                    .mitre(&["T1055"]),
            );
        }
        // Start in non-image memory is reported with its allocation above.
    }

    // Modules from user-writable places, or whose file is gone.
    for m in v.modules.iter().filter(|m| Some(m.base) != v.peb_image_base) {
        if let Some(why) = suspicious_dir(&m.path) {
            out.push(
                mk(Severity::Medium, "DLL loaded from a user-writable location")
                    .path(m.path.clone())
                    .addr(m.base)
                    .detail(why)
                    .mitre(&["T1574.002", "T1574.001"]),
            );
        }
    }

    out
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::super::{MEM_PRIVATE, PAGE_EXECUTE_READ};
    use super::*;

    fn region(base: u64, size: u64, protect: u32, kind: u32) -> Region {
        Region { base, alloc_base: base, size, state: MEM_COMMIT, protect, alloc_protect: protect, kind }
    }

    fn view<'a>(
        regions: &'a [Region],
        modules: &'a [Module],
        threads: &'a [ThreadInfo],
        peeks: &'a HashMap<u64, Vec<u8>>,
    ) -> MemView<'a> {
        MemView {
            pid: 1,
            name: "notepad.exe",
            image_path: Some(r"C:\Windows\System32\notepad.exe"),
            regions,
            modules,
            threads,
            peeks,
            peb_image_base: None,
            peb_image_file: None,
            loadlib: &[],
            jit: false,
        }
    }

    #[test]
    fn reflective_pe_and_thread() {
        let mut pe = vec![0u8; 0x200];
        pe[0] = b'M';
        pe[1] = b'Z';
        pe[0x3c] = 0x80;
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        let regions = [region(0x1000_0000, 0x10000, PAGE_EXECUTE_READWRITE, MEM_PRIVATE)];
        let threads = [ThreadInfo { tid: 7, start: 0x1000_1000 }];
        let peeks = HashMap::from([(0x1000_0000u64, pe)]);
        let f = analyze(&view(&regions, &[], &threads, &peeks));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Critical);
        assert!(f[0].title.contains("PE"));
    }

    #[test]
    fn shellcode_prologue() {
        let regions = [region(0x2000_0000, 0x1000, PAGE_EXECUTE_READ, MEM_PRIVATE)];
        let peeks = HashMap::from([(0x2000_0000u64, vec![0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0])]);
        let f = analyze(&view(&regions, &[], &[], &peeks));
        assert!(f[0].title.contains("shellcode"));
    }

    #[test]
    fn jit_rx_ignored() {
        let regions = [region(0x3000_0000, 0x1000, PAGE_EXECUTE_READ, MEM_PRIVATE)];
        let peeks = HashMap::new();
        let mut v = view(&regions, &[], &[], &peeks);
        v.jit = true;
        assert!(analyze(&v).is_empty());
    }

    #[test]
    fn hollowing() {
        let regions = [region(0x40_0000, 0x1000, PAGE_EXECUTE_READWRITE, MEM_PRIVATE)];
        let peeks = HashMap::new();
        let mut v = view(&regions, &[], &[], &peeks);
        v.peb_image_base = Some(0x40_0000);
        let f = analyze(&v);
        assert!(f.iter().any(|f| f.title.contains("hollowing")));
    }

    #[test]
    fn mapped_mismatch() {
        let regions = [region(0x40_0000, 0x1000, PAGE_EXECUTE_READ, MEM_IMAGE)];
        let peeks = HashMap::new();
        let mut v = view(&regions, &[], &[], &peeks);
        v.peb_image_base = Some(0x40_0000);
        v.peb_image_file = Some(r"C:\Users\x\AppData\Local\Temp\evil.exe".into());
        let f = analyze(&v);
        assert!(f.iter().any(|f| f.title.contains("different file")));
    }
}
