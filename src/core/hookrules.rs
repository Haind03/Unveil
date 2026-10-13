//! Turn raw code patches into findings: inline hooks, ETW/AMSI patches, module stomping.

use super::memrules::hex;
use super::pecmp::Patch;
use super::report::{Category, Finding, Severity};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// Inside a loaded module (file name, signer if known).
    Module(String, Option<String>),
    /// Executable memory not backed by any file.
    Unbacked,
    Unknown,
}

/// Decode a jump/trampoline at the start of `b` (located at `addr`). Returns the destination.
/// `read_ptr` reads a pointer from the target process (for `jmp [rip+x]`).
pub fn decode_jump(b: &[u8], addr: u64, is64: bool, read_ptr: &dyn Fn(u64) -> Option<u64>) -> Option<u64> {
    let i32_at = |o: usize| b.get(o..o + 4).map(|s| i32::from_le_bytes(s.try_into().unwrap()) as i64);
    let u64_at = |o: usize| b.get(o..o + 8).map(|s| u64::from_le_bytes(s.try_into().unwrap()));
    let u32_at = |o: usize| b.get(o..o + 4).map(|s| u32::from_le_bytes(s.try_into().unwrap()) as u64);
    match b {
        [0xE9, ..] => Some((addr as i64 + 5 + i32_at(1)?) as u64),
        [0xEB, r, ..] => Some((addr as i64 + 2 + *r as i8 as i64) as u64),
        [0xFF, 0x25, ..] if is64 => read_ptr((addr as i64 + 6 + i32_at(2)?) as u64),
        [0xFF, 0x25, ..] => read_ptr(u32_at(2)?),
        [0x48, 0xB8, ..] if b.get(10..12) == Some(&[0xFF, 0xE0]) => u64_at(2),
        [0x49, 0xBB, ..] if b.get(10..13) == Some(&[0x41, 0xFF, 0xE3]) => u64_at(2),
        [0x49, 0xBA, ..] if b.get(10..13) == Some(&[0x41, 0xFF, 0xE2]) => u64_at(2),
        [0x68, ..] if b.get(5) == Some(&0xC3) => u32_at(1),
        [0xB8, ..] if b.get(5..7) == Some(&[0xFF, 0xE0]) => u32_at(1),
        _ => None,
    }
}

/// Patches that neutralise a function by returning immediately.
pub fn early_return(b: &[u8]) -> Option<&'static str> {
    const P: &[(&[u8], &str)] = &[
        (&[0xC3], "ret"),
        (&[0xC2], "ret n"),
        (&[0x33, 0xC0, 0xC3], "xor eax,eax; ret"),
        (&[0x31, 0xC0, 0xC3], "xor eax,eax; ret"),
        (&[0x48, 0x33, 0xC0, 0xC3], "xor rax,rax; ret"),
        (&[0x48, 0x31, 0xC0, 0xC3], "xor rax,rax; ret"),
        (&[0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3], "mov eax,E_INVALIDARG; ret"),
        (&[0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2], "mov eax,E_INVALIDARG; ret n"),
        (&[0x31, 0xC0, 0xC2], "xor eax,eax; ret n"),
        (&[0x33, 0xC0, 0xC2], "xor eax,eax; ret n"),
    ];
    P.iter().find(|(p, _)| b.starts_with(p)).map(|(_, n)| *n)
}

const ETW_FUNCS: &[&str] = &[
    "EtwEventWrite", "EtwEventWriteFull", "EtwEventWriteTransfer", "EtwEventWriteEx", "EtwEventWriteString",
    "NtTraceEvent", "ZwTraceEvent", "EtwNotificationRegister", "EtwEventRegister",
];
const AMSI_FUNCS: &[&str] = &["AmsiScanBuffer", "AmsiScanString", "AmsiOpenSession", "AmsiInitialize", "AmsiUacScan"];

pub struct HookCtx<'a> {
    pub pid: u32,
    pub process: &'a str,
    pub module: &'a str,
    pub module_base: u64,
    pub exports: &'a [(u32, String)],
    pub self_scan: bool,
    /// True when we are diffing the 32-bit `ntdll.dll` of a WOW64 process. Every Zw* syscall
    /// stub there is a 4-byte jump into `wow64cpu.dll`'s private thunk, by design: those are
    /// not EDR hooks and must not be reported as "Syscall stub modified".
    pub wow64_ntdll: bool,
}

/// Nearest export at or before `rva` (within 64 bytes counts as "at the function start").
fn func_for(exports: &[(u32, String)], rva: u32) -> Option<(&str, u32)> {
    let i = exports.partition_point(|(r, _)| *r <= rva);
    if i == 0 {
        return None;
    }
    let (r, n) = &exports[i - 1];
    Some((n.as_str(), rva - r))
}

/// Classify all patches of one module. Large modified areas collapse into one stomping finding.
pub fn classify(ctx: &HookCtx, patches: &[Patch], target_of: &dyn Fn(u64) -> Option<(u64, Target)>) -> Vec<Finding> {
    let mut out = Vec::new();
    let total: usize = patches.iter().map(|p| p.mem.len()).sum();
    let mk = |sev, title: String| Finding::new(sev, Category::Hook, title).proc(ctx.pid, ctx.process).path(ctx.module.to_string());

    if total >= 4096 {
        out.push(
            mk(Severity::Critical, format!("Module stomping: {total} bytes of code differ from disk"))
                .addr(ctx.module_base + patches[0].rva as u64)
                .detail(format!("{} modified ranges in {}", patches.len(), ctx.module))
                .mitre(&["T1055.001", "T1620"]),
        );
        return out;
    }

    let mut generic = 0usize;
    for p in patches {
        let addr = ctx.module_base + p.rva as u64;
        let func = func_for(ctx.exports, p.rva);
        let fname = func.map(|(n, off)| if off == 0 { n.to_string() } else { format!("{n}+0x{off:x}") });
        let short = func.map(|(n, _)| n).unwrap_or("");
        let near_start = func.is_some_and(|(_, off)| off < 32);

        let is_etw = ETW_FUNCS.contains(&short);
        let is_amsi = AMSI_FUNCS.contains(&short);
        let ret = early_return(&p.mem);
        let tgt = target_of(addr);

        let label = fname.clone().unwrap_or_else(|| format!("rva 0x{:x}", p.rva));
        let bytes = format!("memory {} | disk {}", hex(&p.mem[..p.mem.len().min(16)]), hex(&p.disk[..p.disk.len().min(16)]));

        if is_etw && near_start {
            out.push(
                mk(Severity::High, format!("ETW patched: {label}"))
                    .addr(addr)
                    .detail(bytes)
                    .detail(ret.map(|r| format!("patched to '{r}'")).unwrap_or_else(|| "prologue modified".into()))
                    .mitre(&["T1562.006"]),
            );
            continue;
        }
        if is_amsi && near_start {
            out.push(
                mk(Severity::Critical, format!("AMSI patched: {label}"))
                    .addr(addr)
                    .detail(bytes)
                    .detail(ret.map(|r| format!("patched to '{r}'")).unwrap_or_else(|| "prologue modified".into()))
                    .mitre(&["T1562.001"]),
            );
            continue;
        }

        match tgt {
            Some((dest, Target::Unbacked)) => out.push(
                mk(Severity::Critical, format!("Inline hook into unbacked memory: {label}"))
                    .addr(addr)
                    .detail(format!("jumps to 0x{dest:x} (no file backs this code)"))
                    .detail(bytes)
                    .mitre(&["T1055", "T1014"]),
            ),
            Some((dest, Target::Module(m, signer))) => {
                let signed = signer.is_some();
                let sev = if ctx.self_scan {
                    Severity::High
                } else if signed {
                    Severity::Low
                } else {
                    Severity::High
                };
                let mut f = mk(sev, format!("Inline hook: {label} -> {m}"))
                    .addr(addr)
                    .detail(format!("jumps to 0x{dest:x} in {m} ({})", signer.as_deref().unwrap_or("unsigned")))
                    .detail(bytes)
                    .mitre(&["T1056.004"]);
                if signed {
                    f = f.detail("signed hooking module - usually an EDR/AV or accessibility tool, verify the vendor");
                }
                if ctx.self_scan {
                    f = f.detail("the scanner itself is hooked - results may be manipulated");
                }
                out.push(f);
            }
            _ if ret.is_some() && near_start => out.push(
                mk(Severity::High, format!("Function neutralised: {label}"))
                    .addr(addr)
                    .detail(format!("patched to '{}'", ret.unwrap()))
                    .detail(bytes)
                    .mitre(&["T1562.001"]),
            ),
            _ if short.starts_with("Nt") || short.starts_with("Zw") => {
                // In a WOW64 process the 32-bit ntdll stubs always redirect into wow64cpu's
                // transition thunk - that is not a hook (see HookCtx::wow64_ntdll).
                if ctx.wow64_ntdll {
                    continue;
                }
                out.push(
                    mk(Severity::Medium, format!("Syscall stub modified: {label}"))
                        .addr(addr)
                        .detail(bytes)
                        .mitre(&["T1562.001"]),
                );
            }
            _ => generic += 1,
        }
    }
    if generic > 0 {
        let first = patches.iter().find(|p| early_return(&p.mem).is_none()).unwrap_or(&patches[0]);
        out.push(
            mk(Severity::Medium, format!("Code modified in memory ({generic} ranges)"))
                .addr(ctx.module_base + first.rva as u64)
                .detail(format!("first at rva 0x{:x}: memory {} | disk {}", first.rva, hex(&first.mem[..first.mem.len().min(16)]), hex(&first.disk[..first.disk.len().min(16)])))
                .mitre(&["T1055"]),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_jumps() {
        let none = |_| None;
        assert_eq!(decode_jump(&[0xE9, 0x00, 0x10, 0x00, 0x00], 0x1000, true, &none), Some(0x2005));
        let b = [0x48, 0xB8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0xFF, 0xE0];
        assert_eq!(decode_jump(&b, 0, true, &none), Some(0x1122334455667788));
        let rd = |a: u64| (a == 0x1006 + 0x10).then_some(0xdead);
        assert_eq!(decode_jump(&[0xFF, 0x25, 0x10, 0, 0, 0], 0x1000, true, &rd), Some(0xdead));
    }

    #[test]
    fn classifies_amsi_and_etw() {
        let exports = vec![(0x100u32, "AmsiScanBuffer".to_string()), (0x200, "EtwEventWrite".to_string())];
        let ctx = HookCtx { pid: 1, process: "p.exe", module: "amsi.dll", module_base: 0x1000_0000, exports: &exports, self_scan: false, wow64_ntdll: false };
        let patches = vec![
            Patch { rva: 0x100, mem: vec![0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3], disk: vec![0x4C, 0x8B, 0xDC, 0x49, 0x89, 0x5B] },
            Patch { rva: 0x200, mem: vec![0xC3], disk: vec![0x4C] },
        ];
        let f = classify(&ctx, &patches, &|_| None);
        assert_eq!(f.len(), 2);
        assert!(f[0].title.starts_with("AMSI patched"));
        assert_eq!(f[0].severity, Severity::Critical);
        assert!(f[1].title.starts_with("ETW patched"));
    }

    #[test]
    fn unbacked_hook_is_critical() {
        let exports = vec![(0x100u32, "NtCreateThreadEx".to_string())];
        let ctx = HookCtx { pid: 1, process: "p.exe", module: "ntdll.dll", module_base: 0, exports: &exports, self_scan: false, wow64_ntdll: false };
        let patches = vec![Patch { rva: 0x100, mem: vec![0xE9, 1, 2, 3, 4], disk: vec![0x4C, 0x8B, 0xD1, 0xB8, 0xC1] }];
        let f = classify(&ctx, &patches, &|_| Some((0x5000, Target::Unbacked)));
        assert_eq!(f[0].severity, Severity::Critical);
    }
}
