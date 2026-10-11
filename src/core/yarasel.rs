//! YARA helpers that do not depend on the engine: which memory to scan, how rule metadata maps to
//! a severity, which ATT&CK IDs a rule declares, and which embedded files are rule sources.

use std::collections::{BTreeMap, HashSet};
use std::sync::Mutex;

use super::report::Severity;
use super::{is_exec, is_writable_exec, Region, MEM_COMMIT, MEM_IMAGE, PAGE_GUARD, PAGE_NOACCESS};

/// Largest single allocation read for a memory scan.
pub const MAX_REGION: u64 = 32 << 20;
/// Memory budget per process, so one bloated process cannot stall the scan.
pub const MAX_PER_PROCESS: u64 = 128 << 20;
/// Larger files are skipped (installers, archives): not what an autostart payload looks like.
pub const MAX_FILE: u64 = 64 << 20;

/// Engine-neutral copy of a rule metadata value.
#[derive(Debug, Clone, PartialEq)]
pub enum Meta {
    Int(i64),
    Float(f64),
    Bool(bool),
    Str(String),
}

/// A memory range to scan: one allocation, from its base (which keeps a reflectively loaded
/// module's PE header in view for `pe`-module rules) to the end of its last executable region.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Span {
    pub alloc_base: u64,
    pub len: u64,
    /// Committed executable bytes inside the range.
    pub exec_bytes: u64,
    pub rwx: bool,
}

/// Executable memory that does not belong to a mapped image: private or mapped-data allocations
/// that hold code. That is where injected payloads, shellcode and reflective DLLs live.
/// In a JIT host (browser, CLR, JVM) private RX code is normal, so only allocations with RWX
/// pages are kept unless `deep` is set. Each range is capped at `MAX_REGION` and the sum at
/// `MAX_PER_PROCESS`.
pub fn suspicious_spans(regions: &[Region], jit: bool, deep: bool) -> Vec<Span> {
    let mut by_alloc: BTreeMap<u64, Span> = BTreeMap::new();
    for r in regions {
        if r.state != MEM_COMMIT || r.kind == MEM_IMAGE || !is_exec(r.protect) {
            continue;
        }
        if r.protect & PAGE_GUARD != 0 || r.protect & 0xff == PAGE_NOACCESS {
            continue;
        }
        let s = by_alloc.entry(r.alloc_base).or_insert(Span { alloc_base: r.alloc_base, len: 0, exec_bytes: 0, rwx: false });
        s.len = s.len.max((r.base + r.size).saturating_sub(r.alloc_base));
        s.exec_bytes += r.size;
        s.rwx |= is_writable_exec(r.protect);
    }
    let mut out = Vec::new();
    let mut budget = MAX_PER_PROCESS;
    for (_, mut s) in by_alloc {
        if budget == 0 {
            break;
        }
        if jit && !deep && !s.rwx {
            continue;
        }
        s.len = s.len.min(MAX_REGION).min(budget);
        budget -= s.len;
        out.push(s);
    }
    out
}

fn from_score(n: f64) -> Severity {
    if n >= 90.0 {
        Severity::Critical
    } else if n >= 75.0 {
        Severity::High
    } else if n >= 60.0 {
        Severity::Medium
    } else if n >= 40.0 {
        Severity::Low
    } else {
        Severity::Info
    }
}

fn num(v: &Meta) -> Option<f64> {
    match v {
        Meta::Int(i) => Some(*i as f64),
        Meta::Float(f) => Some(*f),
        Meta::Str(s) => s.trim().parse::<f64>().ok(),
        Meta::Bool(_) => None,
    }
}

/// Severity of a rule match from its metadata.
///
/// * `score` (signature-base, Unveil) and numeric `severity` (Elastic) are 0-100:
///   >=90 critical, >=75 high, >=60 medium, >=40 low, below that info.
/// * textual `severity` / `threat_level` ("high", "critical"...) is taken as is.
/// * ReversingLabs: `category = "MALWARE"` is high, `"INFO"` is info.
/// * No usable metadata: medium.
///
/// A hit in injected (unbacked executable) memory is one level more serious than the same hit
/// in a file: the code is running.
pub fn severity(meta: &[(String, Meta)], in_memory: bool) -> Severity {
    let get = |k: &str| meta.iter().find(|(n, _)| n.eq_ignore_ascii_case(k)).map(|(_, v)| v);
    let mut sev = None;
    for k in ["score", "severity", "threat_level"] {
        if let Some(v) = get(k) {
            if let Some(n) = num(v) {
                sev = Some(from_score(n));
                break;
            }
            if let Meta::Str(s) = v {
                if let Some(s) = Severity::parse(s.trim()) {
                    sev = Some(s);
                    break;
                }
            }
        }
    }
    if sev.is_none() {
        if let Some(Meta::Str(c)) = get("category") {
            sev = match c.to_ascii_uppercase().as_str() {
                "MALWARE" => Some(Severity::High),
                "INFO" => Some(Severity::Info),
                _ => None,
            };
        }
    }
    let sev = sev.unwrap_or(Severity::Medium);
    if in_memory { sev.bump() } else { sev }
}

/// Text of the first metadata key that exists and is a string.
pub fn meta_str<'a>(meta: &'a [(String, Meta)], keys: &[&str]) -> Option<&'a str> {
    keys.iter().find_map(|k| match meta.iter().find(|(n, _)| n.eq_ignore_ascii_case(k)) {
        Some((_, Meta::Str(s))) if !s.trim().is_empty() => Some(s.as_str()),
        _ => None,
    })
}

fn is_technique(t: &str) -> bool {
    let b = t.as_bytes();
    let base = b.len() >= 5 && b[0] == b'T' && b[1..5].iter().all(u8::is_ascii_digit);
    base && (b.len() == 5 || (b.len() == 9 && b[5] == b'.' && b[6..].iter().all(u8::is_ascii_digit)))
}

/// Interned so `Finding::mitre` can keep `&'static str`. Bounded by the set of IDs in the rules.
fn intern(s: &str) -> &'static str {
    static POOL: Mutex<Option<HashSet<&'static str>>> = Mutex::new(None);
    let mut g = POOL.lock().unwrap();
    let set = g.get_or_insert_with(HashSet::new);
    if let Some(v) = set.get(s) {
        return v;
    }
    let v: &'static str = Box::leak(s.to_string().into_boxed_str());
    set.insert(v);
    v
}

/// ATT&CK technique IDs declared in `mitre`, `mitre_att`, `mitre_attack` or `technique` metadata.
pub fn mitre_ids(meta: &[(String, Meta)]) -> Vec<&'static str> {
    let mut out = Vec::new();
    for (k, v) in meta {
        let k = k.to_ascii_lowercase();
        if !(k == "mitre" || k.starts_with("mitre_att") || k == "technique") {
            continue;
        }
        let Meta::Str(s) = v else { continue };
        for t in s.split(|c: char| !(c.is_ascii_alphanumeric() || c == '.')) {
            let t = t.to_ascii_uppercase();
            if is_technique(&t) {
                let t = intern(&t);
                if !out.contains(&t) {
                    out.push(t);
                }
            }
        }
    }
    out
}

/// YARA namespace for a rule file: its path relative to the rules root, without extension,
/// with anything outside `[A-Za-z0-9_]` replaced. One namespace per file keeps identical rule
/// names in different sources from clashing.
pub fn namespace(rel: &str) -> String {
    let stem = rel.rsplit_once('.').map(|(s, _)| s).unwrap_or(rel);
    let mut ns: String = stem.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect();
    if ns.is_empty() || ns.as_bytes()[0].is_ascii_digit() {
        ns.insert(0, '_');
    }
    ns
}

pub fn is_rule_file(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.ends_with(".yar") || n.ends_with(".yara")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{MEM_PRIVATE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE};

    fn reg(base: u64, alloc: u64, size: u64, protect: u32, kind: u32) -> Region {
        Region { base, alloc_base: alloc, size, state: MEM_COMMIT, protect, alloc_protect: protect, kind }
    }

    fn m(k: &str, v: Meta) -> (String, Meta) {
        (k.to_string(), v)
    }

    #[test]
    fn spans_skip_images_and_group_by_allocation() {
        let regions = vec![
            reg(0x1000, 0x1000, 0x1000, PAGE_EXECUTE_READ, MEM_IMAGE),
            reg(0x10000, 0x10000, 0x1000, 0x02, MEM_PRIVATE), // R header page of a reflective DLL
            reg(0x11000, 0x10000, 0x1000, PAGE_EXECUTE_READ, MEM_PRIVATE),
            reg(0x12000, 0x10000, 0x2000, PAGE_EXECUTE_READWRITE, MEM_PRIVATE),
            reg(0x20000, 0x20000, 0x1000, 0x04, MEM_PRIVATE), // RW, not code
            reg(0x30000, 0x30000, 0x1000, PAGE_EXECUTE_READ | PAGE_GUARD, MEM_PRIVATE),
        ];
        let s = suspicious_spans(&regions, false, false);
        assert_eq!(s, vec![Span { alloc_base: 0x10000, len: 0x4000, exec_bytes: 0x3000, rwx: true }]);
    }

    #[test]
    fn jit_keeps_only_rwx_unless_deep() {
        let regions = vec![
            reg(0x10000, 0x10000, 0x1000, PAGE_EXECUTE_READ, MEM_PRIVATE),
            reg(0x20000, 0x20000, 0x1000, PAGE_EXECUTE_READWRITE, MEM_PRIVATE),
        ];
        let s = suspicious_spans(&regions, true, false);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].alloc_base, 0x20000);
        assert_eq!(suspicious_spans(&regions, true, true).len(), 2);
    }

    #[test]
    fn spans_respect_size_caps() {
        let big = MAX_REGION * 2;
        let regions: Vec<Region> = (1..=10u64).map(|i| reg(i << 40, i << 40, big, PAGE_EXECUTE_READ, MEM_PRIVATE)).collect();
        let s = suspicious_spans(&regions, false, false);
        assert!(s.iter().all(|x| x.len <= MAX_REGION));
        assert_eq!(s.iter().map(|x| x.len).sum::<u64>(), MAX_PER_PROCESS);
        assert_eq!(s.len() as u64, MAX_PER_PROCESS / MAX_REGION);
    }

    #[test]
    fn severity_from_metadata() {
        assert_eq!(severity(&[m("score", Meta::Int(40))], false), Severity::Low);
        assert_eq!(severity(&[m("score", Meta::Int(70))], false), Severity::Medium);
        assert_eq!(severity(&[m("score", Meta::Int(80))], false), Severity::High);
        assert_eq!(severity(&[m("score", Meta::Str("95".into()))], false), Severity::Critical);
        assert_eq!(severity(&[m("severity", Meta::Int(100))], false), Severity::Critical);
        assert_eq!(severity(&[m("severity", Meta::Int(50))], false), Severity::Low);
        assert_eq!(severity(&[m("severity", Meta::Str("High".into()))], false), Severity::High);
        assert_eq!(severity(&[m("category", Meta::Str("MALWARE".into()))], false), Severity::High);
        assert_eq!(severity(&[m("category", Meta::Str("INFO".into()))], false), Severity::Info);
        assert_eq!(severity(&[m("author", Meta::Str("x".into()))], false), Severity::Medium);
        // Same rule in injected memory is one level higher.
        assert_eq!(severity(&[m("score", Meta::Int(70))], true), Severity::High);
        assert_eq!(severity(&[m("severity", Meta::Int(100))], true), Severity::Critical);
    }

    #[test]
    fn score_wins_over_category() {
        let meta = [m("category", Meta::Str("INFO".into())), m("score", Meta::Int(85))];
        assert_eq!(severity(&meta, false), Severity::High);
    }

    #[test]
    fn mitre_ids_are_validated_and_deduplicated() {
        let meta = [
            m("mitre", Meta::Str("T1055.012, T1106".into())),
            m("mitre_att", Meta::Str("t1106 Tx123 T12345".into())),
            m("author", Meta::Str("T1000".into())),
        ];
        assert_eq!(mitre_ids(&meta), vec!["T1055.012", "T1106"]);
    }

    #[test]
    fn namespaces_are_identifiers() {
        assert_eq!(namespace("custom/unveil.yar"), "custom_unveil");
        assert_eq!(namespace("signature-base/apt_x.yara"), "signature_base_apt_x");
        assert_eq!(namespace("1st.yar"), "_1st");
        assert!(is_rule_file("A.YAR") && is_rule_file("b.yara") && !is_rule_file("LICENSE"));
    }

    #[test]
    fn meta_str_picks_first_present() {
        let meta = [m("description", Meta::Str("".into())), m("threat_name", Meta::Str("Win.Trojan.X".into()))];
        assert_eq!(meta_str(&meta, &["description", "threat_name"]), Some("Win.Trojan.X"));
    }
}
