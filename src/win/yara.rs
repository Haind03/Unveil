//! YARA scanning of live process memory (suspicious executable allocations) and of files on disk
//! (process images, autostart targets). Rules are compiled by `crate::rules` on a background thread.

use std::collections::BTreeMap;

use windows_sys::Win32::Foundation::HANDLE;

use super::memory::ProcMem;
use super::read_mem;
use crate::core::memrules;
use crate::core::report::{Category, Finding};
use crate::core::yarasel::{self, Span, MAX_FILE};
use crate::core::{is_exec, ProcInfo, MEM_COMMIT, PAGE_GUARD, PAGE_NOACCESS};
use crate::rules::{self, Hit};

/// Read `[span.alloc_base, +len)` region by region. Uncommitted, guard or unreadable pages are
/// left as zeros so offsets inside the buffer still match the process layout.
fn read_span(h: HANDLE, pm: &ProcMem, span: &Span) -> Option<Vec<u8>> {
    let start = span.alloc_base;
    let end = start + span.len;
    let mut buf = vec![0u8; span.len as usize];
    let mut any = false;
    for r in pm.regions.iter().filter(|r| r.base < end && r.base + r.size > start) {
        if r.state != MEM_COMMIT || r.protect & PAGE_GUARD != 0 || r.protect & 0xff == PAGE_NOACCESS {
            continue;
        }
        let a = r.base.max(start);
        let b = (r.base + r.size).min(end);
        if let Some(d) = read_mem(h, a, (b - a) as usize) {
            let off = (a - start) as usize;
            buf[off..off + d.len()].copy_from_slice(&d);
            any |= !d.is_empty();
        }
    }
    any.then_some(buf)
}

fn finding(hit: &Hit, in_memory: bool) -> Finding {
    let sev = yarasel::severity(&hit.meta, in_memory);
    let mut f = Finding::new(sev, Category::Yara, format!("YARA {}: {}", if in_memory { "memory" } else { "file" }, hit.rule));
    if let Some(d) = yarasel::meta_str(&hit.meta, &["description", "threat_name", "malware", "info"]) {
        f = f.detail(d.to_string());
    }
    f = f.detail(format!("rule set: {}", hit.namespace));
    if let Some(a) = yarasel::meta_str(&hit.meta, &["author"]) {
        f = f.detail(format!("rule author: {a}"));
    }
    if let Some(r) = yarasel::meta_str(&hit.meta, &["reference", "references", "url"]) {
        f = f.detail(format!("reference: {r}"));
    }
    if !hit.patterns.is_empty() {
        f = f.detail(format!("matched: {}", hit.patterns.join(" ")));
    }
    if !hit.tags.is_empty() {
        f = f.detail(format!("tags: {}", hit.tags.join(" ")));
    }
    let ids = yarasel::mitre_ids(&hit.meta);
    if !ids.is_empty() {
        f.mitre.extend(ids);
    } else if in_memory {
        f = f.mitre(&["T1055"]);
    }
    f
}

/// Scan the executable non-image allocations of one process. One finding per matching rule,
/// listing every allocation it fired in.
pub fn scan_memory(p: &ProcInfo, h: HANDLE, pm: &ProcMem, sc: &mut yara_x::Scanner, deep: bool) -> Vec<Finding> {
    if !pm.regions.iter().any(|r| is_exec(r.protect)) {
        return Vec::new();
    }
    let jit = memrules::is_jit_process(&p.name, &pm.images);
    let mut by_rule: BTreeMap<(String, String), (Hit, Vec<&Span>)> = BTreeMap::new();
    let spans = yarasel::suspicious_spans(&pm.regions, jit, deep);
    for span in &spans {
        let Some(buf) = read_span(h, pm, span) else { continue };
        for hit in rules::scan(sc, &buf) {
            by_rule.entry((hit.namespace.clone(), hit.rule.clone())).or_insert_with(|| (hit, Vec::new())).1.push(span);
        }
    }
    by_rule
        .into_values()
        .map(|(hit, spans)| {
            let mut f = finding(&hit, true).proc(p.pid, &p.name).addr(spans[0].alloc_base);
            for s in spans.iter().take(8) {
                f = f.detail(format!(
                    "allocation 0x{:x}: {} KiB executable{}",
                    s.alloc_base,
                    s.exec_bytes / 1024,
                    if s.rwx { ", RWX" } else { "" }
                ));
            }
            if spans.len() > 8 {
                f = f.detail(format!("... and {} more allocations", spans.len() - 8));
            }
            if let Some(path) = &p.path {
                f = f.detail(format!("process image: {path}"));
            }
            f
        })
        .collect()
}

/// Scan one file. `why` says where it came from (process image, autostart entry).
pub fn scan_file(path: &str, why: &str, sc: &mut yara_x::Scanner) -> Vec<Finding> {
    match std::fs::metadata(path) {
        Ok(m) if m.is_file() && m.len() > 0 && m.len() <= MAX_FILE => {}
        _ => return Vec::new(),
    }
    let Some(data) = super::read_file(path) else { return Vec::new() };
    rules::scan(sc, &data)
        .iter()
        .map(|hit| finding(hit, false).path(path.to_string()).detail(format!("scanned as: {why}")))
        .collect()
}
