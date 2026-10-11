//! The YARA rule set: rules embedded at build time (`rules/**`, see build.rs) plus optional extra
//! rules from `--rules`. Compiled with yara-x, one namespace per file, includes disabled. A file
//! that does not compile is skipped with a warning instead of failing the whole set.

use std::path::{Path, PathBuf};
use std::thread::JoinHandle;
use std::time::Duration;

use crate::core::yarasel::{self, Meta};

pub use crate::embedded::RULES as EMBEDDED;

pub struct RuleSet {
    pub rules: yara_x::Rules,
    pub files_ok: usize,
    /// `(file, first line of the error)` for every file that was skipped.
    pub skipped: Vec<(String, String)>,
    pub rule_count: usize,
    pub compile_secs: f64,
}

/// A rule that matched, with its metadata copied out of the engine.
#[derive(Debug, Clone)]
pub struct Hit {
    pub namespace: String,
    pub rule: String,
    pub tags: Vec<String>,
    pub meta: Vec<(String, Meta)>,
    /// Identifiers of the patterns that matched (`$s1`, `$op`...), at most a handful.
    pub patterns: Vec<String>,
}

fn walk(p: &Path, out: &mut Vec<PathBuf>) {
    if p.is_file() {
        out.push(p.to_path_buf());
        return;
    }
    let Ok(rd) = std::fs::read_dir(p) else { return };
    let mut entries: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
    entries.sort();
    for e in entries {
        if e.is_dir() {
            walk(&e, out);
        } else if e.file_name().is_some_and(|n| yarasel::is_rule_file(&n.to_string_lossy())) {
            out.push(e);
        }
    }
}

/// Rule sources to compile: `(origin, namespace, bytes)`.
fn sources(extra: &[PathBuf], skipped: &mut Vec<(String, String)>) -> Vec<(String, String, Vec<u8>)> {
    let mut v: Vec<(String, String, Vec<u8>)> =
        EMBEDDED.iter().map(|(rel, b)| (rel.to_string(), yarasel::namespace(rel), b.to_vec())).collect();
    for root in extra {
        let mut files = Vec::new();
        walk(root, &mut files);
        if files.is_empty() {
            skipped.push((root.display().to_string(), "no .yar/.yara files found".into()));
        }
        for f in files {
            let origin = f.display().to_string();
            match std::fs::read(&f) {
                Ok(b) => {
                    let rel = f.strip_prefix(root).ok().filter(|r| !r.as_os_str().is_empty()).unwrap_or(&f);
                    let ns = format!("extra_{}", yarasel::namespace(&rel.to_string_lossy()));
                    v.push((origin, ns, b));
                }
                Err(e) => skipped.push((origin, e.to_string())),
            }
        }
    }
    v
}

pub fn compile(extra: &[PathBuf]) -> RuleSet {
    let t = std::time::Instant::now();
    let mut skipped = Vec::new();
    let srcs = sources(extra, &mut skipped);
    let mut c = yara_x::Compiler::new();
    c.enable_includes(false).relaxed_re_syntax(true).switch_all_warnings(false);
    let mut files_ok = 0;
    for (origin, ns, bytes) in &srcs {
        c.new_namespace(ns);
        let src = yara_x::SourceCode::from(bytes.as_slice()).with_origin(origin.clone());
        match c.add_source(src) {
            Ok(_) => files_ok += 1,
            Err(e) => {
                let msg = e.to_string();
                let first = msg.lines().find(|l| !l.trim().is_empty()).unwrap_or("compile error").trim().to_string();
                skipped.push((origin.clone(), first));
            }
        }
    }
    let rules = c.build();
    let rule_count = rules.iter().len();
    RuleSet { rules, files_ok, skipped, rule_count, compile_secs: t.elapsed().as_secs_f64() }
}

/// Compile on a background thread so process enumeration runs meanwhile.
pub fn compile_in_background(extra: Vec<PathBuf>) -> JoinHandle<RuleSet> {
    std::thread::Builder::new()
        .name("yara-compile".into())
        .stack_size(64 << 20) // deeply nested conditions in third-party rules recurse in the compiler
        .spawn(move || compile(&extra))
        .expect("spawn rule compiler")
}

pub fn scanner(rs: &RuleSet) -> yara_x::Scanner<'_> {
    let mut s = yara_x::Scanner::new(&rs.rules);
    s.set_timeout(Duration::from_secs(20));
    s.max_matches_per_pattern(1000);
    s
}

fn meta_of(v: yara_x::MetaValue) -> Meta {
    match v {
        yara_x::MetaValue::Integer(i) => Meta::Int(i),
        yara_x::MetaValue::Float(f) => Meta::Float(f),
        yara_x::MetaValue::Bool(b) => Meta::Bool(b),
        yara_x::MetaValue::String(s) => Meta::Str(s.to_string()),
        yara_x::MetaValue::Bytes(b) => Meta::Str(String::from_utf8_lossy(b).into_owned()),
    }
}

/// Scan a buffer. A timeout or engine error yields no hits rather than aborting the hunt.
pub fn scan(s: &mut yara_x::Scanner, data: &[u8]) -> Vec<Hit> {
    let Ok(res) = s.scan(data) else { return Vec::new() };
    res.matching_rules()
        .map(|r| Hit {
            namespace: r.namespace().to_string(),
            rule: r.identifier().to_string(),
            tags: r.tags().map(|t| t.identifier().to_string()).collect(),
            meta: r.metadata().map(|(k, v)| (k.to_string(), meta_of(v))).collect(),
            patterns: r.patterns().filter(|p| p.matches().next().is_some()).map(|p| p.identifier().to_string()).take(8).collect(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The custom rule file must compile cleanly on its own (no skipped files, no errors).
    #[test]
    fn custom_rules_compile() {
        let (rel, bytes) = EMBEDDED.iter().find(|(r, _)| *r == "custom/unveil.yar").expect("custom rules embedded");
        let mut c = yara_x::Compiler::new();
        c.enable_includes(false);
        c.new_namespace(&yarasel::namespace(rel));
        if let Err(e) = c.add_source(yara_x::SourceCode::from(*bytes).with_origin(*rel)) {
            panic!("rules/custom/unveil.yar does not compile:\n{e}");
        }
        let rules = c.build();
        assert!(rules.iter().len() >= 8);
    }

    /// Every embedded rule file compiles, so nothing is silently dropped at runtime.
    #[test]
    fn all_embedded_rules_compile() {
        let rs = compile(&[]);
        assert!(rs.skipped.is_empty(), "skipped: {:?}", &rs.skipped[..rs.skipped.len().min(10)]);
        assert_eq!(rs.files_ok, EMBEDDED.len());
        assert!(rs.rule_count > 1000);
    }

    #[test]
    fn custom_rule_matches_syscall_stubs() {
        let rs = compile(&[]);
        let mut s = scanner(&rs);
        let stub = [0x4C, 0x8B, 0xD1, 0xB8, 0x18, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3, 0x90];
        let data: Vec<u8> = stub.iter().cycle().take(stub.len() * 4).copied().collect();
        let hits = scan(&mut s, &data);
        let h = hits.iter().find(|h| h.rule == "UNV_Direct_Syscall_Stubs").expect("syscall stub rule fires");
        assert_eq!(h.namespace, "custom_unveil");
        assert_eq!(yarasel::mitre_ids(&h.meta), vec!["T1106"]);
        assert!(scan(&mut s, &[0u8; 64]).iter().all(|h| h.rule != "UNV_Direct_Syscall_Stubs"));
    }

    #[test]
    fn broken_extra_file_is_skipped_not_fatal() {
        let dir = std::env::temp_dir().join(format!("unveil-rules-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("good.yar"), "rule extra_good { strings: $a = \"unveil-extra-test\" condition: $a }").unwrap();
        std::fs::write(dir.join("bad.yar"), "rule broken { condition: nope( }").unwrap();
        std::fs::write(dir.join("inc.yar"), "include \"other.yar\"\nrule x { condition: true }").unwrap();
        let rs = compile(std::slice::from_ref(&dir));
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(rs.skipped.len(), 2, "{:?}", rs.skipped);
        assert!(rs.skipped.iter().any(|(f, _)| f.ends_with("bad.yar")));
        assert!(rs.skipped.iter().any(|(f, _)| f.ends_with("inc.yar")));
        let mut s = scanner(&rs);
        assert!(scan(&mut s, b"xx unveil-extra-test xx").iter().any(|h| h.rule == "extra_good" && h.namespace == "extra_good"));
    }
}
