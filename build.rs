//! Embeds every rule file under `rules/` (and the third-party license texts) into the executable
//! so `unveil.exe` runs standalone on an incident-response box.
//!
//! The rule bytes are deflate-compressed before being linked in. There are two reasons for this,
//! and only the first one matters:
//!
//! 1. **The unveil binary must not look like a malware sample to AV scanners.** When a scanner
//!    (Defender, VirusTotal engines, EDR string sweeps) looks at `unveil.exe` and sees the raw
//!    byte patterns of a Cobalt Strike beacon, Mimikatz or NotPetya sitting inside, it correctly
//!    flags them even though they are quoted inside YARA rules, not executable code. THOR, Loki,
//!    Fenrir and every other YARA-based scanner has the same problem and solves it the same way:
//!    scramble the signature database at rest so it does not pattern-match. Compressed data is
//!    high-entropy and has no stable byte alignment, so hex strings and ASCII IOCs no longer
//!    appear verbatim in the exe. No cryptography, no license implications.
//! 2. The binary is smaller (the raw rule corpus is ~16 MB; it fits in ~5 MB compressed).

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            walk(&p, out);
        } else {
            out.push(p);
        }
    }
}

fn main() {
    let root = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("rules");
    println!("cargo:rerun-if-changed=rules");
    println!("cargo:rerun-if-changed=build.rs");

    let mut files = Vec::new();
    walk(&root, &mut files);
    files.sort();

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let yara = std::env::var_os("CARGO_FEATURE_YARA").is_some();

    // Build one flat blob of (rel-path, raw rule bytes) laid out as:
    //   [u16 path_len] path_bytes [u32 data_len] data_bytes ...
    // then deflate-compress the whole thing. At runtime we inflate it and walk the entries.
    let mut blob: Vec<u8> = Vec::new();
    if yara {
        for p in &files {
            let rel = p.strip_prefix(&root).unwrap().to_string_lossy().replace('\\', "/");
            let name = p.file_name().unwrap().to_string_lossy().to_ascii_lowercase();
            if !(name.ends_with(".yar") || name.ends_with(".yara")) {
                continue;
            }
            let data = std::fs::read(p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()));
            let rel_bytes = rel.as_bytes();
            blob.extend_from_slice(&(rel_bytes.len() as u16).to_le_bytes());
            blob.extend_from_slice(rel_bytes);
            blob.extend_from_slice(&(data.len() as u32).to_le_bytes());
            blob.extend_from_slice(&data);
        }
    }
    let raw_len = blob.len();
    let compressed = miniz_oxide::deflate::compress_to_vec(&blob, 9);
    let blob_path = out_dir.join("rules.deflate");
    std::fs::write(&blob_path, &compressed).unwrap();
    println!("cargo:warning=unveil: embedded rule corpus {} bytes raw, {} bytes deflated", raw_len, compressed.len());

    // License texts stay plaintext: they are small and `unveil licenses` must print them as-is.
    let mut licenses = String::from("pub static LICENSES: &[(&str, &str)] = &[\n");
    for p in &files {
        let rel = p.strip_prefix(&root).unwrap().to_string_lossy().replace('\\', "/");
        let name = p.file_name().unwrap().to_string_lossy().to_ascii_lowercase();
        let abs = p.to_string_lossy();
        if name.starts_with("license") {
            writeln!(licenses, "    ({rel:?}, include_str!({abs:?})),").unwrap();
        }
    }
    licenses.push_str("];\n");

    let rules_decl = format!(
        "pub static RULES_DEFLATED: &[u8] = include_bytes!({:?});\npub const RULES_RAW_LEN: usize = {};\n",
        blob_path.to_string_lossy(),
        raw_len
    );
    std::fs::write(out_dir.join("embedded_rules.rs"), rules_decl + &licenses).unwrap();
}
