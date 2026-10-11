//! Embeds every rule file under `rules/` (and the third-party license texts) into the executable,
//! so `unveil.exe` runs standalone on an incident-response box.

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

    let yara = std::env::var_os("CARGO_FEATURE_YARA").is_some();
    let mut rules = String::from("pub static RULES: &[(&str, &[u8])] = &[\n");
    let mut licenses = String::from("pub static LICENSES: &[(&str, &str)] = &[\n");
    for p in &files {
        let rel = p.strip_prefix(&root).unwrap().to_string_lossy().replace('\\', "/");
        let name = p.file_name().unwrap().to_string_lossy().to_ascii_lowercase();
        let abs = p.to_string_lossy();
        if name.ends_with(".yar") || name.ends_with(".yara") {
            if yara {
                writeln!(rules, "    ({rel:?}, include_bytes!({abs:?})),").unwrap();
            }
        } else if name.starts_with("license") {
            writeln!(licenses, "    ({rel:?}, include_str!({abs:?})),").unwrap();
        }
    }
    rules.push_str("];\n");
    licenses.push_str("];\n");
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("embedded_rules.rs");
    std::fs::write(out, rules + &licenses).unwrap();
}
