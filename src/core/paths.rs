//! Path and command-line helpers. Pure string logic so it can be unit tested anywhere.

/// Lowercase, forward slashes to backslashes, strip `\\?\` and `\??\` prefixes.
pub fn normalize(p: &str) -> String {
    let mut s = p.trim().trim_matches('"').replace('/', "\\").to_ascii_lowercase();
    for pre in ["\\\\?\\", "\\??\\"] {
        if let Some(rest) = s.strip_prefix(pre) {
            s = rest.to_string();
        }
    }
    if let Some(rest) = s.strip_prefix("\\systemroot\\") {
        s = format!("c:\\windows\\{rest}");
    } else if let Some(rest) = s.strip_prefix("system32\\") {
        s = format!("c:\\windows\\system32\\{rest}");
    }
    s
}

pub fn file_name(p: &str) -> &str {
    let p = p.trim_end_matches(['\\', '/']);
    p.rsplit(['\\', '/']).next().unwrap_or(p)
}

/// Split a Windows command line into arguments (CommandLineToArgvW rules, simplified).
pub fn split_args(cmd: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut cur = String::new();
    let mut in_q = false;
    let mut has = false;
    let mut chars = cmd.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                let mut n = 1;
                while chars.peek() == Some(&'\\') {
                    chars.next();
                    n += 1;
                }
                if chars.peek() == Some(&'"') {
                    cur.extend(std::iter::repeat_n('\\', n / 2));
                    if n % 2 == 1 {
                        chars.next();
                        cur.push('"');
                    }
                } else {
                    cur.extend(std::iter::repeat_n('\\', n));
                }
                has = true;
            }
            '"' => {
                in_q = !in_q;
                has = true;
            }
            ' ' | '\t' if !in_q => {
                if has {
                    args.push(std::mem::take(&mut cur));
                    has = false;
                }
            }
            _ => {
                cur.push(c);
                has = true;
            }
        }
    }
    if has {
        args.push(cur);
    }
    args
}

const EXEC_EXT: &[&str] = &[
    ".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".ocx", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf",
    ".hta", ".msi", ".lnk",
];

/// Best-effort: the file a command line actually runs. For unquoted paths with spaces
/// (`C:\Program Files\x\y.exe -a`) it grows the candidate until it hits a known extension.
/// For proxy launchers (rundll32, regsvr32, script hosts) it returns the payload instead.
pub fn command_target(cmd: &str) -> Option<String> {
    let cmd = cmd.trim();
    if cmd.is_empty() {
        return None;
    }
    let first = if cmd.starts_with('"') {
        split_args(cmd).into_iter().next()?
    } else {
        let lower = cmd.to_ascii_lowercase();
        let mut end = None;
        for ext in EXEC_EXT {
            let mut from = 0;
            while let Some(i) = lower[from..].find(ext) {
                let stop = from + i + ext.len();
                if lower[stop..].is_empty() || lower[stop..].starts_with([' ', ',', '\t']) {
                    end = Some(end.map_or(stop, |e: usize| e.min(stop)));
                    break;
                }
                from = stop;
            }
        }
        match end {
            Some(e) => cmd[..e].to_string(),
            None => cmd.split_whitespace().next()?.to_string(),
        }
    };

    let exe = file_name(&first).to_ascii_lowercase();
    let rest: Vec<String> = split_args(cmd).into_iter().skip(1).collect();
    let payload = match exe.trim_end_matches(".exe") {
        "rundll32" => rest.first().map(|a| a.split(',').next().unwrap_or(a).to_string()),
        "regsvr32" => rest.iter().find(|a| !a.starts_with(['/', '-'])).cloned(),
        "wscript" | "cscript" | "mshta" => rest.iter().find(|a| !a.starts_with(['/', '-'])).cloned(),
        _ => None,
    };
    Some(payload.filter(|p| !p.is_empty()).unwrap_or(first))
}

/// Directories normal software does not run from, and that any user can write to.
pub fn suspicious_dir(path: &str) -> Option<&'static str> {
    let p = normalize(path);
    let checks: &[(&str, &str)] = &[
        ("\\appdata\\local\\temp\\", "user temp directory"),
        ("\\windows\\temp\\", "Windows temp directory"),
        ("\\users\\public\\", "Users\\Public"),
        ("\\$recycle.bin\\", "recycle bin"),
        ("\\perflogs\\", "PerfLogs"),
        ("\\downloads\\", "Downloads folder"),
        ("\\appdata\\roaming\\", "roaming AppData"),
        ("\\windows\\tasks\\", "Windows\\Tasks"),
        ("\\windows\\debug\\", "Windows\\debug"),
        ("\\windows\\fonts\\", "Windows\\Fonts"),
        ("\\windows\\system32\\spool\\drivers\\color\\", "spool color directory"),
        ("\\windows\\system32\\tasks\\", "System32\\Tasks"),
    ];
    for (needle, why) in checks {
        if p.contains(needle) {
            return Some(why);
        }
    }
    // Files directly under C:\ProgramData or C:\Users\<name> (not in a vendor subfolder).
    for root in ["c:\\programdata\\", "c:\\users\\"] {
        if let Some(rest) = p.strip_prefix(root) {
            let depth = rest.matches('\\').count();
            if (root == "c:\\programdata\\" && depth == 0) || (root == "c:\\users\\" && depth <= 1) {
                return Some("top of a user-writable directory");
            }
        }
    }
    None
}

pub fn in_system_dir(path: &str) -> bool {
    let p = normalize(path);
    p.starts_with("c:\\windows\\system32\\") || p.starts_with("c:\\windows\\syswow64\\") || p.starts_with("c:\\windows\\winsxs\\")
}

pub fn is_script(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    [".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".scr"]
        .iter()
        .any(|e| p.trim_end_matches('"').ends_with(e))
}

/// Levenshtein distance, used to catch names like `scvhost.exe` or `lsasss.exe`.
pub fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0; b.len() + 1];
    for i in 1..=a.len() {
        cur[0] = i;
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            cur[j] = (prev[j] + 1).min(cur[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes() {
        assert_eq!(normalize("\\??\\C:\\Windows\\System32\\x.sys"), "c:\\windows\\system32\\x.sys");
        assert_eq!(normalize("\\SystemRoot\\System32\\drivers\\a.sys"), "c:\\windows\\system32\\drivers\\a.sys");
        assert_eq!(normalize("System32\\drivers\\a.sys"), "c:\\windows\\system32\\drivers\\a.sys");
    }

    #[test]
    fn splits_args() {
        assert_eq!(split_args(r#""C:\a b\c.exe" -x "y z""#), vec![r"C:\a b\c.exe", "-x", "y z"]);
        assert_eq!(split_args(r#"a\\"b c" d"#), vec![r#"a\b c"#, "d"]);
    }

    #[test]
    fn finds_command_target() {
        assert_eq!(command_target(r"C:\Program Files\App\app.exe /s").unwrap(), r"C:\Program Files\App\app.exe");
        assert_eq!(command_target(r#""C:\x\y.exe" -a"#).unwrap(), r"C:\x\y.exe");
        assert_eq!(
            command_target(r"rundll32.exe C:\Users\a\AppData\Local\Temp\evil.dll,Start").unwrap(),
            r"C:\Users\a\AppData\Local\Temp\evil.dll"
        );
        assert_eq!(command_target(r"wscript.exe //B C:\ProgramData\a.vbs").unwrap(), r"C:\ProgramData\a.vbs");
        assert_eq!(command_target("explorer.exe").unwrap(), "explorer.exe");
    }

    #[test]
    fn flags_suspicious_dirs() {
        assert!(suspicious_dir(r"C:\Users\bob\AppData\Local\Temp\x.exe").is_some());
        assert!(suspicious_dir(r"C:\ProgramData\x.exe").is_some());
        assert!(suspicious_dir(r"C:\Users\bob\x.exe").is_some());
        assert!(suspicious_dir(r"C:\ProgramData\Microsoft\Windows Defender\x.exe").is_none());
        assert!(suspicious_dir(r"C:\Program Files\App\x.exe").is_none());
    }

    #[test]
    fn distance() {
        assert_eq!(edit_distance("svchost.exe", "scvhost.exe"), 2);
        assert_eq!(edit_distance("lsass.exe", "lsas.exe"), 1);
    }
}
