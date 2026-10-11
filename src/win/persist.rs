//! Autostart collection: registry ASEPs, services, drivers, scheduled tasks, startup folders, COM.

use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegEnumKeyExW, RegEnumValueW, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_READ, KEY_WOW64_64KEY, REG_DWORD,
    REG_EXPAND_SZ, REG_MULTI_SZ, REG_SZ,
};

use super::{expand_env, file_exists, from_wide, resolve_path, wide};
use crate::core::paths::{command_target, file_name, normalize};
use crate::core::persistrules::{self as pr, Entry, Kind};
use crate::core::report::Severity;
use crate::core::{lnk, taskxml};

pub struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        unsafe { RegCloseKey(self.0) };
    }
}

#[derive(Debug, Clone)]
pub enum Val {
    Str(String),
    Multi(Vec<String>),
    Dword(u32),
    Other,
}

impl Val {
    pub fn text(&self) -> String {
        match self {
            Val::Str(s) => s.clone(),
            Val::Multi(v) => v.join(" | "),
            Val::Dword(d) => d.to_string(),
            Val::Other => String::new(),
        }
    }
}

impl Key {
    pub fn open(root: HKEY, path: &str) -> Option<Key> {
        let w = wide(path);
        let mut k: HKEY = std::ptr::null_mut();
        (unsafe { RegOpenKeyExW(root, w.as_ptr(), 0, KEY_READ | KEY_WOW64_64KEY, &mut k) } == 0).then_some(Key(k))
    }

    pub fn sub(&self, path: &str) -> Option<Key> {
        Key::open(self.0, path)
    }

    pub fn subkeys(&self) -> Vec<String> {
        let mut out = Vec::new();
        for i in 0.. {
            let mut buf = vec![0u16; 512];
            let mut n = buf.len() as u32;
            let st = unsafe {
                RegEnumKeyExW(self.0, i, buf.as_mut_ptr(), &mut n, std::ptr::null(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut())
            };
            if st != 0 {
                break;
            }
            out.push(from_wide(&buf[..n as usize]));
        }
        out
    }

    pub fn values(&self) -> Vec<(String, Val)> {
        let mut out = Vec::new();
        for i in 0.. {
            let mut name = vec![0u16; 16384];
            let mut nlen = name.len() as u32;
            let mut ty = 0u32;
            let mut data = vec![0u8; 65536];
            let mut dlen = data.len() as u32;
            let st = unsafe { RegEnumValueW(self.0, i, name.as_mut_ptr(), &mut nlen, std::ptr::null(), &mut ty, data.as_mut_ptr(), &mut dlen) };
            match st {
                0 => {}
                234 => continue, // ERROR_MORE_DATA: value larger than 64 KiB, not an autostart path
                _ => break,
            }
            data.truncate(dlen as usize);
            out.push((from_wide(&name[..nlen as usize]), decode(ty, &data)));
        }
        out
    }

    pub fn get(&self, name: &str) -> Option<Val> {
        self.values().into_iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v)
    }

    pub fn str(&self, name: &str) -> Option<String> {
        match self.get(name)? {
            Val::Str(s) => Some(s),
            Val::Multi(v) => Some(v.join(" ")),
            _ => None,
        }
    }

    pub fn dword(&self, name: &str) -> Option<u32> {
        match self.get(name)? {
            Val::Dword(d) => Some(d),
            _ => None,
        }
    }
}

fn decode(ty: u32, d: &[u8]) -> Val {
    let u16s = || d.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect::<Vec<u16>>();
    match ty {
        REG_SZ | REG_EXPAND_SZ => Val::Str(from_wide(&u16s())),
        REG_MULTI_SZ => Val::Multi(String::from_utf16_lossy(&u16s()).split('\0').filter(|s| !s.is_empty()).map(String::from).collect()),
        REG_DWORD if d.len() >= 4 => Val::Dword(u32::from_le_bytes(d[..4].try_into().unwrap())),
        _ => Val::Other,
    }
}

/// Loaded user hives under HKEY_USERS (S-1-5-21-..., not the _Classes hives).
fn user_hives() -> Vec<String> {
    Key::open(HKEY_USERS, "")
        .map(|k| k.subkeys().into_iter().filter(|s| s.starts_with("S-1-5-21-") && !s.ends_with("_Classes")).collect())
        .unwrap_or_default()
}

/// Fill target, existence and signature for an entry.
pub fn resolve(mut e: Entry, check_sig: bool) -> Entry {
    if e.target.is_none() {
        e.target = command_target(&expand_env(&e.command)).map(|t| resolve_path(&t));
    }
    if let Some(t) = &e.target {
        let exists = file_exists(t);
        e.target_exists = Some(exists);
        let pe = [".exe", ".dll", ".sys", ".ocx", ".cpl", ".scr", ".com", ".drv"].iter().any(|x| t.to_ascii_lowercase().ends_with(x));
        if exists && pe && check_sig {
            e.signature = Some(super::sig::check(t));
        }
    }
    e
}

const RUN_KEYS: &[&str] = &[
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Software\Microsoft\Windows\CurrentVersion\RunServices",
    r"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
    r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
];

pub fn collect() -> Vec<Entry> {
    let mut v = Vec::new();
    let hives: Vec<(HKEY, String, String)> = std::iter::once((HKEY_LOCAL_MACHINE, String::new(), "HKLM".to_string()))
        .chain(user_hives().into_iter().map(|s| (HKEY_USERS, format!("{s}\\"), format!("HKU\\{s}"))))
        .collect();

    // Run keys, Load/Run under Windows, cmd AutoRun, user Winlogon shell, screensaver.
    for (root, prefix, label) in &hives {
        for rk in RUN_KEYS {
            if let Some(k) = Key::open(*root, &format!("{prefix}{rk}")) {
                for (name, val) in k.values() {
                    if name.is_empty() && val.text().is_empty() {
                        continue;
                    }
                    v.push(Entry::new(Kind::RunKey, format!("{label}\\{rk}"), name, val.text()));
                }
            }
        }
        let wk = r"Software\Microsoft\Windows NT\CurrentVersion\Windows";
        if let Some(k) = Key::open(*root, &format!("{prefix}{wk}")) {
            for n in ["Load", "Run"] {
                if let Some(s) = k.str(n).filter(|s| !s.trim().is_empty()) {
                    v.push(Entry::new(Kind::RunKey, format!("{label}\\{wk}"), n, s));
                }
            }
        }
        let ck = r"Software\Microsoft\Command Processor";
        if let Some(s) = Key::open(*root, &format!("{prefix}{ck}")).and_then(|k| k.str("AutoRun")).filter(|s| !s.trim().is_empty()) {
            v.push(Entry::new(Kind::CmdAutoRun, format!("{label}\\{ck}"), "AutoRun", s));
        }
        if !prefix.is_empty() {
            let wl = r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon";
            if let Some(s) = Key::open(*root, &format!("{prefix}{wl}")).and_then(|k| k.str("Shell")).filter(|s| !s.trim().is_empty()) {
                let mut e = Entry::new(Kind::Winlogon, format!("{label}\\{wl}"), "Shell (per-user)", s);
                e.floor = Severity::High;
                v.push(e);
            }
            if let Some(s) = Key::open(*root, &format!("{prefix}Control Panel\\Desktop")).and_then(|k| k.str("SCRNSAVE.EXE")) {
                let mut e = Entry::new(Kind::Screensaver, format!("{label}\\Control Panel\\Desktop"), "SCRNSAVE.EXE", s.clone());
                if !normalize(&expand_env(&s)).starts_with("c:\\windows\\system32\\") {
                    e.floor = Severity::Medium;
                }
                v.push(e);
            }
        }
    }

    winlogon(&mut v);
    ifeo(&mut v);
    session_manager(&mut v);
    lsa(&mut v);
    misc_dlls(&mut v);
    active_setup(&mut v);
    services(&mut v);
    tasks(&mut v);
    startup_folders(&mut v);
    com_hijack(&mut v);
    v
}

fn winlogon(v: &mut Vec<Entry>) {
    let p = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
    let Some(k) = Key::open(HKEY_LOCAL_MACHINE, p) else { return };
    let loc = format!("HKLM\\{p}");
    if let Some(s) = k.str("Shell") {
        if s.trim().to_ascii_lowercase() != pr::WINLOGON_SHELL {
            let mut e = Entry::new(Kind::Winlogon, &loc, "Shell", s);
            e.floor = Severity::High;
            v.push(e);
        }
    }
    if let Some(s) = k.str("Userinit") {
        let n = normalize(&expand_env(&s));
        if n != pr::WINLOGON_USERINIT && n != pr::WINLOGON_USERINIT.trim_end_matches(',') {
            let mut e = Entry::new(Kind::Winlogon, &loc, "Userinit", s);
            e.floor = Severity::High;
            v.push(e);
        }
    }
    for n in ["Taskman", "AppSetup", "GinaDLL", "System"] {
        if let Some(s) = k.str(n).filter(|s| !s.trim().is_empty()) {
            let mut e = Entry::new(Kind::Winlogon, &loc, n, s);
            e.floor = Severity::Medium;
            v.push(e);
        }
    }
    if let Some(nk) = k.sub("Notify") {
        for sk in nk.subkeys() {
            if let Some(dll) = nk.sub(&sk).and_then(|x| x.str("DllName")) {
                let mut e = Entry::new(Kind::Winlogon, format!("{loc}\\Notify\\{sk}"), sk.clone(), dll);
                e.floor = Severity::Medium;
                v.push(e);
            }
        }
    }
}

fn ifeo(v: &mut Vec<Entry>) {
    for p in [
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        r"SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    ] {
        let Some(k) = Key::open(HKEY_LOCAL_MACHINE, p) else { continue };
        for img in k.subkeys() {
            let Some(sk) = k.sub(&img) else { continue };
            if let Some(d) = sk.str("Debugger").filter(|s| !s.trim().is_empty()) {
                let mut e = Entry::new(Kind::Ifeo, format!("HKLM\\{p}\\{img}"), img.clone(), d);
                // Accessibility binaries hijacked = classic sticky-keys backdoor.
                if ["sethc.exe", "utilman.exe", "osk.exe", "magnify.exe", "narrator.exe", "displayswitch.exe", "atbroker.exe"]
                    .contains(&img.to_ascii_lowercase().as_str())
                {
                    e.floor = Severity::Critical;
                    e.notes.push("accessibility binary hijack (sticky keys backdoor)".into());
                }
                v.push(e);
            }
            if let Some(d) = sk.str("VerifierDlls").filter(|s| !s.trim().is_empty()) {
                let mut e = Entry::new(Kind::Ifeo, format!("HKLM\\{p}\\{img}"), format!("{img} VerifierDlls"), d);
                e.floor = Severity::High;
                e.notes.push("Application Verifier DLL is loaded into every start of this program".into());
                v.push(e);
            }
            if sk.dword("GlobalFlag").is_some_and(|g| g & 0x200 != 0) {
                let spe = format!(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\{img}");
                if let Some(m) = Key::open(HKEY_LOCAL_MACHINE, &spe).and_then(|k| k.str("MonitorProcess")) {
                    v.push(Entry::new(Kind::SilentProcessExit, format!("HKLM\\{spe}"), img.clone(), m));
                }
            }
        }
    }
}

fn session_manager(v: &mut Vec<Entry>) {
    let p = r"SYSTEM\CurrentControlSet\Control\Session Manager";
    let Some(k) = Key::open(HKEY_LOCAL_MACHINE, p) else { return };
    for n in ["BootExecute", "SetupExecute", "Execute", "S0InitialCommand", "BootExecuteNoPnpSync", "PlatformExecute"] {
        if let Some(val) = k.get(n) {
            let items = match val {
                Val::Multi(v) => v,
                Val::Str(s) if !s.trim().is_empty() => vec![s],
                _ => vec![],
            };
            for it in items {
                if n == "BootExecute" && it.trim().eq_ignore_ascii_case(pr::BOOTEXECUTE_DEFAULT) {
                    continue;
                }
                let mut e = Entry::new(Kind::BootExecute, format!("HKLM\\{p}"), n, it);
                e.floor = Severity::Medium;
                v.push(e);
            }
        }
    }
    if let Some(ac) = k.sub("AppCertDlls") {
        for (n, val) in ac.values() {
            v.push(Entry::new(Kind::AppCert, format!("HKLM\\{p}\\AppCertDlls"), n, val.text()));
        }
    }
}

fn lsa(v: &mut Vec<Entry>) {
    for p in [r"SYSTEM\CurrentControlSet\Control\Lsa", r"SYSTEM\CurrentControlSet\Control\Lsa\OSConfig"] {
        let Some(k) = Key::open(HKEY_LOCAL_MACHINE, p) else { continue };
        for n in ["Authentication Packages", "Security Packages", "Notification Packages"] {
            let items = match k.get(n) {
                Some(Val::Multi(v)) => v,
                Some(Val::Str(s)) => s.split_whitespace().map(String::from).collect(),
                _ => continue,
            };
            for pkg in items.into_iter().filter(|x| pr::lsa_package_unusual(x)) {
                let mut e = Entry::new(Kind::Lsa, format!("HKLM\\{p}"), format!("{n}: {pkg}"), pkg.clone());
                let dll = if pkg.contains('\\') { pkg.clone() } else { format!("%SystemRoot%\\System32\\{}.dll", pkg.trim_end_matches(".dll")) };
                e.target = Some(resolve_path(&dll));
                e.floor = Severity::High;
                e.notes.push("non-default LSA package: loaded into lsass.exe, can capture credentials".into());
                v.push(e);
            }
        }
    }
}

fn misc_dlls(v: &mut Vec<Entry>) {
    for p in [r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", r"SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows"] {
        if let Some(k) = Key::open(HKEY_LOCAL_MACHINE, p) {
            if let Some(s) = k.str("AppInit_DLLs").filter(|s| !s.trim().is_empty()) {
                let mut e = Entry::new(Kind::AppInit, format!("HKLM\\{p}"), "AppInit_DLLs", s);
                e.notes.push(format!("LoadAppInit_DLLs = {}", k.dword("LoadAppInit_DLLs").unwrap_or(0)));
                v.push(e);
            }
        }
    }
    if let Some(k) = Key::open(HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Print\Monitors") {
        for m in k.subkeys() {
            if let Some(d) = k.sub(&m).and_then(|x| x.str("Driver")) {
                if !pr::PRINT_MONITOR_DEFAULT.contains(&file_name(&d).to_ascii_lowercase().as_str()) {
                    let mut e = Entry::new(Kind::PrintMonitor, format!(r"HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\{m}"), m.clone(), d.clone());
                    e.target = Some(resolve_path(&if d.contains('\\') { d } else { format!("%SystemRoot%\\System32\\{d}") }));
                    e.floor = Severity::Medium;
                    v.push(e);
                }
            }
        }
    }
    if let Some(k) = Key::open(HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\NetSh") {
        for (n, val) in k.values() {
            let d = val.text();
            if pr::netsh_unusual(&d) {
                let mut e = Entry::new(Kind::NetshHelper, r"HKLM\SOFTWARE\Microsoft\NetSh", n, d.clone());
                e.target = Some(resolve_path(&if d.contains('\\') { d } else { format!("%SystemRoot%\\System32\\{d}") }));
                e.floor = Severity::Medium;
                v.push(e);
            }
        }
    }
    let ak = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjectDelayLoad";
    if let Some(k) = Key::open(HKEY_LOCAL_MACHINE, ak) {
        for (n, val) in k.values() {
            if let Some(path) = clsid_server(&val.text()) {
                v.push(Entry::new(Kind::ComHijack, format!("HKLM\\{ak}"), n, path));
            }
        }
    }
}

fn active_setup(v: &mut Vec<Entry>) {
    for p in [r"SOFTWARE\Microsoft\Active Setup\Installed Components", r"SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components"] {
        let Some(k) = Key::open(HKEY_LOCAL_MACHINE, p) else { continue };
        for c in k.subkeys() {
            if let Some(s) = k.sub(&c).and_then(|x| x.str("StubPath")).filter(|s| !s.trim().is_empty()) {
                v.push(Entry::new(Kind::ActiveSetup, format!("HKLM\\{p}\\{c}"), c.clone(), s));
            }
        }
    }
}

fn services(v: &mut Vec<Entry>) {
    let p = r"SYSTEM\CurrentControlSet\Services";
    let Some(k) = Key::open(HKEY_LOCAL_MACHINE, p) else { return };
    for name in k.subkeys() {
        let Some(sk) = k.sub(&name) else { continue };
        let ty = sk.dword("Type").unwrap_or(0);
        let start = sk.dword("Start").unwrap_or(4);
        let image = sk.str("ImagePath").unwrap_or_default();
        let dll = sk.sub("Parameters").and_then(|x| x.str("ServiceDll")).or_else(|| sk.str("ServiceDll"));
        if image.is_empty() && dll.is_none() {
            continue;
        }
        let driver = ty & 0x3 != 0;
        let susp = crate::core::paths::suspicious_dir(&expand_env(&image)).is_some()
            || dll.as_deref().is_some_and(|d| crate::core::paths::suspicious_dir(&expand_env(d)).is_some());
        // Auto/boot/system start, or anything (even disabled/demand) living in a user-writable path.
        if start > 2 && !susp {
            continue;
        }
        let loc = format!("HKLM\\{p}\\{name}");
        let kind = if driver { Kind::Driver } else { Kind::Service };
        let start_s = ["boot", "system", "auto", "demand", "disabled"].get(start as usize).copied().unwrap_or("?");
        let mut e = Entry::new(kind, &loc, name.clone(), image.clone());
        e.notes.push(format!("start: {start_s}, type: 0x{ty:x}"));
        if let Some(d) = &dll {
            e.target = Some(resolve_path(d));
            e.notes.push(format!("ServiceDll: {d}"));
        } else if driver {
            e.target = Some(resolve_path(&image));
        }
        let ip = image.trim();
        if !driver && !ip.starts_with('"') && ip.contains(' ') {
            let exe_end = ip.to_ascii_lowercase().find(".exe").map(|i| i + 4).unwrap_or(ip.len());
            if ip[..exe_end].contains(' ') {
                e.notes.push("unquoted service path with spaces (privilege escalation risk, T1574.009)".into());
                e.floor = e.floor.max(Severity::Low);
            }
        }
        v.push(e);
    }
}

fn walk_tasks(dir: &std::path::Path, root: &std::path::Path, out: &mut Vec<(String, Vec<u8>)>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            walk_tasks(&p, root, out);
        } else if let Ok(b) = std::fs::read(&p) {
            let rel = p.strip_prefix(root).map(|r| format!("\\{}", r.display())).unwrap_or_else(|_| p.display().to_string());
            out.push((rel, b));
        }
    }
}

fn tasks(v: &mut Vec<Entry>) {
    let root = std::path::PathBuf::from(format!("{}\\System32\\Tasks", expand_env("%SystemRoot%")));
    let mut files = Vec::new();
    walk_tasks(&root, &root, &mut files);
    let mut on_disk = std::collections::HashSet::new();
    for (name, raw) in &files {
        on_disk.insert(name.to_ascii_lowercase());
        let t = taskxml::parse(&taskxml::decode(raw));
        let loc = format!("{}{}", root.display(), name);
        for a in &t.actions {
            let mut e = Entry::new(Kind::ScheduledTask, &loc, name.clone(), a.clone());
            if t.hidden {
                e.notes.push("task is marked Hidden".into());
            }
            if let Some(u) = &t.run_as {
                e.notes.push(format!("runs as {u}{}", if t.highest { " (highest privileges)" } else { "" }));
            }
            if let Some(a) = &t.author {
                e.notes.push(format!("author: {a}"));
            }
            v.push(e);
        }
        for c in &t.com_handlers {
            if let Some(path) = clsid_server(c) {
                let mut e = Entry::new(Kind::ScheduledTask, &loc, format!("{name} (COM handler {c})"), path);
                if t.hidden {
                    e.notes.push("task is marked Hidden".into());
                }
                v.push(e);
            }
        }
    }

    // Tarrask: task registered in TaskCache but its security descriptor (SD) was deleted, so it is
    // invisible to schtasks / Task Scheduler UI while still running.
    let tree = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree";
    if let Some(k) = Key::open(HKEY_LOCAL_MACHINE, tree) {
        let mut stack = vec![(String::new(), k)];
        while let Some((path, key)) = stack.pop() {
            for sk in key.subkeys() {
                let Some(child) = key.sub(&sk) else { continue };
                let full = format!("{path}\\{sk}");
                if child.get("Id").is_some() {
                    if child.get("SD").is_none() {
                        let mut e = Entry::new(Kind::ScheduledTask, format!("HKLM\\{tree}{full}"), full.clone(), String::new());
                        e.floor = Severity::Critical;
                        e.notes.push("TaskCache entry has no SD value: task hidden from schtasks and the Task Scheduler UI (Tarrask)".into());
                        v.push(e);
                    } else if !on_disk.contains(&full.to_ascii_lowercase()) {
                        let mut e = Entry::new(Kind::ScheduledTask, format!("HKLM\\{tree}{full}"), full.clone(), String::new());
                        e.floor = Severity::Medium;
                        e.notes.push("task registered in TaskCache but its XML file is missing from System32\\Tasks".into());
                        v.push(e);
                    }
                }
                stack.push((full, child));
            }
        }
    }
}

fn startup_folders(v: &mut Vec<Entry>) {
    let mut dirs = vec![format!("{}\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp", expand_env("%ProgramData%"))];
    let users = format!("{}\\Users", expand_env("%SystemDrive%"));
    if let Ok(rd) = std::fs::read_dir(&users) {
        for u in rd.flatten() {
            dirs.push(format!("{}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", u.path().display()));
        }
    }
    for d in dirs {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for f in rd.flatten() {
            let p = f.path();
            let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            if name.eq_ignore_ascii_case("desktop.ini") || p.is_dir() {
                continue;
            }
            let ps = p.display().to_string();
            let mut e = Entry::new(Kind::StartupFolder, &d, name.clone(), ps.clone());
            if name.to_ascii_lowercase().ends_with(".lnk") {
                if let Some(l) = std::fs::read(&p).ok().and_then(|b| lnk::parse(&b)) {
                    if let Some(t) = l.target.filter(|t| !t.is_empty()) {
                        e.command = match &l.args {
                            Some(a) if !a.is_empty() => format!("\"{t}\" {a}"),
                            _ => format!("\"{t}\""),
                        };
                        e.notes.push(format!("shortcut file: {ps}"));
                    }
                }
            } else {
                e.target = Some(ps);
            }
            v.push(e);
        }
    }
}

/// Server DLL/EXE registered for a CLSID (machine-wide view).
fn clsid_server(clsid: &str) -> Option<String> {
    let c = clsid.trim();
    for root in [r"SOFTWARE\Classes\CLSID", r"SOFTWARE\Wow6432Node\Classes\CLSID"] {
        if let Some(k) = Key::open(HKEY_LOCAL_MACHINE, &format!("{root}\\{c}")) {
            for s in ["InprocServer32", "LocalServer32"] {
                if let Some(p) = k.sub(s).and_then(|x| x.str("")) {
                    return Some(p);
                }
            }
        }
    }
    None
}

/// Per-user CLSID registrations. One that shadows an existing machine-wide CLSID is a hijack.
fn com_hijack(v: &mut Vec<Entry>) {
    for sid in user_hives() {
        let base = format!(r"{sid}_Classes\CLSID");
        let Some(k) = Key::open(HKEY_USERS, &base) else { continue };
        for clsid in k.subkeys() {
            let Some(ck) = k.sub(&clsid) else { continue };
            for s in ["InprocServer32", "LocalServer32"] {
                let Some(path) = ck.sub(s).and_then(|x| x.str("")).filter(|p| !p.trim().is_empty()) else { continue };
                let shadows = Key::open(HKEY_LOCAL_MACHINE, &format!(r"SOFTWARE\Classes\CLSID\{clsid}")).is_some();
                let mut e = Entry::new(Kind::ComHijack, format!(r"HKU\{base}\{clsid}\{s}"), clsid.clone(), path);
                if shadows {
                    e.floor = Severity::High;
                    e.notes.push("per-user registration overrides a machine-wide CLSID".into());
                    if let Some(orig) = clsid_server(&clsid) {
                        e.notes.push(format!("machine-wide server: {orig}"));
                    }
                } else {
                    e.floor = Severity::Info;
                }
                v.push(e);
            }
        }
    }
}
