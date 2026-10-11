//! Scoring of autostart entries collected from the registry, task store, WMI and startup folders.

use serde::Serialize;

use super::paths::{command_target, file_name, in_system_dir, is_script, normalize, suspicious_dir};
use super::procrules::{cmdline_findings, truncate};
use super::report::{Category, Finding, Severity};
use super::SigStatus;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Kind {
    RunKey,
    Winlogon,
    Ifeo,
    SilentProcessExit,
    AppInit,
    AppCert,
    Lsa,
    PrintMonitor,
    NetshHelper,
    CmdAutoRun,
    BootExecute,
    ActiveSetup,
    Service,
    Driver,
    ScheduledTask,
    StartupFolder,
    WmiSubscription,
    ComHijack,
    Screensaver,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::RunKey => "Run key",
            Kind::Winlogon => "Winlogon",
            Kind::Ifeo => "IFEO debugger",
            Kind::SilentProcessExit => "SilentProcessExit monitor",
            Kind::AppInit => "AppInit_DLLs",
            Kind::AppCert => "AppCertDlls",
            Kind::Lsa => "LSA package",
            Kind::PrintMonitor => "Print monitor",
            Kind::NetshHelper => "Netsh helper",
            Kind::CmdAutoRun => "cmd.exe AutoRun",
            Kind::BootExecute => "BootExecute",
            Kind::ActiveSetup => "Active Setup",
            Kind::Service => "Service",
            Kind::Driver => "Driver",
            Kind::ScheduledTask => "Scheduled task",
            Kind::StartupFolder => "Startup folder",
            Kind::WmiSubscription => "WMI event subscription",
            Kind::ComHijack => "COM hijack",
            Kind::Screensaver => "Screensaver",
        }
    }

    fn mitre(self) -> &'static [&'static str] {
        match self {
            Kind::RunKey | Kind::StartupFolder => &["T1547.001"],
            Kind::Winlogon => &["T1547.004"],
            Kind::Ifeo | Kind::SilentProcessExit => &["T1546.012"],
            Kind::AppInit => &["T1546.010"],
            Kind::AppCert => &["T1546.009"],
            Kind::Lsa => &["T1547.002", "T1547.005"],
            Kind::PrintMonitor => &["T1547.010"],
            Kind::NetshHelper => &["T1546.007"],
            Kind::CmdAutoRun => &["T1546"],
            Kind::BootExecute => &["T1547.001"],
            Kind::ActiveSetup => &["T1547.014"],
            Kind::Service => &["T1543.003"],
            Kind::Driver => &["T1543.003", "T1014"],
            Kind::ScheduledTask => &["T1053.005"],
            Kind::WmiSubscription => &["T1546.003"],
            Kind::ComHijack => &["T1546.015"],
            Kind::Screensaver => &["T1546.002"],
        }
    }

    /// Mechanisms that are empty on a clean machine: anything present deserves a look.
    fn rare(self) -> bool {
        matches!(
            self,
            Kind::Ifeo | Kind::SilentProcessExit | Kind::AppInit | Kind::AppCert | Kind::CmdAutoRun | Kind::WmiSubscription
        )
    }
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub kind: Kind,
    /// Registry key, file path or WMI object that holds the entry.
    pub location: String,
    pub name: String,
    /// What runs (command line, DLL path, script text...).
    pub command: String,
    /// Resolved target file (after env expansion), if any.
    pub target: Option<String>,
    pub target_exists: Option<bool>,
    pub signature: Option<SigStatus>,
    pub notes: Vec<String>,
    /// Severity floor set by the collector (e.g. HKCU CLSID shadowing an HKLM one).
    pub floor: Severity,
}

impl Entry {
    pub fn new(kind: Kind, location: impl Into<String>, name: impl Into<String>, command: impl Into<String>) -> Self {
        Entry {
            kind,
            location: location.into(),
            name: name.into(),
            command: command.into(),
            target: None,
            target_exists: None,
            signature: None,
            notes: Vec::new(),
            floor: Severity::Info,
        }
    }

    pub fn guess_target(&self) -> Option<String> {
        command_target(&self.command)
    }
}

pub fn assess(e: &Entry) -> Finding {
    let mut sev = if e.kind.rare() { Severity::Medium } else { e.floor.max(Severity::Info) };
    sev = sev.max(e.floor);
    let mut reasons: Vec<String> = Vec::new();
    let mut extra_mitre: Vec<&'static str> = Vec::new();

    let target = e.target.clone().or_else(|| e.guess_target());
    let tname = target.as_deref().map(|t| file_name(t).to_ascii_lowercase()).unwrap_or_default();

    // Command-line heuristics reuse the process rules (encoded PowerShell, LOLBins...).
    for f in cmdline_findings(&tname, &e.command) {
        if f.severity > sev {
            sev = f.severity;
        }
        reasons.push(f.title);
        extra_mitre.extend(f.mitre);
    }
    let lc = e.command.to_ascii_lowercase();
    // Proxy launchers and script hosts started from autoruns.
    let launcher = ["powershell", "pwsh", "mshta", "wscript", "cscript", "rundll32", "regsvr32", "cmd.exe", "cmd /c", "certutil", "bitsadmin", "msiexec"]
        .iter()
        .find(|k| lc.contains(**k));
    if let Some(k) = launcher {
        if !matches!(e.kind, Kind::ScheduledTask | Kind::Service) || !in_system_dir(target.as_deref().unwrap_or("")) || *k != "rundll32" {
            sev = sev.max(Severity::Medium);
            reasons.push(format!("autostart uses {k}"));
        }
    }
    if lc.contains("http://") || lc.contains("https://") {
        sev = sev.max(Severity::High);
        reasons.push("command contains a URL".into());
    }

    if let Some(t) = &target {
        if let Some(why) = suspicious_dir(t) {
            sev = sev.max(Severity::Medium);
            reasons.push(format!("target in {why}"));
        }
        if is_script(t) {
            sev = sev.max(Severity::Medium);
            reasons.push("target is a script".into());
        }
    }

    match &e.signature {
        Some(SigStatus::Invalid(why)) => {
            sev = sev.max(Severity::High);
            reasons.push(format!("invalid signature: {why}"));
        }
        Some(SigStatus::Unsigned) => {
            if sev >= Severity::Medium {
                sev = sev.bump();
            } else {
                sev = sev.max(Severity::Low);
            }
            reasons.push("target is unsigned".into());
        }
        _ => {}
    }
    if e.target_exists == Some(false) {
        sev = sev.max(Severity::Low);
        reasons.push("target file does not exist (dangling or deleted payload)".into());
    }
    // Microsoft-signed system binaries without other signals stay informational.
    if reasons.is_empty() && e.signature.as_ref().is_some_and(|s| s.microsoft()) && !e.kind.rare() {
        sev = e.floor;
    }

    let mut f = Finding::new(sev, Category::Persistence, format!("{}: {}", e.kind.label(), e.name))
        .detail(format!("location: {}", e.location))
        .detail(format!("command: {}", truncate(&e.command, 500)))
        .mitre(e.kind.mitre());
    if let Some(t) = &target {
        f = f.path(t.clone());
    }
    if let Some(SigStatus::Signed(Some(s))) = &e.signature {
        f = f.detail(format!("signer: {s}"));
    }
    for r in reasons {
        f = f.detail(r);
    }
    for n in &e.notes {
        f = f.detail(n.clone());
    }
    extra_mitre.sort();
    extra_mitre.dedup();
    for m in extra_mitre {
        if !f.mitre.contains(&m) {
            f.mitre.push(m);
        }
    }
    f
}

/// Default Windows values. Anything else in these slots is reported.
pub const WINLOGON_SHELL: &str = "explorer.exe";
pub const WINLOGON_USERINIT: &str = "c:\\windows\\system32\\userinit.exe,";
pub const BOOTEXECUTE_DEFAULT: &str = "autocheck autochk *";

pub const LSA_DEFAULT_PACKAGES: &[&str] = &[
    "msv1_0", "kerberos", "negoextender", "pku2u", "schannel", "wdigest", "tspkg", "cloudap", "livessp", "wsauth", "rassfm",
    "scecli", "\"\"", "", "msoidssp", "kdcsvc",
];

pub fn lsa_package_unusual(pkg: &str) -> bool {
    let p = normalize(pkg);
    let p = p.trim_end_matches(".dll");
    !LSA_DEFAULT_PACKAGES.contains(&p)
}

pub const NETSH_DEFAULT: &[&str] = &[
    "ifmon.dll", "rasmontr.dll", "authfwcfg.dll", "dhcpcmonitor.dll", "dot3cfg.dll", "fwcfg.dll", "hnetmon.dll",
    "netiohlp.dll", "nettrace.dll", "nshhttp.dll", "nshipsec.dll", "nshwfp.dll", "p2pnetsh.dll", "rpcnsh.dll", "whhelper.dll",
    "wlancfg.dll", "wshelper.dll", "wwancfg.dll", "peerdistsh.dll", "napmontr.dll", "dhcpmonitor.dll",
];

pub fn netsh_unusual(dll: &str) -> bool {
    !NETSH_DEFAULT.contains(&file_name(dll).to_ascii_lowercase().as_str())
}

pub const PRINT_MONITOR_DEFAULT: &[&str] = &["localspl.dll", "tcpmon.dll", "usbmon.dll", "wsdmon.dll", "appmon.dll", "fxsmon.dll", "apmon.dll", "inetpp.dll"];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn benign_run_key_is_info() {
        let mut e = Entry::new(Kind::RunKey, "HKLM\\...\\Run", "SecurityHealth", r"%windir%\system32\SecurityHealthSystray.exe");
        e.target = Some(r"C:\Windows\system32\SecurityHealthSystray.exe".into());
        e.signature = Some(SigStatus::Signed(Some("Microsoft Windows".into())));
        e.target_exists = Some(true);
        assert_eq!(assess(&e).severity, Severity::Info);
    }

    #[test]
    fn encoded_powershell_run_key_is_high() {
        let e = Entry::new(Kind::RunKey, "HKCU\\...\\Run", "Updater", "powershell.exe -w hidden -nop -enc SQBFAFgA");
        assert!(assess(&e).severity >= Severity::High);
    }

    #[test]
    fn unsigned_temp_payload_is_high() {
        let mut e = Entry::new(Kind::RunKey, "HKCU\\...\\Run", "x", r"C:\Users\a\AppData\Local\Temp\x.exe");
        e.signature = Some(SigStatus::Unsigned);
        assert_eq!(assess(&e).severity, Severity::High);
    }

    #[test]
    fn ifeo_is_at_least_medium() {
        let e = Entry::new(Kind::Ifeo, "HKLM\\...\\sethc.exe", "sethc.exe", r"C:\Windows\System32\cmd.exe");
        assert!(assess(&e).severity >= Severity::Medium);
    }

    #[test]
    fn lsa_defaults() {
        assert!(!lsa_package_unusual("kerberos"));
        assert!(lsa_package_unusual("mimilib"));
    }
}
