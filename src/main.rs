//! Unveil - live Windows threat hunting.
//! by HaiND from the Post and Telecommunication Institute of Technology

// Collectors live in `win` (Windows only); on other targets only the core logic and its tests build.
#![cfg_attr(not(windows), allow(dead_code))]

mod brand;
mod core;
#[cfg(feature = "yara")]
mod rules;
#[cfg(windows)]
mod win;

use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};

use crate::core::report::Severity;

/// Rule files and third-party license texts, embedded by build.rs.
#[allow(dead_code)]
mod embedded {
    include!(concat!(env!("OUT_DIR"), "/embedded_rules.rs"));
}

const EXAMPLES: &str = "\
Examples:
  unveil                              full hunt, reports written next to unveil.exe
  unveil --deep --min-severity medium full hunt, every module checked for hooks, all JIT memory scanned
  unveil memory --pid 1234            injected code / hollowing checks for one process
  unveil persistence --json auto.json autostart review only, JSON report
  unveil yara --rules C:\\IR\\rules     YARA only, with extra rules from a file or folder
  unveil licenses                     third-party YARA rule licenses

Exit codes: 0 = nothing high or critical, 1 = error, 2 = high or critical findings.
Run from an elevated prompt (Administrator) for full coverage.";

#[derive(Parser, Debug)]
#[command(
    name = "unveil",
    version,
    author = brand::AUTHOR,
    about = "Live Windows threat hunting: injected code, process hollowing, inline hooks, hidden processes and stealthy persistence",
    long_about = None,
    after_help = EXAMPLES
)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Option<Cmd>,

    /// Slower, wider hunt: check every loaded module for hooks, YARA-scan all executable memory
    /// of JIT processes, include Microsoft-signed files in YARA file scans.
    #[arg(long, global = true)]
    pub deep: bool,

    /// Write the JSON report to this file.
    #[arg(long, global = true, value_name = "FILE")]
    pub json: Option<PathBuf>,

    /// Write the HTML report to this file.
    #[arg(long, global = true, value_name = "FILE")]
    pub html: Option<PathBuf>,

    /// Do not write any report file (console output only).
    #[arg(long, global = true, conflicts_with_all = ["json", "html"])]
    pub no_report: bool,

    /// Lowest severity shown and written to reports: info, low, medium, high, critical.
    #[arg(long, global = true, value_name = "LEVEL", default_value = "low", value_parser = parse_severity)]
    pub min_severity: Severity,

    /// Disable ANSI colors (also honoured: NO_COLOR environment variable).
    #[arg(long, global = true)]
    pub no_color: bool,

    /// Extra YARA rules: a .yar/.yara file or a folder (searched recursively). Repeatable.
    #[arg(long, global = true, value_name = "PATH")]
    pub rules: Vec<PathBuf>,

    /// Skip YARA scanning in a full hunt.
    #[arg(long, global = true)]
    pub no_yara: bool,

    /// Only scan these process IDs in the per-process phases. Repeatable.
    #[arg(long, global = true, value_name = "PID")]
    pub pid: Vec<u32>,

    /// Worker threads for per-process and file scans (default: number of CPUs, max 16).
    #[arg(long, global = true, value_name = "N")]
    pub threads: Option<usize>,

    /// Print only the findings and the summary.
    #[arg(short, long, global = true)]
    pub quiet: bool,
}

#[derive(Subcommand, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cmd {
    /// Full hunt (same as no subcommand).
    Scan,
    /// Process anomalies: masquerading, wrong path or parent, LOLBin command lines, signatures.
    Processes,
    /// Injected code, reflective PE, hollowing, unbacked threads, unlinked DLLs.
    Memory,
    /// Inline hooks and patches in ntdll, kernel32, AMSI, ETW and other APIs.
    Hooks,
    /// Processes hidden from the system process list (cross-view).
    Hidden,
    /// Autostart locations: registry, services, drivers, tasks, startup folders, WMI, COM.
    Persistence,
    /// YARA scan of suspicious process memory, process images and autostart files.
    Yara,
    /// Print the licenses of the embedded third-party YARA rules.
    Licenses,
}

fn parse_severity(s: &str) -> Result<Severity, String> {
    Severity::parse(s).ok_or_else(|| format!("unknown severity '{s}' (info, low, medium, high, critical)"))
}

/// Which hunting modules run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Modules {
    pub processes: bool,
    pub memory: bool,
    pub hooks: bool,
    pub hidden: bool,
    pub persistence: bool,
    pub yara: bool,
}

impl Modules {
    pub fn select(cmd: Option<Cmd>, no_yara: bool, yara_built: bool) -> Modules {
        let none = Modules::default();
        match cmd {
            None | Some(Cmd::Scan) => Modules {
                processes: true,
                memory: true,
                hooks: true,
                hidden: true,
                persistence: true,
                yara: yara_built && !no_yara,
            },
            Some(Cmd::Processes) => Modules { processes: true, ..none },
            Some(Cmd::Memory) => Modules { memory: true, ..none },
            Some(Cmd::Hooks) => Modules { hooks: true, ..none },
            Some(Cmd::Hidden) => Modules { hidden: true, ..none },
            Some(Cmd::Persistence) => Modules { persistence: true, ..none },
            Some(Cmd::Yara) => Modules { yara: yara_built, ..none },
            Some(Cmd::Licenses) => none,
        }
    }

    /// Console phases, in order. YARA runs last so rule compilation overlaps the other phases.
    pub fn phases(&self) -> Vec<&'static str> {
        let mut v = vec![PH_PROCS];
        if self.memory || self.hooks {
            v.push(PH_MEMORY);
        }
        if self.hidden {
            v.push(PH_HIDDEN);
        }
        if self.persistence || self.yara {
            v.push(PH_PERSIST);
        }
        if self.yara {
            v.push(PH_YARA_MEM);
            v.push(PH_YARA_FILES);
        }
        v
    }
}

pub const PH_PROCS: &str = "Enumerating processes";
pub const PH_MEMORY: &str = "Hunting in process memory (injection, hollowing, hooks)";
pub const PH_HIDDEN: &str = "Cross-view hidden process check";
pub const PH_PERSIST: &str = "Collecting autostart entries";
pub const PH_YARA_MEM: &str = "YARA scan of suspicious process memory";
pub const PH_YARA_FILES: &str = "YARA scan of process images and autostart files";

/// Keep host names safe for a file name.
fn sanitize(s: &str) -> String {
    let t: String = s.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect();
    if t.is_empty() { "host".into() } else { t }
}

/// `<dir>/unveil_<HOST>_<YYYYMMDD-HHMMSS>.{json,html}`
pub fn default_report_paths(dir: &Path, host: &str, stamp: &str) -> (PathBuf, PathBuf) {
    let base = format!("unveil_{}_{}", sanitize(host), stamp);
    (dir.join(format!("{base}.json")), dir.join(format!("{base}.html")))
}

/// Report destinations: the explicit `--json` / `--html` files, or both next to the exe by default.
pub fn report_targets(cli: &Cli, exe_dir: &Path, host: &str, stamp: &str) -> (Option<PathBuf>, Option<PathBuf>) {
    if cli.no_report {
        return (None, None);
    }
    if cli.json.is_some() || cli.html.is_some() {
        return (cli.json.clone(), cli.html.clone());
    }
    let (j, h) = default_report_paths(exe_dir, host, stamp);
    (Some(j), Some(h))
}

/// 2 when any high or critical finding exists, else 0.
pub fn exit_code(max: Option<Severity>) -> i32 {
    match max {
        Some(s) if s >= Severity::High => 2,
        _ => 0,
    }
}

pub fn worker_count(requested: Option<usize>) -> usize {
    let cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
    requested.unwrap_or(cpus).clamp(1, 16)
}

fn print_licenses() {
    println!("{} {} - by {}", brand::NAME, brand::VERSION, brand::AUTHOR);
    println!("Unveil's own code and rules/custom are MIT licensed. Embedded third-party YARA rules:\n");
    for (path, text) in embedded::LICENSES {
        println!("===== rules/{path} =====\n{text}\n");
    }
}

fn main() {
    // Usage errors exit with 1: exit code 2 is reserved for "high or critical findings".
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            let _ = e.print();
            std::process::exit(if e.use_stderr() { 1 } else { 0 });
        }
    };
    if cli.cmd == Some(Cmd::Licenses) {
        print_licenses();
        return;
    }
    #[cfg(windows)]
    {
        std::process::exit(win::hunt::run(&cli));
    }
    #[cfg(not(windows))]
    {
        let _ = Modules::select(cli.cmd, cli.no_yara, cfg!(feature = "yara"));
        eprintln!("{} hunts on live Windows hosts; this build targets {}.", brand::NAME, std::env::consts::OS);
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(std::iter::once("unveil").chain(args.iter().copied())).unwrap()
    }

    #[test]
    fn no_args_is_full_scan() {
        let c = parse(&[]);
        let m = Modules::select(c.cmd, c.no_yara, true);
        assert!(m.processes && m.memory && m.hooks && m.hidden && m.persistence && m.yara);
        assert_eq!(c.min_severity, Severity::Low);
        assert_eq!(m.phases(), vec![PH_PROCS, PH_MEMORY, PH_HIDDEN, PH_PERSIST, PH_YARA_MEM, PH_YARA_FILES]);
    }

    #[test]
    fn subcommands_select_one_module() {
        let m = Modules::select(parse(&["hooks"]).cmd, false, true);
        assert_eq!(m, Modules { hooks: true, ..Default::default() });
        assert_eq!(m.phases(), vec![PH_PROCS, PH_MEMORY]);
        let m = Modules::select(parse(&["persistence"]).cmd, false, true);
        assert_eq!(m.phases(), vec![PH_PROCS, PH_PERSIST]);
        let m = Modules::select(parse(&["yara"]).cmd, false, true);
        assert!(m.yara && !m.memory);
        // Autostart targets are collected for the file scan even though persistence is not reported.
        assert_eq!(m.phases(), vec![PH_PROCS, PH_PERSIST, PH_YARA_MEM, PH_YARA_FILES]);
    }

    #[test]
    fn yara_off_when_not_built_or_disabled() {
        assert!(!Modules::select(None, true, true).yara);
        assert!(!Modules::select(None, false, false).yara);
        assert!(!Modules::select(Some(Cmd::Yara), false, false).yara);
    }

    #[test]
    fn flags_are_global_and_parsed() {
        let c = parse(&["memory", "--deep", "--min-severity", "HIGH", "--pid", "4242", "--pid", "7", "--no-color", "--rules", "x.yar"]);
        assert_eq!(c.cmd, Some(Cmd::Memory));
        assert!(c.deep && c.no_color);
        assert_eq!(c.min_severity, Severity::High);
        assert_eq!(c.pid, vec![4242, 7]);
        assert_eq!(c.rules, vec![PathBuf::from("x.yar")]);
        assert!(Cli::try_parse_from(["unveil", "--min-severity", "loud"]).is_err());
        assert!(Cli::try_parse_from(["unveil", "--no-report", "--json", "a.json"]).is_err());
    }

    #[test]
    fn reports_default_next_to_exe() {
        let dir = Path::new("C:/Tools");
        let c = parse(&[]);
        let (j, h) = report_targets(&c, dir, "WS-01.corp", "20261011-153000");
        assert_eq!(j.unwrap(), dir.join("unveil_WS-01_corp_20261011-153000.json"));
        assert_eq!(h.unwrap(), dir.join("unveil_WS-01_corp_20261011-153000.html"));

        let c = parse(&["--json", "out.json"]);
        assert_eq!(report_targets(&c, dir, "h", "s"), (Some(PathBuf::from("out.json")), None));
        let c = parse(&["--no-report"]);
        assert_eq!(report_targets(&c, dir, "h", "s"), (None, None));
        assert_eq!(sanitize(""), "host");
    }

    #[test]
    fn exit_code_reflects_high_findings() {
        assert_eq!(exit_code(None), 0);
        assert_eq!(exit_code(Some(Severity::Medium)), 0);
        assert_eq!(exit_code(Some(Severity::High)), 2);
        assert_eq!(exit_code(Some(Severity::Critical)), 2);
    }

    #[test]
    fn workers_are_bounded() {
        assert_eq!(worker_count(Some(0)), 1);
        assert_eq!(worker_count(Some(64)), 16);
        assert!((1..=16).contains(&worker_count(None)));
    }

    #[test]
    fn brand_is_consistent() {
        assert_eq!(brand::AUTHOR, "HaiND from the Post and Telecommunication Institute of Technology");
        assert!(!embedded::LICENSES.is_empty());
    }
}
