//! Orchestration of a hunt: phases, parallel per-process scanning, report output.

use std::collections::{HashMap, HashSet};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use super::ui::{self, Ui};
use super::{hidden, hooks, memory, persist, procs, sig, wmi_sub, FileCache};
use crate::core::paths::file_name;
use crate::core::persistrules::{self, Entry};
use crate::core::procrules;
use crate::core::report::{Report, Severity};
use crate::core::{html, ProcInfo, SigStatus};
use crate::{brand, Cli, Modules};

/// Run `f` over `items` on `workers` scoped threads (each with its own state from `init`) while
/// the calling thread draws the progress bar. A panic on one item drops that item only.
fn parallel<T, R, S, I, F, L>(ui: &Ui, items: &[T], workers: usize, label: L, init: I, f: F) -> Vec<R>
where
    T: Sync,
    R: Send,
    I: Fn() -> S + Sync,
    F: Fn(&mut S, &T) -> R + Sync,
    L: Fn(&T) -> String + Sync,
{
    let next = AtomicUsize::new(0);
    let done = AtomicUsize::new(0);
    let current = Mutex::new(String::new());
    let out: Mutex<Vec<(usize, R)>> = Mutex::new(Vec::with_capacity(items.len()));
    std::thread::scope(|s| {
        for _ in 0..workers.clamp(1, items.len().max(1)) {
            s.spawn(|| {
                let mut st = init();
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(it) = items.get(i) else { break };
                    *current.lock().unwrap() = label(it);
                    if let Ok(r) = catch_unwind(AssertUnwindSafe(|| f(&mut st, it))) {
                        out.lock().unwrap().push((i, r));
                    }
                    done.fetch_add(1, Ordering::Release);
                }
            });
        }
        loop {
            let d = done.load(Ordering::Acquire);
            let l = current.lock().unwrap().clone();
            ui.progress(d, items.len(), &l);
            if d >= items.len() {
                break;
            }
            std::thread::sleep(Duration::from_millis(120));
        }
    });
    let mut v = out.into_inner().unwrap();
    v.sort_by_key(|(i, _)| *i);
    v.into_iter().map(|(_, r)| r).collect()
}

struct Phases<'a> {
    ui: &'a Ui,
    names: Vec<&'static str>,
}

impl Phases<'_> {
    fn start(&self, name: &'static str) {
        let i = self.names.iter().position(|n| *n == name).map_or(0, |i| i + 1);
        self.ui.phase(i, self.names.len(), name);
    }
}

fn write_report(path: &Path, body: &str) -> std::io::Result<()> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(path, body)
}

/// Write to `path`; for default locations, fall back to the working directory if the exe folder
/// is read-only (e.g. run from a share or Program Files).
fn write_with_fallback(ui: &Ui, path: &Path, body: &str, fallback: bool) -> Option<PathBuf> {
    match write_report(path, body) {
        Ok(()) => Some(path.to_path_buf()),
        Err(e) if fallback => {
            let alt = std::env::current_dir().ok()?.join(path.file_name()?);
            match write_report(&alt, body) {
                Ok(()) => Some(alt),
                Err(e2) => {
                    ui.warn(&format!("cannot write {}: {e}; {}: {e2}", path.display(), alt.display()));
                    None
                }
            }
        }
        Err(e) => {
            ui.warn(&format!("cannot write {}: {e}", path.display()));
            None
        }
    }
}

fn is_microsoft(s: Option<&SigStatus>) -> bool {
    s.is_some_and(|s| s.microsoft())
}

pub fn run(cli: &Cli) -> i32 {
    let mods = Modules::select(cli.cmd, cli.no_yara, cfg!(feature = "yara"));
    let ui = Ui::new(cli.no_color, cli.quiet);
    let elevated = super::is_elevated();
    let debug = super::enable_debug_privilege();
    let host = super::hostname();
    let (started, stamp) = super::local_time();
    ui.banner(&host, elevated);
    // Forensic footprint controls (silent on failure: a lowered-privilege run should not abort).
    if cli.lowprio && super::footprint::enter_background_mode() {
        ui.info("running in background priority (--lowprio)");
    }
    if let Some(pct) = cli.cpu_limit {
        if super::footprint::cap_cpu(pct) {
            ui.info(&format!("CPU capped at {pct}% (--cpu-limit)"));
        } else {
            ui.warn(&format!("could not apply --cpu-limit {pct}% (Job Object creation refused)"));
        }
    }
    if !elevated {
        ui.warn("not elevated: run from an Administrator prompt to see protected and other users' processes");
    } else if !debug {
        ui.warn("SeDebugPrivilege could not be enabled: some processes will be inaccessible");
    }

    #[cfg(feature = "yara")]
    let compiling = mods.yara.then(|| crate::rules::compile_in_background(cli.rules.clone()));
    #[cfg(not(feature = "yara"))]
    if !cli.rules.is_empty() || cli.cmd == Some(crate::Cmd::Yara) {
        ui.warn("this build has no YARA support (built without the \"yara\" feature)");
    }

    let phases = Phases { ui: &ui, names: mods.phases() };
    let self_pid = std::process::id();
    let self_exe = std::env::current_exe().ok().map(|p| p.display().to_string().to_ascii_lowercase());
    let mut report = Report {
        tool: brand::NAME,
        version: brand::VERSION,
        host: host.clone(),
        started,
        elevated,
        ..Default::default()
    };

    // 1. Processes.
    phases.start(crate::PH_PROCS);
    let raw = procs::snapshot();
    if raw.is_empty() {
        ui.warn("NtQuerySystemInformation returned no processes");
    }
    let mut ps = procs::collect(&raw);
    ui.info(&format!("{} processes, {} threads", ps.len(), ps.iter().map(|p| p.threads.len()).sum::<usize>()));
    // Workers are sized once we know the input volume: per-phase they are capped by that phase's
    // item count anyway, so --threads 16 on a six-process host still ends up as six workers.
    let workers = crate::core::sched::worker_count(ps.len(), cli.threads, 16);
    if mods.processes || mods.yara {
        let mut seen = HashSet::new();
        let paths: Vec<String> =
            ps.iter().filter_map(|p| p.path.clone()).filter(|p| super::file_exists(p) && seen.insert(p.to_ascii_lowercase())).collect();
        let sigs = parallel(&ui, &paths, workers, |p| file_name(p).to_string(), || (), |_, p| (p.to_ascii_lowercase(), sig::check(p)));
        let sigs: HashMap<String, SigStatus> = sigs.into_iter().collect();
        for p in &mut ps {
            if let Some(path) = &p.path {
                p.signature = sigs.get(&path.to_ascii_lowercase()).cloned();
            }
        }
        ui.info(&format!("{} process images verified (Authenticode, offline)", sigs.len()));
    }
    if mods.processes {
        let mut instances: HashMap<String, usize> = HashMap::new();
        for p in &ps {
            *instances.entry(p.name.to_ascii_lowercase()).or_default() += 1;
        }
        let by_pid: HashMap<u32, &ProcInfo> = ps.iter().map(|p| (p.pid, p)).collect();
        for p in &ps {
            // A parent PID can be reused: only trust a parent created before the child.
            let parent = by_pid.get(&p.ppid).copied().filter(|par| par.pid != p.pid && par.create_time <= p.create_time);
            let n = instances.get(&p.name.to_ascii_lowercase()).copied().unwrap_or(1);
            report.findings.extend(procrules::analyze(p, parent, n));
        }
    }
    report.processes_scanned = ps.len();
    // Scan the heaviest processes first (thread count is a cheap proxy for VAD + YARA cost), so
    // the final tail is small items that finish together across all workers instead of one
    // giant process holding up the last 30% of each phase.
    let mut targets: Vec<&ProcInfo> = ps.iter().filter(|p| p.pid > 4 && (cli.pid.is_empty() || cli.pid.contains(&p.pid))).collect();
    let order = crate::core::sched::heavy_first(&targets, |p| p.threads.len() as u64);
    targets = order.into_iter().map(|i| targets[i]).collect();

    // 2. Memory and hooks, one handle and one VAD walk per process.
    if mods.memory || mods.hooks {
        phases.start(crate::PH_MEMORY);
        let cache = FileCache::default();
        let res = parallel(&ui, &targets, workers, |p| p.name.clone(), || (), |_, p| {
            let h = procs::open(p.pid, true)?;
            let pm = memory::collect(h.0);
            let mut out = Vec::new();
            // Our own process hosts the YARA engine's JIT code: memory rules would flag it.
            if mods.memory && p.pid != self_pid {
                out.extend(memory::analyze(p, h.0, &pm, &cache));
            }
            if mods.hooks {
                out.extend(hooks::analyze(p, h.0, &pm, &cache, cli.deep, self_pid));
            }
            Some(out)
        });
        let opened = res.iter().filter(|r| r.is_some()).count();
        let n0 = report.findings.len();
        report.findings.extend(res.into_iter().flatten().flatten());
        ui.info(&format!(
            "{opened}/{} processes inspected, {} findings{}",
            targets.len(),
            report.findings.len() - n0,
            if opened < targets.len() { format!(" ({} protected or inaccessible)", targets.len() - opened) } else { String::new() }
        ));
    }

    // 3. Hidden processes.
    if mods.hidden {
        phases.start(crate::PH_HIDDEN);
        let listed: HashSet<u32> = raw.iter().map(|p| p.pid).collect();
        let f = hidden::scan(&listed);
        ui.info(&format!("{} hidden process(es)", f.len()));
        report.findings.extend(f);
    }

    // 4. Autostart entries (also the file list for the YARA file scan).
    let mut entries: Vec<Entry> = Vec::new();
    if mods.persistence || mods.yara {
        phases.start(crate::PH_PERSIST);
        let mut raw_entries = persist::collect();
        raw_entries.extend(wmi_sub::collect());
        entries = parallel(&ui, &raw_entries, workers, |e| e.name.clone(), || (), |_, e| persist::resolve(e.clone(), true));
        ui.info(&format!("{} autostart entries", entries.len()));
        if mods.persistence {
            report.findings.extend(entries.iter().map(persistrules::assess));
        }
    }

    // 5-6. YARA.
    #[cfg(feature = "yara")]
    if let Some(handle) = compiling {
        if !handle.is_finished() {
            ui.info("waiting for the YARA rules to finish compiling...");
        }
        match handle.join() {
            Ok(rs) => {
                ui.info(&format!("{} YARA rules from {} files, compiled in {:.1}s", rs.rule_count, rs.files_ok, rs.compile_secs));
                for (f, e) in rs.skipped.iter().take(10) {
                    ui.warn(&format!("skipped rule file {f}: {e}"));
                }
                if rs.skipped.len() > 10 {
                    ui.warn(&format!("... and {} more rule files skipped", rs.skipped.len() - 10));
                }
                yara_phases(cli, &ui, &phases, &rs, &targets, &ps, &entries, workers, self_pid, self_exe.as_deref(), &mut report);
            }
            Err(_) => ui.warn("YARA rule compilation failed; YARA phases skipped"),
        }
    }
    #[cfg(not(feature = "yara"))]
    let _ = (&entries, &self_exe);

    // Output.
    report.sort();
    let code = crate::exit_code(report.max_severity());
    let total = report.findings.len();
    report.findings.retain(|f| f.severity >= cli.min_severity);
    report.print(cli.min_severity, ui.color);
    if total > report.findings.len() {
        println!("{}{} findings below --min-severity {} not shown{}", ui.c(ui::DIM), total - report.findings.len(), cli.min_severity.to_string().to_lowercase(), ui.c(ui::RESET));
    }
    let (crit, high) = (report.count(Severity::Critical), report.count(Severity::High));
    if code == 2 {
        println!(
            "{}{}VERDICT: {crit} critical, {high} high - investigate this host{}",
            ui.c(ui::BOLD),
            ui.c(ui::RED),
            ui.c(ui::RESET)
        );
    } else {
        println!("{}{}VERDICT: no high or critical findings{}", ui.c(ui::BOLD), ui.c(ui::GREEN), ui.c(ui::RESET));
    }

    let duration = ui.elapsed();
    let exe_dir = std::env::current_exe().ok().and_then(|p| p.parent().map(Path::to_path_buf)).unwrap_or_else(|| PathBuf::from("."));
    let (json_path, html_path) = crate::report_targets(cli, &exe_dir, &host, &stamp);
    let default_paths = cli.json.is_none() && cli.html.is_none();
    if let Some(p) = json_path {
        let mut v = serde_json::to_value(&report).unwrap_or_default();
        if let Some(o) = v.as_object_mut() {
            o.insert("duration".into(), serde_json::json!(duration));
            o.insert("author".into(), serde_json::json!(brand::AUTHOR));
            o.insert("min_severity".into(), serde_json::json!(cli.min_severity));
        }
        let body = serde_json::to_string_pretty(&v).unwrap_or_default();
        if crate::is_stdout(&p) {
            // Zero-footprint mode: operator pipes the JSON somewhere off the host.
            use std::io::Write as _;
            let _ = std::io::stdout().write_all(body.as_bytes());
            let _ = std::io::stdout().write_all(b"\n");
        } else if let Some(w) = write_with_fallback(&ui, &p, &body, default_paths) {
            println!("{}JSON report:{} {}", ui.c(ui::DIM), ui.c(ui::RESET), w.display());
        }
    }
    if let Some(p) = html_path {
        if crate::is_stdout(&p) {
            ui.warn("--html - is not supported; HTML must go to a file");
        } else if let Some(w) = write_with_fallback(&ui, &p, &html::render(&report, duration), default_paths) {
            println!("{}HTML report:{} {}", ui.c(ui::DIM), ui.c(ui::RESET), w.display());
        }
    }
    println!("{}Done in {duration:.1}s.{}", ui.c(ui::DIM), ui.c(ui::RESET));
    code
}

#[cfg(feature = "yara")]
#[allow(clippy::too_many_arguments)]
fn yara_phases(
    cli: &Cli,
    ui: &Ui,
    phases: &Phases,
    rs: &crate::rules::RuleSet,
    targets: &[&ProcInfo],
    ps: &[ProcInfo],
    entries: &[Entry],
    workers: usize,
    self_pid: u32,
    self_exe: Option<&str>,
    report: &mut Report,
) {
    use super::yara;

    phases.start(crate::PH_YARA_MEM);
    let res = parallel(ui, targets, workers, |p| p.name.clone(), || crate::rules::scanner(rs), |sc, p| {
        if p.pid == self_pid {
            return Vec::new();
        }
        let Some(h) = procs::open(p.pid, true) else { return Vec::new() };
        let pm = memory::collect(h.0);
        yara::scan_memory(p, h.0, &pm, sc, cli.deep)
    });
    let hits: Vec<_> = res.into_iter().flatten().collect();
    ui.info(&format!("{} memory matches", hits.len()));
    report.findings.extend(hits);

    phases.start(crate::PH_YARA_FILES);
    // Microsoft-signed files are skipped unless --deep: they are not where payloads hide, and the
    // embedded rule set is large.
    let mut seen = HashSet::new();
    if let Some(s) = self_exe {
        seen.insert(s.to_string()); // unveil.exe itself embeds every rule's strings
    }
    let mut files: Vec<(String, String)> = Vec::new();
    for p in ps {
        let Some(path) = &p.path else { continue };
        if (cli.deep || !is_microsoft(p.signature.as_ref())) && p.image_exists && seen.insert(path.to_ascii_lowercase()) {
            files.push((path.clone(), format!("image of {} [pid {}]", p.name, p.pid)));
        }
    }
    for e in entries {
        let Some(t) = &e.target else { continue };
        if e.target_exists == Some(true) && (cli.deep || !is_microsoft(e.signature.as_ref())) && seen.insert(t.to_ascii_lowercase()) {
            files.push((t.clone(), format!("{} target ({})", e.kind.label(), e.name)));
        }
    }
    let res = parallel(ui, &files, workers, |(p, _)| file_name(p).to_string(), || crate::rules::scanner(rs), |sc, (p, why)| {
        yara::scan_file(p, why, sc)
    });
    let hits: Vec<_> = res.into_iter().flatten().collect();
    ui.info(&format!("{} files scanned, {} matches", files.len(), hits.len()));
    report.findings.extend(hits);
}
