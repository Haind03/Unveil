//! Permanent WMI event subscriptions (filter -> consumer binding), a favourite fileless persistence.

use std::collections::HashMap;

use wmi::{Variant, WMIConnection};

use crate::core::persistrules::{Entry, Kind};
use crate::core::report::Severity;

type Row = HashMap<String, Variant>;

fn s(r: &Row, k: &str) -> String {
    match r.get(k) {
        Some(Variant::String(s)) => s.clone(),
        Some(Variant::Array(a)) => a.iter().filter_map(|v| if let Variant::String(s) = v { Some(s.clone()) } else { None }).collect::<Vec<_>>().join(" "),
        _ => String::new(),
    }
}

fn q(c: &WMIConnection, query: &str) -> Vec<Row> {
    c.raw_query::<Row>(query).unwrap_or_default()
}

pub fn collect() -> Vec<Entry> {
    // COM must be used from one thread; run on a dedicated one so the caller's apartment is untouched.
    std::thread::spawn(collect_inner).join().unwrap_or_default()
}

fn collect_inner() -> Vec<Entry> {
    let mut out = Vec::new();
    let Ok(c) = WMIConnection::with_namespace_path("ROOT\\subscription") else { return out };

    let filters: HashMap<String, String> = q(&c, "SELECT Name, Query FROM __EventFilter").iter().map(|r| (s(r, "Name"), s(r, "Query"))).collect();
    let bindings: Vec<(String, String)> =
        q(&c, "SELECT Filter, Consumer FROM __FilterToConsumerBinding").iter().map(|r| (s(r, "Filter"), s(r, "Consumer"))).collect();
    let filter_for = |consumer_name: &str| -> Vec<String> {
        bindings
            .iter()
            .filter(|(_, cons)| cons.contains(&format!("Name=\"{consumer_name}\"")))
            .filter_map(|(f, _)| {
                let name = f.split("Name=\"").nth(1)?.trim_end_matches('"');
                Some(format!("{name}: {}", filters.get(name).cloned().unwrap_or_default()))
            })
            .collect()
    };

    for r in q(&c, "SELECT Name, CommandLineTemplate, ExecutablePath FROM CommandLineEventConsumer") {
        let name = s(&r, "Name");
        let cmd = {
            let t = s(&r, "CommandLineTemplate");
            if t.is_empty() { s(&r, "ExecutablePath") } else { t }
        };
        let mut e = Entry::new(Kind::WmiSubscription, "ROOT\\subscription:CommandLineEventConsumer", name.clone(), cmd.clone());
        // Stock Windows ships one benign consumer.
        if name == "BVTConsumer" && (cmd.to_ascii_lowercase().contains("kernrate") || cmd.to_ascii_lowercase().contains("kerncap.vbs")) {
            continue;
        }
        e.floor = Severity::High;
        for f in filter_for(&name) {
            e.notes.push(format!("trigger: {f}"));
        }
        out.push(e);
    }
    for r in q(&c, "SELECT Name, ScriptingEngine, ScriptText, ScriptFileName FROM ActiveScriptEventConsumer") {
        let name = s(&r, "Name");
        let text = s(&r, "ScriptText");
        let file = s(&r, "ScriptFileName");
        let mut e = Entry::new(
            Kind::WmiSubscription,
            "ROOT\\subscription:ActiveScriptEventConsumer",
            name.clone(),
            if text.is_empty() { file.clone() } else { text },
        );
        if !file.is_empty() {
            e.target = Some(file);
        }
        e.floor = Severity::High;
        e.notes.push(format!("engine: {}", s(&r, "ScriptingEngine")));
        for f in filter_for(&name) {
            e.notes.push(format!("trigger: {f}"));
        }
        out.push(e);
    }
    out
}
