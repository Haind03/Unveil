//! Scheduled task XML (Task Scheduler 2.0 format) - just the fields a hunter needs.

#[derive(Debug, Default, Clone)]
pub struct TaskDef {
    pub actions: Vec<String>,
    pub com_handlers: Vec<String>,
    pub hidden: bool,
    pub author: Option<String>,
    pub run_as: Option<String>,
    pub highest: bool,
}

pub fn decode(raw: &[u8]) -> String {
    if raw.starts_with(&[0xFF, 0xFE]) {
        let u: Vec<u16> = raw[2..].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        String::from_utf16_lossy(&u)
    } else if raw.len() >= 2 && raw[1] == 0 && raw[0] == b'<' {
        let u: Vec<u16> = raw.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        String::from_utf16_lossy(&u)
    } else {
        String::from_utf8_lossy(raw.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(raw)).into_owned()
    }
}

fn unescape(s: &str) -> String {
    s.replace("&quot;", "\"").replace("&apos;", "'").replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
}

/// All inner texts of <tag>...</tag> (no nesting of the same tag in task XML).
fn all(xml: &str, tag: &str) -> Vec<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(i) = rest.find(&open) {
        let after = &rest[i + open.len()..];
        let Some(j) = after.find(&close) else { break };
        out.push(unescape(after[..j].trim()));
        rest = &after[j + close.len()..];
    }
    out
}

fn first(xml: &str, tag: &str) -> Option<String> {
    all(xml, tag).into_iter().next()
}

pub fn parse(xml: &str) -> TaskDef {
    let mut t = TaskDef::default();
    for exec in all(xml, "Exec") {
        let cmd = first(&exec, "Command").unwrap_or_default();
        let args = first(&exec, "Arguments").unwrap_or_default();
        let cmd = if cmd.contains(' ') && !cmd.starts_with('"') { format!("\"{cmd}\"") } else { cmd };
        t.actions.push(if args.is_empty() { cmd } else { format!("{cmd} {args}") });
    }
    t.com_handlers = all(xml, "ComHandler").iter().filter_map(|c| first(c, "ClassId")).collect();
    t.hidden = first(xml, "Hidden").is_some_and(|v| v.eq_ignore_ascii_case("true"));
    t.author = first(xml, "Author");
    t.run_as = first(xml, "UserId");
    t.highest = first(xml, "RunLevel").is_some_and(|v| v == "HighestAvailable");
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_exec_and_flags() {
        let xml = r#"<?xml version="1.0" encoding="UTF-16"?><Task><RegistrationInfo><Author>evil</Author></RegistrationInfo>
<Settings><Hidden>true</Hidden></Settings><Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
<Actions Context="Author"><Exec><Command>C:\Program Files\x\a.exe</Command><Arguments>-c &quot;x&quot;</Arguments></Exec>
<ComHandler><ClassId>{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}</ClassId></ComHandler></Actions></Task>"#;
        let t = parse(xml);
        assert_eq!(t.actions, vec![r#""C:\Program Files\x\a.exe" -c "x""#]);
        assert_eq!(t.com_handlers.len(), 1);
        assert!(t.hidden && t.highest);
        assert_eq!(t.author.as_deref(), Some("evil"));
    }

    #[test]
    fn decodes_utf16() {
        let s = "<Task/>";
        let mut b = vec![0xFF, 0xFE];
        for u in s.encode_utf16() {
            b.extend(u.to_le_bytes());
        }
        assert_eq!(decode(&b), s);
    }
}
