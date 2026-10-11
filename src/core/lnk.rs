//! Minimal .lnk (MS-SHLLINK) reader: target path and arguments. Bounds-checked, never panics.

pub struct Lnk {
    pub target: Option<String>,
    pub args: Option<String>,
}

fn u16_at(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(o..o + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?))
}

fn cstr(b: &[u8], o: usize) -> Option<String> {
    let s = b.get(o..)?;
    let n = s.iter().position(|&c| c == 0)?;
    Some(String::from_utf8_lossy(&s[..n]).into_owned())
}

fn wstr(b: &[u8], o: usize) -> Option<String> {
    let s = b.get(o..)?;
    let u: Vec<u16> = s.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|&c| c != 0).collect();
    Some(String::from_utf16_lossy(&u))
}

pub fn parse(b: &[u8]) -> Option<Lnk> {
    if u32_at(b, 0)? != 0x4C {
        return None;
    }
    let flags = u32_at(b, 0x14)?;
    let unicode = flags & 0x80 != 0;
    let mut o = 0x4Cusize;
    if flags & 0x1 != 0 {
        o += 2 + u16_at(b, o)? as usize;
    }
    let mut target = None;
    if flags & 0x2 != 0 {
        let li = o;
        let size = u32_at(b, li)? as usize;
        let hdr = u32_at(b, li + 4)? as usize;
        let lflags = u32_at(b, li + 8)?;
        if lflags & 1 != 0 {
            if hdr >= 0x24 {
                let wo = u32_at(b, li + 28)? as usize;
                if wo != 0 {
                    target = wstr(b, li + wo);
                }
            }
            if target.as_deref().is_none_or(str::is_empty) {
                let ao = u32_at(b, li + 16)? as usize;
                target = cstr(b, li + ao);
            }
        }
        o += size;
    }
    // StringData: NAME, RELATIVE_PATH, WORKING_DIR, ARGUMENTS, ICON (each optional, counted chars).
    let mut read = |present: bool| -> Option<Option<String>> {
        if !present {
            return Some(None);
        }
        let n = u16_at(b, o)? as usize;
        o += 2;
        let s = if unicode {
            let bytes = b.get(o..o + n * 2)?;
            let u: Vec<u16> = bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
            o += n * 2;
            String::from_utf16_lossy(&u)
        } else {
            let bytes = b.get(o..o + n)?;
            o += n;
            String::from_utf8_lossy(bytes).into_owned()
        };
        Some(Some(s))
    };
    let _name = read(flags & 0x4 != 0)?;
    let rel = read(flags & 0x8 != 0)?;
    let _wd = read(flags & 0x10 != 0)?;
    let args = read(flags & 0x20 != 0).unwrap_or(None);
    if target.is_none() {
        target = rel;
    }
    Some(Lnk { target, args })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_garbage() {
        assert!(parse(b"not a lnk").is_none());
        assert!(parse(&[0x4C, 0, 0, 0]).is_none());
    }

    #[test]
    fn reads_relative_path_and_args() {
        let mut b = vec![0u8; 0x4C];
        b[0] = 0x4C;
        b[0x14] = 0x08 | 0x20 | 0x80; // relative path, arguments, unicode
        for s in ["..\\evil.exe", "-run"] {
            let u: Vec<u16> = s.encode_utf16().collect();
            b.extend((u.len() as u16).to_le_bytes());
            for c in u {
                b.extend(c.to_le_bytes());
            }
        }
        let l = parse(&b).unwrap();
        assert_eq!(l.target.as_deref(), Some("..\\evil.exe"));
        assert_eq!(l.args.as_deref(), Some("-run"));
    }
}
