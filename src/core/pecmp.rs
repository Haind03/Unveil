//! Compare a module's executable sections in memory against the file on disk, after applying
//! base relocations. Any remaining difference is code that was modified at runtime.

use goblin::pe::PE;

const SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const SCN_MEM_WRITE: u32 = 0x8000_0000;

#[derive(Debug, Clone)]
pub struct Patch {
    pub rva: u32,
    pub mem: Vec<u8>,
    pub disk: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ExecSection {
    pub name: String,
    pub rva: u32,
    pub size: u32,
}

pub struct DiskImage<'a> {
    data: &'a [u8],
    pe: PE<'a>,
}

impl<'a> DiskImage<'a> {
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        let pe = PE::parse(data).ok()?;
        Some(DiskImage { data, pe })
    }

    pub fn is_64(&self) -> bool {
        self.pe.is_64
    }

    pub fn image_base(&self) -> u64 {
        self.pe.image_base
    }

    pub fn size_of_image(&self) -> u32 {
        self.pe.header.optional_header.map(|o| o.windows_fields.size_of_image).unwrap_or(0)
    }

    pub fn entry_rva(&self) -> u32 {
        self.pe.entry as u32
    }

    pub fn timestamp(&self) -> u32 {
        self.pe.header.coff_header.time_date_stamp
    }

    pub fn exec_sections(&self) -> Vec<ExecSection> {
        self.pe
            .sections
            .iter()
            .filter(|s| s.characteristics & SCN_MEM_EXECUTE != 0)
            // Packer stubs (UPX, MPRESS...) unpack into writable or mostly-virtual sections at runtime.
            .filter(|s| s.characteristics & SCN_MEM_WRITE == 0 && s.size_of_raw_data as u64 * 2 >= s.virtual_size as u64)
            .map(|s| ExecSection {
                name: String::from_utf8_lossy(&s.name).trim_end_matches('\0').to_string(),
                rva: s.virtual_address,
                size: s.virtual_size.max(s.size_of_raw_data),
            })
            .collect()
    }

    /// Exported functions as (rva, name), sorted by rva.
    pub fn exports(&self) -> Vec<(u32, String)> {
        let mut v: Vec<(u32, String)> = self
            .pe
            .exports
            .iter()
            .filter(|e| e.reexport.is_none())
            .filter_map(|e| Some((e.rva as u32, e.name?.to_string())))
            .collect();
        v.sort();
        v
    }

    pub fn export_rva(&self, name: &str) -> Option<u32> {
        self.pe.exports.iter().find(|e| e.name == Some(name) && e.reexport.is_none()).map(|e| e.rva as u32)
    }

    fn rva_to_off(&self, rva: u32) -> Option<usize> {
        for s in &self.pe.sections {
            let vsz = s.virtual_size.max(s.size_of_raw_data);
            if rva >= s.virtual_address && rva < s.virtual_address + vsz {
                let delta = rva - s.virtual_address;
                if delta >= s.size_of_raw_data {
                    return None; // zero-filled tail
                }
                return Some(s.pointer_to_raw_data as usize + delta as usize);
            }
        }
        None
    }

    fn dir(&self, idx: usize) -> Option<(u32, u32)> {
        let oh = self.pe.header.optional_header?;
        let d = oh.data_directories.data_directories.get(idx)?.as_ref()?.1;
        (d.virtual_address != 0 && d.size != 0).then_some((d.virtual_address, d.size))
    }

    /// Ranges inside the image that legitimately differ at runtime (IAT is often merged into .text).
    pub fn volatile_ranges(&self) -> Vec<(u32, u32)> {
        let mut v = Vec::new();
        for idx in [1usize, 12, 13] {
            // import table, IAT, delay import descriptor
            if let Some((rva, size)) = self.dir(idx) {
                v.push((rva, rva + size));
            }
        }
        v
    }

    /// Reloc fixup locations: (rva, width in bytes).
    pub fn relocations(&self) -> Vec<(u32, u8)> {
        let mut out = Vec::new();
        let Some((rva, size)) = self.dir(5) else { return out };
        let Some(off) = self.rva_to_off(rva) else { return out };
        let end = (off + size as usize).min(self.data.len());
        let mut p = off;
        while p + 8 <= end {
            let page = u32::from_le_bytes(self.data[p..p + 4].try_into().unwrap());
            let block = u32::from_le_bytes(self.data[p + 4..p + 8].try_into().unwrap()) as usize;
            if block < 8 || p + block > end {
                break;
            }
            for e in self.data[p + 8..p + block].chunks_exact(2) {
                let e = u16::from_le_bytes([e[0], e[1]]);
                let (ty, ofs) = (e >> 12, (e & 0xfff) as u32);
                match ty {
                    10 => out.push((page + ofs, 8)),
                    3 => out.push((page + ofs, 4)),
                    _ => {}
                }
            }
            p += block;
        }
        out
    }

    /// Expected bytes of `[rva, rva+len)` when loaded at `actual_base`.
    pub fn expected(&self, rva: u32, len: usize, actual_base: u64, relocs: &[(u32, u8)]) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        for (i, b) in buf.iter_mut().enumerate() {
            if let Some(o) = self.rva_to_off(rva + i as u32) {
                if let Some(v) = self.data.get(o) {
                    *b = *v;
                }
            }
        }
        let delta = actual_base.wrapping_sub(self.image_base());
        if delta != 0 {
            let lo = relocs.partition_point(|(r, _)| *r + 8 <= rva);
            for &(r, w) in &relocs[lo..] {
                if r >= rva + len as u32 {
                    break;
                }
                let start = r as i64 - rva as i64;
                if start < 0 || start as usize + w as usize > len {
                    continue;
                }
                let s = start as usize;
                if w == 8 {
                    let v = u64::from_le_bytes(buf[s..s + 8].try_into().unwrap()).wrapping_add(delta);
                    buf[s..s + 8].copy_from_slice(&v.to_le_bytes());
                } else {
                    let v = u32::from_le_bytes(buf[s..s + 4].try_into().unwrap()).wrapping_add(delta as u32);
                    buf[s..s + 4].copy_from_slice(&v.to_le_bytes());
                }
            }
        }
        buf
    }
}

/// Diff memory against expected bytes. `mem` may contain `None` for unreadable pages.
/// Nearby differences (gap < 8 bytes) are merged into one patch.
pub fn diff(base_rva: u32, mem: &[Option<u8>], expected: &[u8], volatile: &[(u32, u32)]) -> Vec<Patch> {
    let mut out: Vec<Patch> = Vec::new();
    let skip = |rva: u32| volatile.iter().any(|&(a, b)| rva >= a && rva < b);
    let mut i = 0;
    let n = mem.len().min(expected.len());
    while i < n {
        let rva = base_rva + i as u32;
        match mem[i] {
            Some(m) if m != expected[i] && !skip(rva) => {
                let start = i;
                let mut last = i;
                let mut j = i + 1;
                while j < n && j - last < 8 {
                    if let Some(m) = mem[j] {
                        if m != expected[j] && !skip(base_rva + j as u32) {
                            last = j;
                        }
                    }
                    j += 1;
                }
                let _ = m;
                out.push(Patch {
                    rva,
                    mem: mem[start..=last].iter().map(|b| b.unwrap_or(0)).collect(),
                    disk: expected[start..=last].to_vec(),
                });
                i = last + 1;
            }
            _ => i += 1,
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diff_merges_close_bytes() {
        let exp = vec![0u8; 64];
        let mut mem: Vec<Option<u8>> = exp.iter().map(|b| Some(*b)).collect();
        mem[10] = Some(0xE9);
        mem[12] = Some(0x11);
        mem[40] = Some(0xC3);
        mem[50] = None;
        let p = diff(0x1000, &mem, &exp, &[]);
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].rva, 0x100a);
        assert_eq!(p[0].mem, vec![0xE9, 0, 0x11]);
        assert_eq!(p[1].rva, 0x1028);
    }

    #[test]
    fn diff_skips_volatile() {
        let exp = vec![0u8; 16];
        let mut mem: Vec<Option<u8>> = exp.iter().map(|b| Some(*b)).collect();
        mem[4] = Some(1);
        assert!(diff(0x2000, &mem, &exp, &[(0x2000, 0x2008)]).is_empty());
    }
}
