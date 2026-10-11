//! Platform-independent analysis. Everything here works on plain data collected by `crate::win`,
//! so the detection logic is unit-tested on any OS.

pub mod hookrules;
pub mod html;
pub mod lnk;
pub mod memrules;
pub mod paths;
pub mod pecmp;
pub mod persistrules;
pub mod procrules;
pub mod report;
pub mod taskxml;

use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", content = "info", rename_all = "lowercase")]
pub enum SigStatus {
    /// Valid Authenticode signature (embedded or catalog). Holds the signer subject if known.
    Signed(Option<String>),
    Unsigned,
    /// Signature present but does not verify (tampered file, revoked or untrusted chain).
    Invalid(String),
}

impl SigStatus {
    pub fn is_signed(&self) -> bool {
        matches!(self, SigStatus::Signed(_))
    }

    pub fn microsoft(&self) -> bool {
        matches!(self, SigStatus::Signed(Some(s)) if s.starts_with("Microsoft"))
    }
}

#[derive(Debug, Clone, Default)]
pub struct ProcInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub path: Option<String>,
    pub cmdline: Option<String>,
    pub signature: Option<SigStatus>,
    pub image_exists: bool,
    pub session: u32,
    pub threads: Vec<u32>,
    pub wow64: bool,
    pub create_time: u64,
}

pub const MEM_COMMIT: u32 = 0x1000;
pub const MEM_IMAGE: u32 = 0x100_0000;
pub const MEM_MAPPED: u32 = 0x4_0000;
pub const MEM_PRIVATE: u32 = 0x2_0000;

pub const PAGE_EXECUTE: u32 = 0x10;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
pub const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
pub const PAGE_GUARD: u32 = 0x100;
pub const PAGE_NOACCESS: u32 = 0x01;

pub fn is_exec(protect: u32) -> bool {
    protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY) != 0
}

pub fn is_writable_exec(protect: u32) -> bool {
    protect & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY) != 0
}

pub fn prot_str(p: u32) -> &'static str {
    match p & 0xff {
        0x01 => "---",
        0x02 => "R--",
        0x04 => "RW-",
        0x08 => "RWC",
        0x10 => "--X",
        0x20 => "R-X",
        0x40 => "RWX",
        0x80 => "RWXC",
        _ => "?",
    }
}

#[derive(Debug, Clone)]
pub struct Region {
    pub base: u64,
    pub alloc_base: u64,
    pub size: u64,
    pub state: u32,
    pub protect: u32,
    pub alloc_protect: u32,
    pub kind: u32,
}

#[derive(Debug, Clone)]
pub struct Module {
    pub base: u64,
    pub size: u64,
    pub path: String,
}

impl Module {
    pub fn contains(&self, a: u64) -> bool {
        a >= self.base && a < self.base + self.size
    }

    pub fn name(&self) -> String {
        paths::file_name(&self.path).to_ascii_lowercase()
    }
}

#[derive(Debug, Clone)]
pub struct ThreadInfo {
    pub tid: u32,
    pub start: u64,
}
