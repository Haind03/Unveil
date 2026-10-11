//! Console UI: VT colors on Windows 10+, banner, phase headers and a single-line progress bar.

use std::io::Write;
use std::time::Instant;

use windows_sys::Win32::System::Console::{
    GetConsoleMode, GetStdHandle, SetConsoleMode, SetConsoleOutputCP, ENABLE_VIRTUAL_TERMINAL_PROCESSING, STD_OUTPUT_HANDLE,
};

pub const RESET: &str = "\x1b[0m";
pub const DIM: &str = "\x1b[90m";
pub const BOLD: &str = "\x1b[1m";
pub const GREEN: &str = "\x1b[38;5;48m";
pub const CYAN: &str = "\x1b[38;5;51m";
pub const MAGENTA: &str = "\x1b[38;5;171m";
pub const RED: &str = "\x1b[38;5;203m";
pub const YELLOW: &str = "\x1b[38;5;221m";

pub struct Ui {
    pub color: bool,
    pub quiet: bool,
    start: Instant,
}

impl Ui {
    pub fn new(no_color: bool, quiet: bool) -> Ui {
        let mut color = !no_color && std::env::var_os("NO_COLOR").is_none();
        unsafe {
            SetConsoleOutputCP(65001);
            let h = GetStdHandle(STD_OUTPUT_HANDLE);
            let mut mode = 0;
            if GetConsoleMode(h, &mut mode) == 0 {
                color = false; // redirected to a file or pipe
            } else if SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) == 0 {
                color = false;
            }
        }
        Ui { color, quiet, start: Instant::now() }
    }

    pub fn c(&self, code: &'static str) -> &'static str {
        if self.color { code } else { "" }
    }

    pub fn banner(&self, host: &str, elevated: bool) {
        if self.quiet {
            return;
        }
        let (g, cy, m, d, r, b) = (self.c(GREEN), self.c(CYAN), self.c(MAGENTA), self.c(DIM), self.c(RESET), self.c(BOLD));
        for (i, line) in crate::brand::BANNER.lines().filter(|l| !l.is_empty()).enumerate() {
            let col = if i < 2 { g } else if i < 4 { cy } else { m };
            println!("{col}{line}{r}");
        }
        println!("{d}  {}  v{}{r}", crate::brand::TAGLINE, crate::brand::VERSION);
        println!("{d}  by {b}{}{r}", crate::brand::AUTHOR);
        println!();
        let priv_s = if elevated { format!("{g}elevated{r}") } else { format!("{}not elevated{r}", self.c(YELLOW)) };
        println!("  {d}host{r} {b}{host}{r}   {d}privileges{r} {priv_s}");
        println!();
    }

    pub fn phase(&self, n: usize, total: usize, title: &str) {
        if self.quiet {
            return;
        }
        let (cy, d, r, b) = (self.c(CYAN), self.c(DIM), self.c(RESET), self.c(BOLD));
        println!("{cy}[{n}/{total}]{r} {b}{title}{r} {d}{:.1}s{r}", self.start.elapsed().as_secs_f64());
    }

    pub fn info(&self, msg: &str) {
        if !self.quiet {
            println!("      {}{msg}{}", self.c(DIM), self.c(RESET));
        }
    }

    pub fn warn(&self, msg: &str) {
        if !self.quiet {
            println!("      {}! {msg}{}", self.c(YELLOW), self.c(RESET));
        }
    }

    pub fn elapsed(&self) -> f64 {
        self.start.elapsed().as_secs_f64()
    }

    pub fn progress(&self, done: usize, total: usize, label: &str) {
        if self.quiet || total == 0 {
            return;
        }
        const W: usize = 28;
        let fill = done * W / total;
        let (g, d, r) = (self.c(GREEN), self.c(DIM), self.c(RESET));
        let label: String = label.chars().take(32).collect();
        print!("\r      {g}{}{d}{}{r} {done:>4}/{total:<4} {d}{label:<32}{r}", "█".repeat(fill), "░".repeat(W - fill));
        let _ = std::io::stdout().flush();
        if done == total {
            print!("\r{}\r", " ".repeat(W + 50));
            let _ = std::io::stdout().flush();
        }
    }
}
