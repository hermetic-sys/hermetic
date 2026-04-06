// Hermetic — Zero-Knowledge Credential Broker for AI Agents
// Copyright (C) 2026 The Hermetic Project
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.
//
// Commercial licenses available at https://hermeticsys.com/license

//! Hermetic Terminal UI — Shared terminal output module with color support,
//! ANSI sanitization, and structured output categories.
//!
//! All output is written to **stderr** (MCP-5: stdout reserved for JSON-RPC).
//! Color detection uses `std::io::IsTerminal` (no unsafe FFI).
//!
//! # Color Palette (from hermeticsys.com CSS variables)
//!
//! | Name    | Hex       | Usage                                    |
//! |---------|-----------|------------------------------------------|
//! | Green   | `#3edd8a` | Success, checkmarks, init phase           |
//! | Cyan    | `#36d6c8` | Highlights, secret names, secrets phase   |
//! | Blue    | `#4a7cff` | Headers, borders, daemon phase            |
//! | Gold    | `#ffd166` | Warnings, spinners, timing info           |
//! | Red     | `#ff4c6a` | Errors, destructive actions (seal)        |
//! | Purple  | `#9366ff` | Accents (reserved)                        |
//! | Dim     | `#505670` | Step indicators, secondary text           |
//! | Muted   | `#404558` | Tertiary text, separators                 |
//! | Text    | `#e8eaf0` | Primary text                              |
//! | Text2   | `#8890a8` | Secondary descriptive text                |
//!
//! # Constitutional Compliance
//!
//! - IC-1: No secret values appear in any UI output
//! - MCP-1: Secret bytes never rendered to terminal
//! - MCP-5: All output to stderr (stdout reserved for JSON-RPC)
//! - BC-3: Log output uses structured format, not UI decorations
//! - HC-11: SafeStr sanitization for all user-controlled strings
//! - Auditor C-1: All sensitive fields show `[REDACTED]` in debug output

use std::io::{self, IsTerminal, Write};

// ─── HC-11: Terminal Output Sanitization ────────────────────────────────────

/// Terminal-safe string. Constructor strips all dangerous code points.
/// Once constructed, the inner string is guaranteed safe for terminal rendering.
///
/// Constitutional binding HC-11: All user-controlled strings must pass through
/// this type before reaching any terminal output function.
///
/// Stripped code points:
/// - C0 control characters U+0000–U+0008, U+000B–U+000C, U+000E–U+001F
///   (includes ESC U+001B — neutralizes ANSI sequences by removing initiator byte)
/// - DEL U+007F
/// - C1 control characters U+0080–U+009F
///   (All above caught by Rust's char::is_control() which covers Cc category)
/// - Zero-width characters: U+200B, U+200C, U+200D, U+FEFF
/// - Bidi embeddings/overrides: U+202A–U+202E (Cf category, NOT caught by is_control())
/// - Invisible formatters: U+2060–U+2064
/// - Bidi isolates: U+2066–U+206F
///   (All above require explicit match — they are Unicode category Cf, not Cc)
///
/// Preserved: U+000A (newline), all printable ASCII, all visible Unicode.
pub struct SafeStr(String);

impl SafeStr {
    pub fn new(input: &str) -> Self {
        Self(
            input
                .chars()
                .filter(|c| {
                    // Block C0/C1 control characters (except newline U+000A)
                    // This catches ESC (U+001B), neutralizing ANSI escape sequences
                    // by removing the prerequisite initiator byte.
                    if c.is_control() && *c != '\n' {
                        return false;
                    }
                    // Block Unicode Cf-category format characters that enable
                    // visual spoofing and bidi override attacks.
                    // These are NOT caught by is_control() (which only covers Cc).
                    !matches!(*c as u32,
                        0x200B | 0x200C | 0x200D | 0xFEFF |
                        0x202A..=0x202E |  // bidi embeddings + overrides (LRE, RLE, PDF, LRO, RLO)
                        0x2060..=0x2064 |  // invisible formatters
                        0x2066..=0x206F    // bidi isolates
                    )
                })
                .collect(),
        )
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SafeStr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

// ─── Error Diagnostics ──────────────────────────────────────────────────────

/// Print a structured error diagnostic with title, guidance, and constitutional code.
///
/// HC-11: Title and guidance are developer-authored literals or SafeStr-sanitized.
/// Internal error strings (Database, Crypto, Io) MUST NOT be passed to this function.
/// Route internal details to tracing only (IC-1, BC-3).
pub fn error_diagnostic(title: &str, guidance: &str, code: &str) {
    let r_col = Colors::red();
    let g_col = Colors::gold();
    let m = Colors::muted();
    let r = reset();

    eprintln!();
    eprintln!("  {r_col}{}\u{2717} {}{r}", bold(), title);
    eprintln!("  {g_col}  {}{r}", guidance);
    eprintln!("  {m}  [{code}]{r}");
    eprintln!();
}

// ─── Color Detection ────────────────────────────────────────────────────────

/// Returns true if stderr is connected to a terminal that supports color.
/// Uses std::io::IsTerminal (safe, no FFI) and checks stderr (MCP-5).
fn supports_color() -> bool {
    io::stderr().is_terminal()
        && std::env::var("NO_COLOR").is_err()
        && std::env::var("TERM").map_or(true, |t| t != "dumb")
}

/// Global lazy-initialized color support flag.
fn color_enabled() -> bool {
    use std::sync::OnceLock;
    static COLOR: OnceLock<bool> = OnceLock::new();
    *COLOR.get_or_init(supports_color)
}

/// Public accessor for color_enabled (used by commands::run warning).
pub fn color_enabled_pub() -> bool {
    color_enabled()
}

// ─── ANSI Escape Helpers ────────────────────────────────────────────────────

/// 24-bit ANSI foreground color from RGB.
fn fg(r: u8, g: u8, b: u8) -> String {
    if color_enabled() {
        format!("\x1b[38;2;{r};{g};{b}m")
    } else {
        String::new()
    }
}

/// ANSI bold.
fn bold() -> &'static str {
    if color_enabled() {
        "\x1b[1m"
    } else {
        ""
    }
}

/// ANSI reset.
fn reset() -> &'static str {
    if color_enabled() {
        "\x1b[0m"
    } else {
        ""
    }
}

// ─── Named Colors (hermeticsys.com palette) ─────────────────────────────────

pub struct Colors;

impl Colors {
    pub fn green() -> String {
        fg(62, 221, 138)
    } // #3edd8a
    pub fn cyan() -> String {
        fg(54, 214, 200)
    } // #36d6c8
    pub fn blue() -> String {
        fg(74, 124, 255)
    } // #4a7cff
    pub fn gold() -> String {
        fg(255, 209, 102)
    } // #ffd166
    pub fn red() -> String {
        fg(255, 76, 106)
    } // #ff4c6a
    pub fn purple() -> String {
        fg(147, 102, 255)
    } // #9366ff
    pub fn dim() -> String {
        fg(120, 130, 160)
    } // #7882A0
    pub fn muted() -> String {
        fg(96, 101, 128)
    } // #606580
    pub fn text() -> String {
        fg(232, 234, 240)
    } // #e8eaf0
    pub fn text2() -> String {
        fg(136, 144, 168)
    } // #8890a8
}

// ─── Core Output Primitives ─────────────────────────────────────────────────

/// The Hermetic prompt character, matching the website's `❯` glyph.
pub fn prompt(color: &str) -> String {
    format!("{}{}{}", color, "❯", reset())
}

/// Print a command echo line: `❯ hermetic init --mode software`
pub fn print_command(cmd: &str) {
    let c = Colors::green();
    eprintln!("  {} {}{}{}", prompt(&c), bold(), cmd, reset());
}

/// Print a step line: `  → Creating SQLCipher database`
pub fn step(msg: &str) {
    eprintln!("  {}  → {}{}", Colors::dim(), msg, reset());
}

/// Print a step with a trailing result: `  → Argon2id: 256MB, t=4, p=2 ... done (1.24s)`
pub fn step_done(msg: &str, result: &str) {
    eprintln!(
        "  {}  → {}{} {}{}{}",
        Colors::dim(),
        msg,
        reset(),
        Colors::green(),
        result,
        reset()
    );
}

/// Print a success line: `✓ Vault initialized. 0 secrets stored.`
pub fn success(msg: &str) {
    eprintln!("  {}{}✓ {}{}", Colors::green(), bold(), msg, reset());
}

/// Print a zeroization confirmation: `  ✓ KEK zeroized ✓   plaintext zeroized ✓`
pub fn zeroized(msg: &str) {
    eprintln!("  {}  ✓ {}{}", Colors::green(), msg, reset());
}

/// Print a warning/action line: `⚙ Initializing vault...`
pub fn action(icon: &str, msg: &str) {
    eprintln!("  {}{}{}{}", Colors::gold(), icon, msg, reset());
}

/// Print an error line.
pub fn error(msg: &str) {
    eprintln!("  {}{}✗ {}{}", Colors::red(), bold(), msg, reset());
}

/// Print a dim/muted info line.
pub fn info(msg: &str) {
    eprintln!("  {}  {}{}", Colors::muted(), msg, reset());
}

/// Print a dim info line with a cyan-highlighted value.
pub fn info_highlight(label: &str, value: &str) {
    eprintln!(
        "  {}  {}{}{}{}",
        Colors::muted(),
        label,
        Colors::cyan(),
        value,
        reset()
    );
}

/// Print a blank line for spacing.
pub fn gap() {
    eprintln!();
}

// ─── Passphrase Display ─────────────────────────────────────────────────────

/// Print the passphrase prompt label (the dots are handled by rpassword).
/// Matches the website's dimmed label with hidden dots aesthetic.
pub fn passphrase_label(label: &str) {
    eprint!("  {}  {}{}", Colors::muted(), label, reset());
    io::stderr().flush().ok();
}

// ─── Table / List Formatting ────────────────────────────────────────────────

/// Print a table header row with blue coloring.
pub fn table_header(columns: &[(&str, usize)]) {
    let mut line = String::from("  ");
    for (name, width) in columns {
        line.push_str(&format!("{:<width$}", name, width = width));
    }
    eprintln!("  {}{}{}", Colors::blue(), line.trim_start(), reset());

    // Separator
    let total_width: usize = columns.iter().map(|(_, w)| w).sum();
    eprintln!(
        "  {}  {}{}",
        Colors::muted(),
        "─".repeat(total_width + 2),
        reset()
    );
}

/// Print a table row with cyan name and dim details.
pub fn table_row(name: &str, name_width: usize, details: &[&str]) {
    eprint!(
        "  {}  {:<width$}{}",
        Colors::cyan(),
        name,
        reset(),
        width = name_width
    );
    for detail in details {
        eprint!("{}{}  {}", Colors::muted(), detail, reset());
    }
    eprintln!();
}

/// Print a table summary footer.
pub fn table_footer(msg: &str) {
    gap();
    eprintln!("  {}  {}{}", Colors::muted(), msg, reset());
}

// ─── Box Drawing (Status Display) ───────────────────────────────────────────

/// A box-drawn status panel matching the website's `hermetic status` output.
///
/// ```text
/// ╔══════════════════════════════════════╗
/// ║  HERMETIC VAULT STATUS               ║
/// ╠══════════════════════════════════════╣
/// ║  State:   UNSEALED + DAEMON ACTIVE   ║
/// ║  Secrets: 2 / 15                     ║
/// ╚══════════════════════════════════════╝
/// ```
pub struct StatusBox {
    title: String,
    rows: Vec<(String, String, StatusColor)>,
    width: usize,
}

#[derive(Clone)]
pub enum StatusColor {
    Green,
    Cyan,
    Blue,
    Gold,
    Red,
    Text2,
}

impl StatusColor {
    fn ansi(&self) -> String {
        match self {
            StatusColor::Green => Colors::green(),
            StatusColor::Cyan => Colors::cyan(),
            StatusColor::Blue => Colors::blue(),
            StatusColor::Gold => Colors::gold(),
            StatusColor::Red => Colors::red(),
            StatusColor::Text2 => Colors::text2(),
        }
    }
}

impl StatusBox {
    pub fn new(title: &str) -> Self {
        Self {
            title: title.to_string(),
            rows: Vec::new(),
            width: 40,
        }
    }

    pub fn width(mut self, w: usize) -> Self {
        self.width = w;
        self
    }

    pub fn row(mut self, label: &str, value: &str, color: StatusColor) -> Self {
        self.rows
            .push((label.to_string(), value.to_string(), color));
        self
    }

    pub fn render(&self) {
        let b = Colors::blue();
        let r = reset();
        let w = self.width;

        // Top border
        eprintln!("  {b}╔{}╗{r}", "═".repeat(w));

        // Title
        let title_pad = w.saturating_sub(self.title.len() + 2);
        eprintln!(
            "  {b}║  {}{}{}{b}{}║{r}",
            bold(),
            self.title,
            r,
            " ".repeat(title_pad)
        );

        // Separator
        eprintln!("  {b}╠{}╣{r}", "═".repeat(w));

        // Rows
        for (label, value, color) in &self.rows {
            let c = color.ansi();
            // Calculate padding: "  Label: Value" must fit in `w` chars
            let content = format!("  {:<9}{}", format!("{}:", label), value);
            let pad = w.saturating_sub(content.len());
            eprintln!(
                "  {b}║{}  {:<9}{}{c}{}{r}{b}{}║{r}",
                Colors::muted(),
                format!("{}:", label),
                r,
                value,
                " ".repeat(pad),
            );
        }

        // Bottom border
        eprintln!("  {b}╚{}╝{r}", "═".repeat(w));
    }
}

// ─── Progress / Spinner ─────────────────────────────────────────────────────

/// A simple inline spinner for long-running operations.
/// Uses the gold color from the website's "⏳ executing..." indicator.
pub struct Spinner {
    frames: &'static [&'static str],
    idx: usize,
    message: String,
}

impl Spinner {
    pub fn new(message: &str) -> Self {
        Self {
            frames: &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"],
            idx: 0,
            message: message.to_string(),
        }
    }

    /// Advance the spinner one frame (call in a loop with ~80ms sleep).
    pub fn tick(&mut self) {
        if !color_enabled() {
            return;
        }
        self.idx = (self.idx + 1) % self.frames.len();
        eprint!(
            "\r  {}  {} {}{}",
            Colors::gold(),
            self.frames[self.idx],
            self.message,
            reset()
        );
        io::stderr().flush().ok();
    }

    /// Clear the spinner line.
    pub fn finish(&self) {
        if color_enabled() {
            eprint!("\r{}\r", " ".repeat(self.message.len() + 20));
            io::stderr().flush().ok();
        }
    }

    /// Clear and replace with a done message.
    pub fn finish_with(&self, msg: &str) {
        self.finish();
        step_done(&self.message, msg);
    }
}

// ─── Banner / Seal Confirmation ─────────────────────────────────────────────

/// The completion banner shown when daemon is fully operational.
/// Matches the website's gradient-bordered "HERMETIC SEAL ACTIVE" panel.
pub fn seal_active_banner(details: &str) {
    if !color_enabled() {
        eprintln!("  ✓ HERMETIC SEAL ACTIVE");
        eprintln!("  {}", details);
        return;
    }

    let g = Colors::green();
    let m = Colors::muted();
    let r = reset();
    let border_color = fg(62, 221, 138); // green with reduced opacity simulated

    eprintln!();
    eprintln!("  {border_color}┌──────────────────────────────────────────────┐{r}");
    eprintln!(
        "  {border_color}│  {g}{}✓ HERMETIC SEAL ACTIVE{}                       {border_color}│{r}",
        bold(),
        r
    );
    eprintln!("  {border_color}│  {m}{:<44}{border_color}│{r}", details);
    eprintln!("  {border_color}└──────────────────────────────────────────────┘{r}");
    eprintln!();
}

/// Waiting banner for daemon idle state.
pub fn waiting_banner(msg: &str) {
    eprintln!(
        "  {}  ════════ {} ════════{}",
        Colors::muted(),
        msg,
        reset()
    );
}

// ─── Header / Branding ─────────────────────────────────────────────────────

/// Print the Hermetic version header matching the website's topnav style.
pub fn version_header(version: &str, rust_version: &str) {
    eprintln!(
        "  {}hermetic {}{}{}{} {}({}, release){}",
        Colors::muted(),
        reset(),
        Colors::green(),
        version,
        reset(),
        Colors::muted(),
        rust_version,
        reset()
    );
}

/// Print the daemon version line.
pub fn daemon_version(version: &str) {
    eprintln!(
        "  {}hermetic-daemon {}{}{}",
        Colors::muted(),
        Colors::green(),
        version,
        reset()
    );
}

/// Print protocol info.
pub fn protocol_info(protocol: &str) {
    eprintln!(
        "  {}protocol: {}{}{}",
        Colors::muted(),
        Colors::cyan(),
        protocol,
        reset()
    );
}

/// Print build info.
pub fn build_info(info: &str) {
    eprintln!(
        "  {}build:    {}{}{}",
        Colors::muted(),
        Colors::gold(),
        info,
        reset()
    );
}

// ─── Daemon-Specific Output ─────────────────────────────────────────────────

/// Print a daemon startup step with checkmark result.
pub fn daemon_step_ok(msg: &str) {
    step(msg);
}

/// Print a daemon step with an inline result.
pub fn daemon_step_result(msg: &str, result: &str) {
    eprintln!(
        "  {}  → {}{}  {}{}{}",
        Colors::dim(),
        msg,
        reset(),
        Colors::green(),
        result,
        reset()
    );
}

/// Print daemon PID/UID/handle info.
pub fn daemon_info(pid: u32, uid: u32, handles: usize, max_handles: usize) {
    eprintln!(
        "  {}  PID: {}  |  UID: {}  |  Handles: {}/{}{}",
        Colors::muted(),
        pid,
        uid,
        handles,
        max_handles,
        reset()
    );
}

// ─── Seal (Destructive Action) ──────────────────────────────────────────────

/// Warning banner for destructive seal operation.
pub fn seal_warning() {
    let r_col = Colors::red();
    let r = reset();
    eprintln!();
    eprintln!("  {r_col}{}⚠  WARNING: IRREVERSIBLE OPERATION{r}", bold());
    eprintln!("  {r_col}  Sealing the vault will destroy all encryption keys.{r}");
    eprintln!("  {r_col}  All stored secrets will become permanently inaccessible.{r}");
    eprintln!("  {r_col}  This action cannot be undone.{r}");
    eprintln!();
}

/// Seal confirmation prompt label.
pub fn seal_confirm_label() {
    eprint!("  {}  Type 'SEAL' to confirm: {}", Colors::red(), reset());
    io::stderr().flush().ok();
}

// ─── Utility ────────────────────────────────────────────────────────────────

/// Shimmer-like separator (simplified for terminal — thin line with color).
pub fn separator() {
    if color_enabled() {
        // Gradient simulated: dim → cyan → blue → dim
        let d = Colors::muted();
        let c = Colors::cyan();
        let b = Colors::blue();
        let r = reset();
        eprintln!("  {d}──────{c}──────────{b}──────────{c}──────────{d}──────{r}");
    } else {
        eprintln!("  {}", "─".repeat(48));
    }
}

/// Format a duration in human-readable form matching the website's style.
pub fn format_duration(secs: f64) -> String {
    if secs < 1.0 {
        format!("{:.0}ms", secs * 1000.0)
    } else {
        format!("{:.2}s", secs)
    }
}

/// Slot counter: "3/15 slots used" or "12 slots available"
pub fn slot_info(used: usize, max: usize) -> String {
    format!("{}/{} slots used", used, max)
}

// ─── Operational Output (lifecycle commands) ─────────────────────────────
// Visually distinct from system startup output (▸ prefix instead of →).

/// Operational step: ▸ prefix, dim.
pub fn op(text: &str) {
    eprintln!("  {}  ▸ {}{}", Colors::dim(), text, reset());
}

/// Operational success: ✓ prefix, green bold.
pub fn op_ok(text: &str) {
    eprintln!("  {}{}✓ {}{}", Colors::green(), bold(), text, reset());
}

/// Operational failure: ✗ prefix, red bold.
pub fn op_fail(text: &str) {
    eprintln!("  {}{}✗ {}{}", Colors::red(), bold(), text, reset());
}

/// Detail line: 2-space indent, muted.
pub fn detail(text: &str) {
    eprintln!("  {}  {}{}", Colors::muted(), text, reset());
}

/// Warning: ⚠ prefix, gold.
pub fn warning(text: &str) {
    eprintln!("  {}⚠ {}{}", Colors::gold(), text, reset());
}

/// Code/config line: 2-space indent, muted. For config snippets shown as guidance.
pub fn code_line(text: &str) {
    eprintln!("  {}  {}{}", Colors::dim(), text, reset());
}

/// "What's next" guidance block. Printed after successful secret storage.
/// Each step is a string like "hermetic list  — verify your secrets".
pub fn next_steps(steps: &[&str]) {
    gap();
    eprintln!("  {}  What's next:{}", Colors::muted(), reset());
    for step_text in steps {
        eprintln!("  {}  → {}{}", Colors::dim(), step_text, reset());
    }
}

/// Passphrase strength bar: renders a colored bar with label.
/// level is 0..=max_level. Colors: red (weak), gold (fair), green (strong).
pub fn passphrase_strength_bar(label: &str, level: u8, max_level: u8) {
    let filled = level as usize;
    let empty = (max_level as usize).saturating_sub(filled);
    let (color, _label_color) = if level <= 2 {
        (Colors::red(), Colors::red())
    } else if level <= 4 {
        (Colors::gold(), Colors::gold())
    } else {
        (Colors::green(), Colors::green())
    };
    let r = reset();
    eprintln!(
        "  {}  [{}{}{}{}] {}{}",
        Colors::muted(),
        color,
        "█".repeat(filled),
        Colors::muted(),
        "░".repeat(empty),
        label,
        r
    );
}

/// Run a closure while displaying a spinner on a background thread.
/// The spinner reuses the existing `Spinner` struct and ticks every 80ms.
/// Returns the result of the closure.
pub fn run_with_spinner<T, F: FnOnce() -> T + Send>(message: &str, f: F) -> T
where
    T: Send,
{
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    // If color is disabled, just run without spinner
    if !color_enabled() {
        return f();
    }

    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = Arc::clone(&stop);
    let msg = message.to_string();

    let handle = std::thread::spawn(move || {
        let mut spinner = Spinner::new(&msg);
        while !stop_clone.load(Ordering::Relaxed) {
            spinner.tick();
            std::thread::sleep(std::time::Duration::from_millis(80));
        }
        spinner.finish();
    });

    let result = f();
    stop.store(true, Ordering::Relaxed);
    let _ = handle.join();
    step_done(message, "done");
    result
}

// ── v1.1: OSC 8 hyperlinks + browser open ──────────────────────────────

/// Emit an OSC 8 clickable hyperlink for supported terminals.
/// Falls back to plain URL text if NO_COLOR is set or TERM=dumb.
/// See: https://gist.github.com/egmontkob/eb114294efbcd5adb1944c9f3cb5feda
pub fn hyperlink(url: &str, label: &str) -> String {
    let no_color = std::env::var("NO_COLOR").is_ok()
        || std::env::var("TERM").map(|t| t == "dumb").unwrap_or(false);
    hyperlink_inner(url, label, no_color)
}

/// Inner function for testability (avoids env var dependency in tests).
fn hyperlink_inner(url: &str, label: &str, no_color: bool) -> String {
    if no_color {
        return url.to_string();
    }
    format!("\x1b]8;;{url}\x1b\\{label}\x1b]8;;\x1b\\")
}

/// Open URL in system browser via xdg-open (Linux).
/// Fire-and-forget: stdin/stdout/stderr null.
/// Returns Ok if launched, Err with message if unavailable.
///
/// Correction 3: Rejects non-HTTPS URLs to prevent file://, javascript:,
/// data:, or other scheme injection into the system URL handler.
///
/// NOTE: xdg-open is NOT in the HC-8 blocklist (it's a desktop utility,
/// not a shell or interpreter). Verified against process.rs:65-96.
pub fn open_browser(url: &str) -> Result<(), String> {
    if !url.starts_with("https://") {
        return Err("Browser open requires https:// URL".into());
    }
    std::process::Command::new("xdg-open")
        .arg(url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("Cannot open browser: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_duration_milliseconds() {
        assert_eq!(format_duration(0.5), "500ms");
        assert_eq!(format_duration(0.042), "42ms");
    }

    #[test]
    fn test_format_duration_seconds() {
        assert_eq!(format_duration(1.24), "1.24s");
        assert_eq!(format_duration(3.0), "3.00s");
    }

    #[test]
    fn test_slot_info() {
        assert_eq!(slot_info(2, 15), "2/15 slots used");
        assert_eq!(slot_info(0, 15), "0/15 slots used");
    }

    #[test]
    fn test_status_box_builds() {
        // Smoke test — just ensure it doesn't panic
        let _ = StatusBox::new("TEST STATUS")
            .width(38)
            .row("State", "SEALED", StatusColor::Red)
            .row("Secrets", "0 / 15", StatusColor::Cyan);
    }

    #[test]
    fn test_color_fg_no_color() {
        // When NO_COLOR is set, fg() should return empty string
        // (This test documents the behavior; actual env var manipulation
        //  would require more infrastructure)
        let _ = fg(255, 0, 0);
    }

    // ── HC-11: SafeStr tests ──

    #[test]
    fn t_hc11_1_strips_ansi_escape() {
        let s = SafeStr::new("hello\x1b[2Jworld");
        assert_eq!(s.as_str(), "hello[2Jworld");
        // ESC (U+001B) stripped, but the printable chars [2J remain
    }

    #[test]
    fn t_hc11_2_strips_null_byte() {
        let s = SafeStr::new("hello\0world");
        assert_eq!(s.as_str(), "helloworld");
    }

    #[test]
    fn t_hc11_3_preserves_newline() {
        let s = SafeStr::new("line1\nline2");
        assert_eq!(s.as_str(), "line1\nline2");
    }

    #[test]
    fn t_hc11_4_strips_zero_width_space() {
        let s = SafeStr::new("api\u{200B}key");
        assert_eq!(s.as_str(), "apikey");
    }

    #[test]
    fn t_hc11_5_strips_bidi_override() {
        // U+202E (Right-to-Left Override) is Unicode category Cf, NOT Cc.
        // It is NOT caught by char::is_control(). SafeStr must strip it
        // via the explicit 0x202A..=0x202E match range.
        let s = SafeStr::new("normal\u{202E}reversed");
        assert!(!s.as_str().contains('\u{202E}'));
        assert_eq!(s.as_str(), "normalreversed");
    }

    #[test]
    fn t_hc11_6_preserves_printable() {
        let s = SafeStr::new("Hello, \u{4e16}\u{754c}! \u{00d1} \u{00e9} \u{00fc}");
        assert_eq!(
            s.as_str(),
            "Hello, \u{4e16}\u{754c}! \u{00d1} \u{00e9} \u{00fc}"
        );
    }

    #[test]
    fn t_hc11_7_display_trait() {
        let s = SafeStr::new("test\x1b[31mred");
        assert_eq!(format!("{}", s), "test[31mred");
    }

    #[test]
    fn t_hc11_8_full_ansi_sequence() {
        // Full terminal title attack: ESC]2;pwned BEL
        // ESC (U+001B) removed by is_control(), BEL (U+0007) also removed.
        // Sequence neutralized by eliminating the ESC prerequisite byte.
        let s = SafeStr::new("\x1b]2;pwned\x07");
        assert!(!s.as_str().contains('\x1b'));
        assert!(!s.as_str().contains('\x07'));
    }

    #[test]
    fn t_hc11_9_strips_all_bidi_embeddings() {
        // All five bidi embedding/override code points (U+202A–U+202E)
        // are Cf category, not Cc. Requires explicit match in SafeStr.
        let input = "a\u{202A}b\u{202B}c\u{202C}d\u{202D}e\u{202E}f";
        let s = SafeStr::new(input);
        assert_eq!(s.as_str(), "abcdef");
    }

    #[test]
    fn test_operational_functions_callable() {
        // Smoke test — verify no panics. stderr captured by test harness.
        op("test op");
        op_ok("test ok");
        op_fail("test fail");
        detail("test detail");
        warning("test warning");
    }

    #[test]
    fn test_hyperlink_renders_osc8() {
        // Force color mode by ensuring NO_COLOR is not set for this test
        let result = hyperlink_inner("https://example.com", "click here", false);
        assert!(result.contains("\x1b]8;;https://example.com\x1b\\"));
        assert!(result.contains("click here"));
        assert!(result.ends_with("\x1b]8;;\x1b\\"));
    }

    #[test]
    fn test_hyperlink_fallback_no_color() {
        let result = hyperlink_inner("https://example.com", "click here", true);
        assert_eq!(result, "https://example.com");
        assert!(!result.contains("\x1b"));
    }
}
