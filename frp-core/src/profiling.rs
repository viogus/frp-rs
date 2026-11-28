//! CPU profiling via pprof (gated behind `profiling` feature).
//!
//! Provides the primary `dump_cpu_profile` function: sample for a wall-clock
//! duration, write a flamegraph SVG, return the file path.
//!
//! OFF in all shipped builds — production binaries never include this
//! module (feature is opt-in and not in any default/tiny/micro set).

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Default sampling frequency: 99 Hz (matches pprof crate default).
const DEFAULT_FREQUENCY: i32 = 99;

/// Canvas dimensions for the in-tree SVG flamegraph renderer.
const SVG_WIDTH: f64 = 1200.0;
const MARGIN_X: f64 = 10.0;
const PLOT_WIDTH: f64 = SVG_WIDTH - 2.0 * MARGIN_X;
const HEADER_HEIGHT: f64 = 32.0;
const FRAME_HEIGHT: f64 = 16.0;
const FOOTER_HEIGHT: f64 = 12.0;
const MIN_BAR_WIDTH: f64 = 0.1;
const MIN_LABEL_WIDTH: f64 = 24.0;
const MAX_FLAME_DEPTH: usize = 512;

/// Months (non-leap days), indexed 0 = January.
const MONTH_DAYS: &[u64] = &[31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Run a CPU profile for `duration`, writing a flamegraph SVG to
/// `output_dir/{prefix}_{timestamp}.svg`.
///
/// The profiler samples at `DEFAULT_FREQUENCY` (99 Hz) using a per-process
/// `setitimer(ITIMER_PROF)` timer.  The calling thread is blocked for the
/// profiling window; in async contexts use `tokio::task::spawn_blocking`.
///
/// The output file name includes a human-readable UTC timestamp
/// (`YYYYMMDD_HHMMSS`) so multiple runs do not collide.
///
/// # Errors
///
/// Returns an error if the output directory cannot be created, the profiler
/// cannot be started (e.g. another guard is already active), the flamegraph
/// cannot be written, etc.
pub fn dump_cpu_profile(
    duration: Duration,
    output_dir: &Path,
    prefix: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    fs::create_dir_all(output_dir)?;

    let timestamp = format_timestamp(SystemTime::now());
    let filename = format!("{}_{}.svg", prefix, timestamp);
    let output_path = output_dir.join(&filename);

    let guard = pprof::ProfilerGuardBuilder::default()
        .frequency(DEFAULT_FREQUENCY)
        .blocklist(&["libc", "libgcc", "pthread", "vdso"])
        .build()?;

    // Block for the sampling window while the signal handler fires.
    std::thread::sleep(duration);

    let report = guard.report().build()?;
    let file = fs::File::create(&output_path)?;
    let mut writer = std::io::BufWriter::new(file);
    write_report_flamegraph_svg(&report, &mut writer)?;
    writer.flush()?;

    Ok(output_path)
}

#[derive(Default)]
struct FlameNode {
    total: u64,
    children: BTreeMap<String, FlameNode>,
}

impl Drop for FlameNode {
    fn drop(&mut self) {
        // Drain deep tries iteratively so stack depth stays O(1) up to `MAX_FLAME_DEPTH`.
        let mut stack: Vec<BTreeMap<String, FlameNode>> = Vec::new();
        if !self.children.is_empty() {
            stack.push(std::mem::take(&mut self.children));
        }
        while let Some(map) = stack.pop() {
            for (_name, mut child) in map {
                if !child.children.is_empty() {
                    stack.push(std::mem::take(&mut child.children));
                }
            }
        }
    }
}

/// Strip control characters / XML noncharacters and replace empty names with `"Unknown"`.
fn sanitize_label(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .filter(|&c| !c.is_control() && c != '\u{fffe}' && c != '\u{ffff}')
        .collect();
    if cleaned.is_empty() {
        "Unknown".to_string()
    } else {
        cleaned
    }
}

/// Escape text and attribute values for XML 1.0/SVG output.
fn xml_escape(input: &str) -> Cow<'_, str> {
    if !input.contains(['&', '<', '>', '"', '\'']) {
        return Cow::Borrowed(input);
    }
    let mut out = String::with_capacity(input.len() + 8);
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(ch),
        }
    }
    Cow::Owned(out)
}

/// Truncate plain text by Unicode scalar count before XML escaping so entities are never split.
fn truncate_chars(input: &str, max_chars: usize) -> Cow<'_, str> {
    if max_chars == 0 {
        return Cow::Borrowed("");
    }
    if input.chars().count() <= max_chars {
        return Cow::Borrowed(input);
    }
    if max_chars <= 2 {
        return Cow::Owned(input.chars().take(max_chars).collect());
    }
    let mut out: String = input.chars().take(max_chars - 2).collect();
    out.push_str("..");
    Cow::Owned(out)
}

/// Deterministic warm flame RGB palette keyed by frame label (FNV-1a).
fn flame_color(name: &str) -> (u8, u8, u8) {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in name.as_bytes() {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    let v1 = hash & 0xffff;
    let v2 = (hash >> 16) & 0xffff;
    let v3 = (hash >> 32) & 0xffff;
    let r = (205 + (v1 % 50)) as u8;
    let g = ((v2 * 230) / 65536) as u8;
    let b = ((v3 * 55) / 65536) as u8;
    (r, g, b)
}

fn build_flame_trie(report: &pprof::Report) -> FlameNode {
    let mut root = FlameNode::default();
    for (frames, &raw_count) in &report.data {
        if raw_count <= 0 {
            continue;
        }
        let count = raw_count as u64;
        root.total = root.total.saturating_add(count);

        let mut cur = &mut root;
        let thread_label = sanitize_label(&frames.thread_name_or_id());
        cur = cur.children.entry(thread_label).or_default();
        cur.total = cur.total.saturating_add(count);
        let mut depth = 1usize;

        // `pprof::Frames` stores innermost leaf first; iterate outer and inner
        // slices in reverse to build caller -> callee flame stacks.
        for frame in frames.frames.iter().rev() {
            for symbol in frame.iter().rev() {
                if depth >= MAX_FLAME_DEPTH {
                    break;
                }
                let sym_label = sanitize_label(&symbol.name());
                cur = cur.children.entry(sym_label).or_default();
                cur.total = cur.total.saturating_add(count);
                depth += 1;
            }
            if depth >= MAX_FLAME_DEPTH {
                break;
            }
        }
    }
    root
}

fn compute_visible_max_depth(root: &FlameNode) -> usize {
    let mut max_depth = 0usize;
    let mut stack = vec![(root, 0usize)];
    while let Some((node, depth)) = stack.pop() {
        if depth > max_depth {
            max_depth = depth;
        }
        for child in node.children.values() {
            let child_w = (child.total as f64 / root.total as f64) * PLOT_WIDTH;
            if child_w >= MIN_BAR_WIDTH {
                stack.push((child, depth + 1));
            }
        }
    }
    max_depth
}

fn write_svg_preamble<W: Write>(
    writer: &mut W,
    height: f64,
    style_css: &str,
) -> std::io::Result<()> {
    writeln!(writer, r#"<?xml version="1.0" standalone="no"?>"#)?;
    writeln!(
        writer,
        r#"<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">"#
    )?;
    writeln!(
        writer,
        r#"<svg version="1.1" width="{w:.0}" height="{h:.0}" viewBox="0 0 {w:.0} {h:.0}" xmlns="http://www.w3.org/2000/svg">"#,
        w = SVG_WIDTH,
        h = height
    )?;
    writeln!(writer, "<style>{style_css}</style>")?;
    writeln!(
        writer,
        r##"<rect x="0" y="0" width="{w:.0}" height="{h:.0}" fill="#ffffff" />"##,
        w = SVG_WIDTH,
        h = height
    )?;
    Ok(())
}

/// Write a standalone SVG flamegraph for `report` using safe std-only XML rendering.
fn write_report_flamegraph_svg<W: Write>(
    report: &pprof::Report,
    writer: &mut W,
) -> std::io::Result<()> {
    let root = build_flame_trie(report);
    if root.total == 0 {
        write_svg_preamble(
            writer,
            80.0,
            ".title { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 16px; font-weight: bold; fill: #222; text-anchor: middle; } .empty { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 12px; fill: #555; text-anchor: middle; }",
        )?;
        writeln!(
            writer,
            r#"<text class="title" x="600" y="28">CPU Flame Graph (0 samples)</text>"#
        )?;
        writeln!(
            writer,
            r#"<text class="empty" x="600" y="54">No CPU samples captured during the profiling window.</text>"#
        )?;
        writeln!(writer, "</svg>")?;
        return Ok(());
    }

    let max_depth = compute_visible_max_depth(&root);
    let total_height = HEADER_HEIGHT + ((max_depth + 1) as f64) * FRAME_HEIGHT + FOOTER_HEIGHT;
    let bar_height = FRAME_HEIGHT - 1.0;

    write_svg_preamble(
        writer,
        total_height,
        ".title { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 16px; font-weight: bold; fill: #222; text-anchor: middle; } .lbl { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 11px; fill: #111; } rect:hover { stroke: #111; stroke-width: 0.6; }",
    )?;
    writeln!(
        writer,
        r#"<text class="title" x="{x:.0}" y="22">CPU Flame Graph ({samples} samples)</text>"#,
        x = SVG_WIDTH / 2.0,
        samples = root.total
    )?;

    let mut stack = vec![("all", &root, 0usize, MARGIN_X)];
    while let Some((name, node, depth, x)) = stack.pop() {
        let width = (node.total as f64 / root.total as f64) * PLOT_WIDTH;
        if width < MIN_BAR_WIDTH {
            continue;
        }
        let y = HEADER_HEIGHT + ((max_depth - depth) as f64) * FRAME_HEIGHT;
        let (r, g, b) = flame_color(name);
        let pct = (node.total as f64 / root.total as f64) * 100.0;
        let escaped_title = xml_escape(name);

        writeln!(writer, "<g>")?;
        writeln!(
            writer,
            r#"  <title>{escaped_title} ({samples} samples, {pct:.2}%)</title>"#,
            samples = node.total
        )?;
        writeln!(
            writer,
            r#"  <rect x="{x:.2}" y="{y:.2}" width="{width:.2}" height="{bar_height:.2}" fill="rgb({r},{g},{b})" rx="1" ry="1" />"#
        )?;
        if width >= MIN_LABEL_WIDTH {
            let max_chars = ((width - 6.0) / 7.0).floor() as usize;
            if max_chars >= 1 {
                let truncated = truncate_chars(name, max_chars);
                let escaped_label = xml_escape(&truncated);
                writeln!(
                    writer,
                    r#"  <text class="lbl" x="{tx:.2}" y="{ty:.2}">{escaped_label}</text>"#,
                    tx = x + 3.0,
                    ty = y + 11.5
                )?;
            }
        }
        writeln!(writer, "</g>")?;

        let mut child_x = x;
        let base_len = stack.len();
        for (child_name, child_node) in &node.children {
            let child_w = (child_node.total as f64 / root.total as f64) * PLOT_WIDTH;
            if child_w >= MIN_BAR_WIDTH {
                stack.push((child_name.as_str(), child_node, depth + 1, child_x));
            }
            child_x += child_w;
        }
        stack[base_len..].reverse();
    }

    writeln!(writer, "</svg>")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Timestamp formatting (no chrono dependency)
// ---------------------------------------------------------------------------

/// Format a `SystemTime` as `YYYYMMDD_HHMMSS` (UTC).
///
/// Assumes every day has exactly 86400 seconds (no leap seconds).
/// `SystemTime` is not guaranteed to be monotonic across leap seconds,
/// but for profiling file names the resulting timestamp is always unique
/// and chronologically ordered, which is sufficient.
fn format_timestamp(now: SystemTime) -> String {
    let secs = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();

    let days = secs / 86400;
    let time_secs = secs % 86400;

    let hour = time_secs / 3600;
    let min = (time_secs / 60) % 60;
    let sec = time_secs % 60;

    let (year, month, day) = days_to_date(days);
    format!(
        "{:04}{:02}{:02}_{:02}{:02}{:02}",
        year, month, day, hour, min, sec
    )
}

fn is_leap_year(year: u64) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

fn days_to_date(mut days: u64) -> (u64, u64, u64) {
    // Find year.
    let mut year = 1970u64;
    loop {
        let year_len = if is_leap_year(year) { 366 } else { 365 };
        if days < year_len {
            break;
        }
        days -= year_len;
        year += 1;
    }

    // Find month.
    let leap = is_leap_year(year);
    for (i, &md) in MONTH_DAYS.iter().enumerate() {
        let mdays = if i == 1 && leap { 29 } else { md };
        if days < mdays {
            return (year, (i as u64) + 1, days + 1);
        }
        days -= mdays;
    }

    (year, 12, days + 1)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{LazyLock, Mutex};

    /// Serialize profiler access — pprof installs a process-wide signal
    /// handler, so only one guard can be active at a time.
    static TEST_MUTEX: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    // -- timestamp formatting -----------------------------------------------

    #[test]
    fn format_timestamp_epoch() {
        let s = format_timestamp(SystemTime::UNIX_EPOCH);
        assert_eq!(s, "19700101_000000");
    }

    #[test]
    fn format_timestamp_known_dates() {
        // 2024-01-01 00:00:00 UTC = 1704067200 → 19723 days
        let t1 = UNIX_EPOCH + Duration::from_secs(1704067200);
        assert_eq!(format_timestamp(t1), "20240101_000000");

        // 2024-02-29 12:34:56 UTC = 1709210096 → 19782 days + 45296 s
        let t2 = UNIX_EPOCH + Duration::from_secs(1709210096);
        assert_eq!(format_timestamp(t2), "20240229_123456");

        // 2025-01-01 00:00:00 UTC = 1735689600 → 20089 days
        let t3 = UNIX_EPOCH + Duration::from_secs(1735689600);
        assert_eq!(format_timestamp(t3), "20250101_000000");
    }

    #[test]
    fn is_leap_year_checks() {
        assert!(is_leap_year(2024));
        assert!(!is_leap_year(2023));
        assert!(!is_leap_year(1900));
        assert!(is_leap_year(2000));
    }

    // -- dump_cpu_profile ---------------------------------------------------

    #[test]
    fn dump_cpu_profile_creates_svg_file() {
        let _lock = TEST_MUTEX.lock().unwrap();
        let dir = tempfile::TempDir::new().unwrap();

        // Spawn a busy thread so the per-process ITIMER_PROF fires during the
        // sampling window.
        let stop = std::sync::atomic::AtomicBool::new(false);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    std::hint::spin_loop();
                }
            });

            let path = dump_cpu_profile(Duration::from_millis(200), dir.path(), "test_profile")
                .expect("dump_cpu_profile should succeed");
            stop.store(true, std::sync::atomic::Ordering::Relaxed);

            assert!(path.exists(), "output SVG should exist at {:?}", path);
            assert_eq!(
                path.extension().and_then(|e| e.to_str()),
                Some("svg"),
                "extension should be .svg"
            );

            // Verify it is valid non-empty SVG.
            let svg = std::fs::read_to_string(&path).expect("read SVG");
            assert!(svg.contains("<svg"), "output must start an SVG document");
            assert!(svg.contains("</svg>"), "output must close SVG document");
        });
    }

    #[test]
    fn dump_cpu_profile_non_existent_dir() {
        let _lock = TEST_MUTEX.lock().unwrap();
        let dir = tempfile::TempDir::new().unwrap();
        let sub = dir.path().join("nonexistent").join("deep");

        let path = dump_cpu_profile(Duration::from_millis(10), &sub, "test")
            .expect("should create parent dirs");
        assert!(path.exists());
        let svg = std::fs::read_to_string(&path).expect("read SVG");
        assert!(svg.contains("<svg"), "output must contain <svg");
        assert!(svg.contains("</svg>"), "output must contain </svg>");
    }

    #[test]
    fn dump_cpu_profile_concurrent_guard_returns_error() {
        let _lock = TEST_MUTEX.lock().unwrap();
        // Start a first guard.
        let g1 = pprof::ProfilerGuard::new(99).expect("first guard");
        let dir = tempfile::TempDir::new().unwrap();

        // A second dump_cpu_profile attempt should fail (only one guard
        // can be active at a time).
        let result = dump_cpu_profile(Duration::from_millis(10), dir.path(), "dup");
        assert!(result.is_err(), "concurrent profile should error");

        drop(g1);
    }

    fn make_test_symbol(name: &str) -> pprof::Symbol {
        pprof::Symbol {
            name: Some(name.as_bytes().to_vec()),
            addr: None,
            lineno: None,
            filename: None,
        }
    }

    fn make_test_report(entries: Vec<(pprof::Frames, isize)>) -> pprof::Report {
        let mut data = std::collections::HashMap::new();
        for (frames, count) in entries {
            data.insert(frames, count);
        }
        pprof::Report {
            data,
            timing: Default::default(),
        }
    }

    fn extract_y_for_title(svg: &str, title_prefix: &str) -> f64 {
        let mut lines = svg.lines().peekable();
        while let Some(line) = lines.next() {
            if line.contains("<title>") && line.contains(title_prefix) {
                if let Some(rect_line) = lines.next() {
                    if let Some(rest) = rect_line.split(" y=\"").nth(1) {
                        if let Some(y_str) = rest.split('"').next() {
                            return y_str.parse::<f64>().expect("valid numeric y");
                        }
                    }
                }
            }
        }
        panic!("missing <rect y=...> for title prefix {title_prefix}");
    }

    #[test]
    fn svg_renderer_handles_zero_samples_and_non_positive_counts() {
        let empty = make_test_report(vec![]);
        let mut buf = Vec::new();
        write_report_flamegraph_svg(&empty, &mut buf).expect("empty report succeeds");
        let svg = String::from_utf8(buf).expect("valid utf-8");
        assert!(svg.contains("<svg"));
        assert!(svg.contains("</svg>"));
        assert!(svg.contains("CPU Flame Graph (0 samples)"));

        let f_zero = pprof::Frames {
            frames: vec![vec![make_test_symbol("ignored_zero")]],
            thread_name: "worker".to_string(),
            thread_id: 1,
            sample_timestamp: UNIX_EPOCH,
        };
        let f_neg = pprof::Frames {
            frames: vec![vec![make_test_symbol("ignored_neg")]],
            thread_name: "worker".to_string(),
            thread_id: 2,
            sample_timestamp: UNIX_EPOCH,
        };
        let f_min = pprof::Frames {
            frames: vec![vec![make_test_symbol("ignored_min")]],
            thread_name: "worker".to_string(),
            thread_id: 3,
            sample_timestamp: UNIX_EPOCH,
        };
        let non_pos = make_test_report(vec![(f_zero, 0), (f_neg, -5), (f_min, isize::MIN)]);
        let mut buf2 = Vec::new();
        write_report_flamegraph_svg(&non_pos, &mut buf2).expect("non-positive counts succeed");
        let svg2 = String::from_utf8(buf2).expect("valid utf-8");
        assert!(svg2.contains("CPU Flame Graph (0 samples)"));
    }

    #[test]
    fn truncate_chars_handles_boundaries_and_utf8() {
        assert_eq!(truncate_chars("abc", 0), "");
        assert_eq!(truncate_chars("a🔥c", 1), "a");
        assert_eq!(truncate_chars("a🔥c", 2), "a🔥");
        assert_eq!(truncate_chars("a🔥c", 3), "a🔥c");
        assert_eq!(truncate_chars("a🔥cd", 3), "a..");
        assert_eq!(truncate_chars("αβγδεζη", 5), "αβγ..");
    }

    #[test]
    fn svg_renderer_escapes_xml_handles_utf8_and_orders_stacks_bottom_up() {
        // `pprof` stores innermost leaf first: frames = [ [leaf_sym, inlined_caller], [caller] ]
        // Expected bottom-up stack: all -> thread -> caller -> inlined_caller -> leaf_sym.
        let long_leaf = format!(
            "leaf_<utf8>_🔥_{}",
            "x&y".repeat(60) // 195 chars (> max_chars ~125 at 75% width) forces truncation + escaping
        );
        let frames1 = pprof::Frames {
            frames: vec![
                vec![
                    make_test_symbol(&long_leaf),
                    make_test_symbol("<alloc::vec::Vec<u8> as Drop>::drop"),
                ],
                vec![make_test_symbol("caller_a&b\"'c")],
            ],
            thread_name: "工作线程\n_🔥".to_string(),
            thread_id: 7,
            sample_timestamp: UNIX_EPOCH,
        };
        let frames2 = pprof::Frames {
            frames: vec![vec![make_test_symbol("caller_a&b\"'c")]],
            thread_name: "工作线程\n_🔥".to_string(),
            thread_id: 7,
            sample_timestamp: UNIX_EPOCH,
        };
        let report = make_test_report(vec![(frames1, 3), (frames2, 1)]);
        let mut buf = Vec::new();
        write_report_flamegraph_svg(&report, &mut buf).expect("render succeeds");
        let svg = String::from_utf8(buf).expect("valid utf-8");

        assert!(svg.contains("CPU Flame Graph (4 samples)"));
        assert!(svg.contains("<title>all (4 samples, 100.00%)</title>"));
        assert!(svg.contains("&lt;alloc::vec::Vec&lt;u8&gt; as Drop&gt;::drop (3 samples, 75.00%)"));
        assert!(svg.contains("caller_a&amp;b&quot;&apos;c (4 samples, 100.00%)"));
        assert!(svg.contains("工作线程_🔥 (4 samples, 100.00%)"));
        // Exact escaped <text> labels are emitted (no raw unescaped generic brackets or unclosed entities).
        assert!(svg.contains("&lt;alloc::vec::Vec&lt;u8&gt; as Drop&gt;::drop</text>"));
        assert!(svg.contains("caller_a&amp;b&quot;&apos;c</text>"));
        let leaf_label_line = svg
            .lines()
            .find(|l| l.contains("leaf_&lt;utf8&gt;_🔥_") && l.contains("<text class=\"lbl\""))
            .expect("truncated leaf <text> must be present");
        assert!(leaf_label_line.ends_with("..</text>"));
        assert!(!svg.contains("<title><alloc"));

        // Bottom-up y coordinates: root "all" at bottom (largest y), then thread, caller, drop, leaf at top (smallest y).
        let y_all = extract_y_for_title(&svg, "all (");
        let y_thread = extract_y_for_title(&svg, "工作线程_🔥 (");
        let y_caller = extract_y_for_title(&svg, "caller_a&amp;b&quot;&apos;c (");
        let y_drop = extract_y_for_title(&svg, "&lt;alloc::vec::Vec&lt;u8&gt;");
        let y_leaf = extract_y_for_title(&svg, "leaf_&lt;utf8&gt;_🔥_");
        assert!(y_all > y_thread && y_thread > y_caller && y_caller > y_drop && y_drop > y_leaf);
    }

    #[test]
    fn svg_renderer_covers_narrow_bars_fallbacks_and_visible_depth() {
        // 1) Empty thread_name -> thread_id fallback; control-only + U+FFFF symbol -> "Unknown" fallback.
        // 2) Sub-pixel sibling (<0.1 px) is skipped and pruned from visible max_depth while narrow bar renders without text.
        let hidden_spike = pprof::Frames {
            frames: (0..600)
                .map(|i| vec![make_test_symbol(&format!("deep_{i}"))])
                .collect(),
            thread_name: "".to_string(),
            thread_id: 99,
            sample_timestamp: UNIX_EPOCH,
        };
        let narrow_no_label = pprof::Frames {
            frames: vec![vec![make_test_symbol("narrow_bar")]],
            thread_name: "narrow_thr".to_string(),
            thread_id: 100,
            sample_timestamp: UNIX_EPOCH,
        };
        let wide_unknown = pprof::Frames {
            frames: vec![vec![make_test_symbol("\x00\n\t\u{ffff}")]],
            thread_name: "".to_string(),
            thread_id: 42,
            sample_timestamp: UNIX_EPOCH,
        };
        // total = 1 (hidden) + 100 (narrow, ~5.9px < MIN_LABEL_WIDTH) + 19_899 (wide) = 20_000
        let report = make_test_report(vec![
            (hidden_spike, 1),
            (narrow_no_label, 100),
            (wide_unknown, 19_899),
        ]);
        let mut buf = Vec::new();
        write_report_flamegraph_svg(&report, &mut buf).expect("render succeeds");
        let svg = String::from_utf8(buf).expect("valid utf-8");

        assert!(svg.contains("<title>42 (19899 samples, 99.50%)</title>"));
        assert!(svg.contains("<title>Unknown (19899 samples, 99.50%)</title>"));
        assert!(svg.contains("<title>narrow_bar (100 samples, 0.50%)</title>"));
        assert!(!svg.contains("narrow_bar</text>"));
        // Sub-pixel 600-deep spike (<0.1px at 1/20_000) is pruned and must not bloat SVG height (visible max_depth = 2 -> height = 92).
        assert!(!svg.contains("deep_0"));
        assert!(svg.contains(r#"height="92""#));
    }

    #[test]
    fn svg_renderer_clamps_depth_and_drops_iteratively() {
        // 600 frames reversed: root (depth 0) + thread (depth 1) + 511 frame levels = depth 512 (f_89),
        // while f_88..f_0 are clamped at MAX_FLAME_DEPTH.
        let deep = pprof::Frames {
            frames: (0..600)
                .map(|i| vec![make_test_symbol(&format!("f_{i}"))])
                .collect(),
            thread_name: "deep_thr".to_string(),
            thread_id: 5,
            sample_timestamp: UNIX_EPOCH,
        };
        let report = make_test_report(vec![(deep, 10)]);
        let mut buf = Vec::new();
        write_report_flamegraph_svg(&report, &mut buf).expect("deep report succeeds");
        let svg = String::from_utf8(buf).expect("valid utf-8");

        assert!(svg.contains("<title>f_599 (10 samples, 100.00%)</title>"));
        assert!(svg.contains("<title>f_89 (10 samples, 100.00%)</title>"));
        assert!(!svg.contains("<title>f_88 "));
    }

    #[test]
    fn svg_renderer_propagates_write_errors() {
        struct FailingWriter;
        impl Write for FailingWriter {
            fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "disk full",
                ))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let report_empty = make_test_report(vec![]);
        let err = write_report_flamegraph_svg(&report_empty, &mut FailingWriter)
            .expect_err("empty report write failure must return Err");
        assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);

        let f = pprof::Frames {
            frames: vec![vec![make_test_symbol("some_fn")]],
            thread_name: "t".to_string(),
            thread_id: 1,
            sample_timestamp: UNIX_EPOCH,
        };
        let report_nonempty = make_test_report(vec![(f, 5)]);
        let err2 = write_report_flamegraph_svg(&report_nonempty, &mut FailingWriter)
            .expect_err("non-empty report write failure must return Err");
        assert_eq!(err2.kind(), std::io::ErrorKind::BrokenPipe);
    }
}
