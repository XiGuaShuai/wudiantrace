use crate::file_reader::FileReader;
use memchr::memchr_iter;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver};
use std::sync::Arc;
use std::thread;

/// One entry in the sparse checkpoint table used by large files.
///
/// The invariant is that `byte_pos` is the **start of a line** — it either
/// equals `0` or points immediately after a `\n`. `line_index` is the
/// zero-based number of that line in the whole file. Keeping checkpoints on
/// line boundaries lets a query answer an exact line ↔ byte mapping by
/// scanning at most one checkpoint's worth of bytes.
#[derive(Clone, Copy, Debug)]
struct SparseCheckpoint {
    byte_pos: usize,
    line_index: usize,
}

/// Messages the background scan worker posts back to the main thread. A
/// Seed is delivered first (after a cheap 10 MB sample) so estimates snap
/// from "rough file_size/80" to "based on this file's actual line density"
/// without blocking the UI on disk I/O; the Exact message follows once
/// the full scan completes.
enum IndexMsg {
    Seed {
        avg_line_length: f64,
        total_lines_estimate: usize,
    },
    Exact {
        checkpoints: Vec<SparseCheckpoint>,
        total_lines: usize,
    },
}

/// Live background scan. Dropping the indexer or starting a new scan flips
/// `cancel` so the worker thread exits on its next cancellation check.
struct PendingExactIndex {
    rx: Receiver<IndexMsg>,
    cancel: Arc<AtomicBool>,
}

pub struct LineIndexer {
    /// Full-index mode only: byte offset of each line's first character.
    /// Length equals `total_lines`.
    line_offsets: Vec<usize>,
    /// Sparse-mode only: line-aligned checkpoints at roughly `sample_interval`
    /// byte intervals. The first entry is always `(0, 0)`.
    sparse_checkpoints: Vec<SparseCheckpoint>,
    total_lines: usize,
    indexed: bool,
    /// `0` means full index; otherwise the target spacing between sparse
    /// checkpoints, in bytes.
    sample_interval: usize,
    file_size: usize,
    avg_line_length: f64,
    /// Some while a sparse exact-scan runs in the background.
    pending: Option<PendingExactIndex>,
    /// True once sparse mode has an exact answer. Full-index mode is always
    /// exact and this flag is set immediately.
    exact_ready: bool,
}

impl Default for LineIndexer {
    fn default() -> Self {
        Self::new()
    }
}

impl LineIndexer {
    pub fn new() -> Self {
        Self {
            line_offsets: vec![0],
            sparse_checkpoints: Vec::new(),
            total_lines: 0,
            indexed: false,
            sample_interval: 0,
            file_size: 0,
            avg_line_length: 80.0,
            pending: None,
            exact_ready: false,
        }
    }

    /// Synchronous indexing. Blocks until the exact line index is ready,
    /// so queries immediately afterwards return exact answers. Fine for
    /// small files and for tests; in a GUI, prefer `index_file_async` so
    /// the UI thread stays responsive while a multi-GB file gets scanned.
    pub fn index_file(&mut self, reader: &FileReader) {
        self.abort_pending();
        self.reset_for_new_file(reader.len());

        const FULL_INDEX_THRESHOLD: usize = 10_000_000; // 10 MB

        if self.file_size <= FULL_INDEX_THRESHOLD {
            self.full_index(reader.all_data());
            self.sample_interval = 0;
            self.total_lines = self.line_offsets.len();
        } else {
            self.sample_interval = SPARSE_CHECKPOINT_INTERVAL;
            // Sync path only used by tests now — do both seed and full scan
            // inline so callers get exact answers immediately afterward.
            self.seed_avg_line_length_from(reader.all_data());
            let bytes = reader.all_data();
            let cancel = Arc::new(AtomicBool::new(false));
            if let Some((checkpoints, total_lines)) =
                sparse_scan_for_exact_index(bytes, SPARSE_CHECKPOINT_INTERVAL, &cancel)
            {
                self.ingest_exact(checkpoints, total_lines);
            }
        }

        self.indexed = true;
    }

    /// Non-blocking indexing. Returns immediately after seeding a cheap
    /// `avg_line_length` estimate (from the first 10 MB) so the UI is
    /// usable right away. The actual checkpoint scan runs on a background
    /// thread; call `poll` each frame from the UI loop to integrate the
    /// result once it's ready.
    ///
    /// While the background scan is in flight, queries fall back to
    /// estimation via `avg_line_length`. Those answers are good enough
    /// for scrolling and for first-approximation row labels; anything
    /// that needs exact numbers (taint jump landing line, Go-To-Line,
    /// precise search-result row) will snap into place once the exact
    /// index lands.
    pub fn index_file_async(&mut self, reader: Arc<FileReader>) {
        self.abort_pending();
        self.reset_for_new_file(reader.len());

        const FULL_INDEX_THRESHOLD: usize = 10_000_000;

        if self.file_size <= FULL_INDEX_THRESHOLD {
            // Full index is cheap — just do it synchronously and avoid the
            // ceremony of a worker thread for tens of milliseconds of work.
            self.full_index(reader.all_data());
            self.sample_interval = 0;
            self.total_lines = self.line_offsets.len();
            self.indexed = true;
            return;
        }

        self.sample_interval = SPARSE_CHECKPOINT_INTERVAL;
        // Cheap-as-it-gets initial estimate so the UI has *something* to
        // show this very frame: average ASCII log lines run ~80 bytes,
        // so file_size/80 is in the right order of magnitude. The Seed
        // message arriving milliseconds later refines it from real bytes;
        // the Exact message replaces it with the precise count.
        self.avg_line_length = 80.0;
        self.total_lines = self.file_size / 80;

        let (tx, rx) = channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let cancel_for_worker = cancel.clone();
        let reader_for_worker = reader;

        thread::spawn(move || {
            // Phase 1: 10 MB sample → real avg_line_length. This touches
            // pages that may not be in OS cache yet (slow on cold-disk),
            // but doing it here instead of on the UI thread is the
            // difference between "drag-drop freezes for 300 ms" and
            // "drag-drop responds instantly".
            const SEED_WINDOW: usize = 10_000_000;
            let bytes_all = reader_for_worker.all_data();
            let seed_end = SEED_WINDOW.min(bytes_all.len());
            if seed_end > 0 {
                let newlines = memchr_iter(b'\n', &bytes_all[..seed_end]).count();
                if newlines > 0 {
                    let avg = seed_end as f64 / newlines as f64;
                    let est = (bytes_all.len() as f64 / avg) as usize;
                    let _ = tx.send(IndexMsg::Seed {
                        avg_line_length: avg,
                        total_lines_estimate: est,
                    });
                }
            }
            if cancel_for_worker.load(Ordering::Relaxed) {
                return;
            }

            // Phase 2: full scan → exact checkpoints + total.
            if let Some((checkpoints, total_lines)) =
                sparse_scan_for_exact_index(bytes_all, SPARSE_CHECKPOINT_INTERVAL, &cancel_for_worker)
            {
                // SendError on a dropped receiver means the indexer moved on
                // (new file, shutdown) — silently ignore.
                let _ = tx.send(IndexMsg::Exact {
                    checkpoints,
                    total_lines,
                });
            }
        });

        self.pending = Some(PendingExactIndex { rx, cancel });
        self.indexed = true; // estimates are already usable
    }

    /// Drive async indexing forward. Returns `true` iff the **final** exact
    /// result landed this call (useful to trigger a UI repaint / cache
    /// invalidation). Intermediate `Seed` messages return `false` — they
    /// refine estimates but don't flip `exact_ready`.
    pub fn poll(&mut self) -> bool {
        let mut exact_landed = false;
        loop {
            let Some(pending) = self.pending.as_ref() else {
                break;
            };
            match pending.rx.try_recv() {
                Ok(IndexMsg::Seed {
                    avg_line_length,
                    total_lines_estimate,
                }) => {
                    // Keep the estimate improving — user sees row counts
                    // converge from "file_size/80" to "actual density"
                    // before the full scan completes.
                    self.avg_line_length = avg_line_length;
                    self.total_lines = total_lines_estimate;
                }
                Ok(IndexMsg::Exact {
                    checkpoints,
                    total_lines,
                }) => {
                    self.ingest_exact(checkpoints, total_lines);
                    self.pending = None;
                    exact_landed = true;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    // Worker exited (cancelled, panicked, or already sent
                    // the final message and dropped its sender).
                    self.pending = None;
                    break;
                }
            }
        }
        exact_landed
    }

    /// True while the background exact-index scan hasn't delivered yet.
    /// The UI can show an "indexing…" hint while this is true.
    pub fn is_indexing(&self) -> bool {
        self.pending.is_some()
    }

    fn reset_for_new_file(&mut self, file_size: usize) {
        self.line_offsets.clear();
        self.line_offsets.push(0);
        self.sparse_checkpoints.clear();
        self.total_lines = 0;
        self.file_size = file_size;
        self.avg_line_length = 80.0;
        self.exact_ready = false;
        self.indexed = false;
    }

    fn abort_pending(&mut self) {
        if let Some(p) = self.pending.take() {
            p.cancel.store(true, Ordering::Relaxed);
        }
    }

    fn seed_avg_line_length_from(&mut self, bytes: &[u8]) {
        // Only used by the sync `index_file` path (tests). The async path
        // does this on the background thread, see `index_file_async`.
        const SEED_WINDOW: usize = 10_000_000;
        let end = SEED_WINDOW.min(bytes.len());
        if end == 0 {
            return;
        }
        let newlines = memchr_iter(b'\n', &bytes[..end]).count();
        if newlines > 0 {
            self.avg_line_length = end as f64 / newlines as f64;
        }
        if self.avg_line_length > 0.0 {
            self.total_lines = (self.file_size as f64 / self.avg_line_length) as usize;
        }
    }

    fn ingest_exact(&mut self, checkpoints: Vec<SparseCheckpoint>, total_lines: usize) {
        self.sparse_checkpoints = checkpoints;
        self.total_lines = total_lines;
        self.exact_ready = true;
        if total_lines > 0 {
            self.avg_line_length = self.file_size as f64 / total_lines as f64;
        }
    }

    fn full_index(&mut self, data: &[u8]) {
        // memchr's SIMD scan is ~5–10× faster than the naive `iter().filter`
        // loop on large inputs; even the 10 MB full-index path benefits.
        for pos in memchr_iter(b'\n', data) {
            self.line_offsets.push(pos + 1);
        }
    }

    pub fn get_line_range(&self, line_num: usize) -> Option<(usize, usize)> {
        if self.sample_interval == 0 {
            if line_num >= self.line_offsets.len() {
                return None;
            }
            let start = self.line_offsets[line_num];
            let end = if line_num + 1 < self.line_offsets.len() {
                self.line_offsets[line_num + 1]
            } else {
                self.file_size
            };
            Some((start, end))
        } else {
            // Sparse path without reader access — best-effort estimate only,
            // kept for backward compatibility. Prefer `get_line_with_reader`.
            let est = (line_num as f64 * self.avg_line_length) as usize;
            Some((est, usize::MAX))
        }
    }

    /// Resolve `line_num` (0-based) to its exact `[start, end)` byte range
    /// when the exact index is ready. Falls back to an estimate (same math
    /// as the old pre-0.29 implementation) while the background scan is
    /// still running.
    pub fn get_line_with_reader(
        &self,
        line_num: usize,
        reader: &FileReader,
    ) -> Option<(usize, usize)> {
        if self.sample_interval == 0 {
            return self.get_line_range(line_num);
        }
        if !self.exact_ready {
            return Some(self.estimate_line_range(line_num, reader));
        }
        if line_num >= self.total_lines {
            return None;
        }

        // Rightmost checkpoint with line_index ≤ line_num.
        let cp_idx = match self
            .sparse_checkpoints
            .binary_search_by_key(&line_num, |cp| cp.line_index)
        {
            Ok(i) => i,
            Err(i) => i.saturating_sub(1),
        };
        let cp = self.sparse_checkpoints[cp_idx];
        let to_skip = line_num - cp.line_index;

        let scan_end = (cp.byte_pos + self.sample_interval * 3 / 2).min(self.file_size);
        if cp.byte_pos >= scan_end && to_skip == 0 {
            return Some((cp.byte_pos, cp.byte_pos));
        }
        let chunk = reader.get_bytes(cp.byte_pos, scan_end);

        let line_start = if to_skip == 0 {
            cp.byte_pos
        } else {
            // memchr_iter returns positions relative to `chunk` start.
            let mut iter = memchr_iter(b'\n', chunk);
            let mut nth = None;
            for _ in 0..to_skip {
                nth = iter.next();
                if nth.is_none() {
                    break;
                }
            }
            cp.byte_pos + nth? + 1
        };

        let rel_start = line_start - cp.byte_pos;
        let line_end = chunk
            .get(rel_start..)
            .and_then(|tail| memchr_iter(b'\n', tail).next())
            .map(|p| line_start + p)
            .unwrap_or_else(|| {
                let extra_end = (line_start + self.sample_interval).min(self.file_size);
                let extra = reader.get_bytes(line_start, extra_end);
                memchr_iter(b'\n', extra)
                    .next()
                    .map(|p| line_start + p)
                    .unwrap_or(extra_end)
            });

        Some((line_start, line_end))
    }

    /// Rough line-range estimate used while the async scan is still running
    /// (no exact checkpoints yet). Same shape as the original pre-0.29
    /// behavior: estimate by `line_num * avg_line_length`, then scan a
    /// neighborhood for real newlines so the line boundaries land on
    /// something plausible.
    fn estimate_line_range(&self, line_num: usize, reader: &FileReader) -> (usize, usize) {
        let est = (line_num as f64 * self.avg_line_length) as usize;
        let radius = (self.avg_line_length * 2.0).max(65536.0) as usize;
        let scan_start = est.saturating_sub(radius).min(self.file_size);
        let scan_end = (est + radius).min(self.file_size);
        if scan_start >= scan_end {
            return (est.min(self.file_size), est.min(self.file_size));
        }
        let chunk = reader.get_bytes(scan_start, scan_end);
        let rel_est = est.saturating_sub(scan_start);
        // Find previous newline to decide line start; default to scan_start.
        let line_start = chunk[..rel_est.min(chunk.len())]
            .iter()
            .rposition(|&b| b == b'\n')
            .map(|p| scan_start + p + 1)
            .unwrap_or(scan_start);
        // Find next newline for line end.
        let line_end = memchr_iter(b'\n', &chunk[line_start.saturating_sub(scan_start)..])
            .next()
            .map(|p| line_start + p)
            .unwrap_or(scan_end);
        (line_start, line_end)
    }

    /// Byte offset → 0-based line number. Exact in full-index mode; exact
    /// in sparse mode once the background scan completes; estimated (via
    /// `avg_line_length`) while it hasn't.
    pub fn find_line_at_offset(&self, offset: usize, reader: &FileReader) -> usize {
        if self.sample_interval == 0 {
            return match self.line_offsets.binary_search(&offset) {
                Ok(line) => line,
                Err(line) => line.saturating_sub(1),
            };
        }

        if !self.exact_ready {
            // Fallback estimate: offset / avg_line_length. Off by a few dozen
            // rows near EOF on multi-GB files but good enough for UI state
            // while the exact index is still being built.
            if self.avg_line_length <= 0.0 {
                return offset / 80;
            }
            return (offset as f64 / self.avg_line_length) as usize;
        }

        let offset = offset.min(self.file_size);
        let cp_idx = match self
            .sparse_checkpoints
            .binary_search_by_key(&offset, |cp| cp.byte_pos)
        {
            Ok(i) => i,
            Err(i) => i.saturating_sub(1),
        };
        let cp = self.sparse_checkpoints[cp_idx];
        if offset <= cp.byte_pos {
            return cp.line_index;
        }
        let bytes = reader.get_bytes(cp.byte_pos, offset);
        let newlines = memchr_iter(b'\n', bytes).count();
        cp.line_index + newlines
    }

    pub fn total_lines(&self) -> usize {
        self.total_lines
    }
}

impl Drop for LineIndexer {
    fn drop(&mut self) {
        self.abort_pending();
    }
}

const SPARSE_CHECKPOINT_INTERVAL: usize = 10_000_000; // 10 MB

/// Walk the whole file once counting `\n` bytes (SIMD-accelerated via
/// `memchr`) and drop a line-aligned checkpoint each time we cross an
/// `interval`-byte boundary. O(file_size) memory bandwidth with negligible
/// allocation; cancellation is checked every 1 MB of newlines so a user
/// opening a new file promptly aborts the previous scan.
fn sparse_scan_for_exact_index(
    bytes: &[u8],
    interval: usize,
    cancel: &AtomicBool,
) -> Option<(Vec<SparseCheckpoint>, usize)> {
    let mut checkpoints = Vec::with_capacity(bytes.len() / interval + 1);
    checkpoints.push(SparseCheckpoint {
        byte_pos: 0,
        line_index: 0,
    });

    let mut cumulative: usize = 0;
    let mut last_cp_byte: usize = 0;
    const CANCEL_CHECK_MASK: usize = (1 << 20) - 1; // every 2^20 newlines

    for nl_pos in memchr_iter(b'\n', bytes) {
        cumulative += 1;
        let next_line_start = nl_pos + 1;
        if next_line_start >= last_cp_byte + interval && next_line_start < bytes.len() {
            checkpoints.push(SparseCheckpoint {
                byte_pos: next_line_start,
                line_index: cumulative,
            });
            last_cp_byte = next_line_start;
        }
        if cumulative & CANCEL_CHECK_MASK == 0 && cancel.load(Ordering::Relaxed) {
            return None;
        }
    }

    let trailing_partial = if !bytes.is_empty() && bytes.last().copied() != Some(b'\n') {
        1
    } else {
        0
    };
    let total_lines = cumulative + trailing_partial;

    Some((checkpoints, total_lines))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file_reader::detect_encoding;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_line_indexer_small_file() -> anyhow::Result<()> {
        let mut file = NamedTempFile::new()?;
        write!(file, "Line 1\nLine 2\nLine 3")?;
        let path = file.path().to_path_buf();

        let reader = FileReader::new(path, detect_encoding(b""))?;
        let mut indexer = LineIndexer::new();
        indexer.index_file(&reader);

        assert_eq!(indexer.total_lines, 3);
        assert_eq!(indexer.line_offsets, vec![0, 7, 14]);
        Ok(())
    }

    #[test]
    fn test_line_indexer_empty_lines() -> anyhow::Result<()> {
        let mut file = NamedTempFile::new()?;
        write!(file, "\n\n\n")?;
        let path = file.path().to_path_buf();

        let reader = FileReader::new(path, detect_encoding(b""))?;
        let mut indexer = LineIndexer::new();
        indexer.index_file(&reader);

        assert_eq!(indexer.total_lines, 4);
        assert_eq!(indexer.line_offsets, vec![0, 1, 2, 3]);
        Ok(())
    }

    /// Sanity-check the sparse path: line numbers must match what the full
    /// index would have produced, regardless of where the query lands.
    #[test]
    fn test_sparse_index_exact_line_numbers() -> anyhow::Result<()> {
        let mut file = NamedTempFile::new()?;
        let mut expected_offsets = vec![0usize];
        let mut total = 0usize;
        for i in 0..200_000u32 {
            let s = if i % 3 == 0 {
                format!("short-{}\n", i)
            } else if i % 3 == 1 {
                format!("medium-{}-ABCDEFGHIJKLMNOPQRSTUVWXYZ\n", i)
            } else {
                format!("long-{}-{}\n", i, "x".repeat(128))
            };
            file.write_all(s.as_bytes())?;
            total += s.len();
            expected_offsets.push(total);
        }
        expected_offsets.pop();
        let path = file.path().to_path_buf();
        let reader = FileReader::new(path, detect_encoding(b""))?;
        assert!(reader.len() > 10_000_000, "test file should hit sparse path");

        let mut indexer = LineIndexer::new();
        indexer.index_file(&reader);

        assert_eq!(indexer.sample_interval, 10_000_000);
        assert_eq!(indexer.total_lines, 200_000);
        assert!(indexer.exact_ready);

        for &line in &[0usize, 1, 63, 64, 65, 199_999, 12_345, 100_000] {
            let (start, end) = indexer
                .get_line_with_reader(line, &reader)
                .expect("line should resolve");
            assert_eq!(
                start, expected_offsets[line],
                "line {} start offset",
                line
            );
            assert!(end >= start);
            assert_eq!(
                indexer.find_line_at_offset(start, &reader),
                line,
                "find_line_at_offset for line {} start",
                line
            );
            if start + 1 < reader.len() {
                assert_eq!(
                    indexer.find_line_at_offset(start + 1, &reader),
                    line,
                    "find_line_at_offset one past start of line {}",
                    line
                );
            }
        }
        Ok(())
    }

    /// Async indexing path: after kicking off the scan, polling eventually
    /// flips `exact_ready` to true and the result matches the sync path.
    #[test]
    fn test_async_indexing_eventual_consistency() -> anyhow::Result<()> {
        let mut file = NamedTempFile::new()?;
        for i in 0..50_000u32 {
            writeln!(file, "line{:09}", i)?;
        }
        // Make sure the file is large enough to hit the sparse path.
        // 50k lines × ~14 bytes = 700k. Bump via padding.
        let padding = "Q".repeat(15_000_000);
        writeln!(file, "{}", padding)?;
        let path = file.path().to_path_buf();
        let reader = Arc::new(FileReader::new(path, detect_encoding(b""))?);

        let mut indexer = LineIndexer::new();
        indexer.index_file_async(reader.clone());
        assert!(indexer.is_indexing());
        // total_lines is the estimate pre-scan.
        assert!(indexer.total_lines > 0);

        // Poll until done (bounded wait).
        let start = std::time::Instant::now();
        while indexer.is_indexing() {
            if indexer.poll() {
                break;
            }
            if start.elapsed() > std::time::Duration::from_secs(10) {
                panic!("async index did not complete within 10s");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(indexer.exact_ready);

        // 50_000 lines + 1 trailing padding line.
        assert_eq!(indexer.total_lines, 50_001);
        // Line 0 starts at byte 0.
        let (s0, _) = indexer.get_line_with_reader(0, &reader).unwrap();
        assert_eq!(s0, 0);
        Ok(())
    }
}
