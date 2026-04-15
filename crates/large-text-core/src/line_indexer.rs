use crate::file_reader::FileReader;

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
        }
    }

    pub fn index_file(&mut self, reader: &FileReader) {
        self.line_offsets.clear();
        self.line_offsets.push(0);
        self.sparse_checkpoints.clear();
        self.file_size = reader.len();

        const FULL_INDEX_THRESHOLD: usize = 10_000_000; // 10 MB

        if self.file_size <= FULL_INDEX_THRESHOLD {
            let data = reader.all_data();
            self.full_index(data);
            self.sample_interval = 0;
            self.total_lines = self.line_offsets.len();
        } else {
            self.sparse_index(reader);
        }

        self.indexed = true;
    }

    fn full_index(&mut self, data: &[u8]) {
        for (i, &byte) in data.iter().enumerate() {
            if byte == b'\n' {
                self.line_offsets.push(i + 1);
            }
        }
    }

    /// Walk the whole file once, counting `\n` bytes and dropping a
    /// line-aligned checkpoint each time we cross an `SPARSE_CHECKPOINT_INTERVAL`
    /// byte boundary. This is an O(file_size) pass but runs at memory
    /// bandwidth on mmap'd bytes (≈0.5 s per GB), and the payoff is that
    /// every later query resolves to an **exact** line number — previously
    /// the sparse path only estimated, which made the UI's row numbers
    /// disagree with anything computed from byte offsets (e.g. taint start
    /// line vs. main view line label).
    fn sparse_index(&mut self, reader: &FileReader) {
        const SPARSE_CHECKPOINT_INTERVAL: usize = 10_000_000; // 10 MB
        self.sample_interval = SPARSE_CHECKPOINT_INTERVAL;

        let bytes = reader.all_data();
        // Line 0 starts at byte 0 — this one is free.
        self.sparse_checkpoints.push(SparseCheckpoint {
            byte_pos: 0,
            line_index: 0,
        });

        let mut cumulative_lines: usize = 0;
        let mut last_cp_byte: usize = 0;

        for (i, &b) in bytes.iter().enumerate() {
            if b == b'\n' {
                cumulative_lines += 1;
                let next_line_start = i + 1;
                // Drop a checkpoint at the *next* line start whenever we've
                // advanced at least one interval past the previous one.
                // Aligning to line starts (rather than to raw 10 MB
                // boundaries) simplifies the query logic: every checkpoint
                // invariantly names a real line.
                if next_line_start >= last_cp_byte + SPARSE_CHECKPOINT_INTERVAL
                    && next_line_start < bytes.len()
                {
                    self.sparse_checkpoints.push(SparseCheckpoint {
                        byte_pos: next_line_start,
                        line_index: cumulative_lines,
                    });
                    last_cp_byte = next_line_start;
                }
            }
        }

        // If the file doesn't end with a newline, the trailing bytes after
        // the last `\n` still form a (partial) line visible to the user.
        let trailing_partial =
            if !bytes.is_empty() && bytes.last().copied() != Some(b'\n') {
                1
            } else {
                0
            };
        self.total_lines = cumulative_lines + trailing_partial;

        if cumulative_lines > 0 {
            self.avg_line_length = self.file_size as f64 / cumulative_lines as f64;
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
            // Sparse mode can't answer without reader access. Callers that
            // actually need an exact byte range should use
            // `get_line_with_reader` instead. Keep the old best-effort
            // estimate here only so legacy callers don't silently panic.
            let est = (line_num as f64 * self.avg_line_length) as usize;
            Some((est, usize::MAX))
        }
    }

    /// Resolve `line_num` (0-based) to its exact `[start, end)` byte range.
    /// In sparse mode this scans at most one checkpoint's worth of bytes
    /// from the nearest checkpoint, giving an **exact** answer — identical
    /// to what the full-index path would have returned if the file had been
    /// fully indexed.
    pub fn get_line_with_reader(
        &self,
        line_num: usize,
        reader: &FileReader,
    ) -> Option<(usize, usize)> {
        if self.sample_interval == 0 {
            return self.get_line_range(line_num);
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

        // Scan window: the next checkpoint is ≤ (interval + 1 long line)
        // away from cp, so reading 1.5 × interval reliably contains both
        // the line's start and end even if the surrounding lines are
        // unusually long. Clamped to file_size.
        let scan_end = (cp.byte_pos + self.sample_interval * 3 / 2)
            .min(self.file_size);
        if cp.byte_pos >= scan_end && to_skip == 0 {
            // Zero-length file tail: line exists (e.g. empty last line) but
            // has no bytes.
            return Some((cp.byte_pos, cp.byte_pos));
        }
        let chunk = reader.get_bytes(cp.byte_pos, scan_end);

        let line_start = if to_skip == 0 {
            cp.byte_pos
        } else {
            // Advance past `to_skip` newlines starting at cp.byte_pos.
            let mut seen = 0usize;
            let mut start: Option<usize> = None;
            for (i, &b) in chunk.iter().enumerate() {
                if b == b'\n' {
                    seen += 1;
                    if seen == to_skip {
                        start = Some(cp.byte_pos + i + 1);
                        break;
                    }
                }
            }
            start?
        };

        // Find the terminating '\n' for `line_num` (or EOF).
        let rel_start = line_start - cp.byte_pos;
        let line_end = chunk
            .get(rel_start..)
            .and_then(|tail| tail.iter().position(|&b| b == b'\n'))
            .map(|p| line_start + p)
            .unwrap_or_else(|| {
                // Line end wasn't within the scan window — fall back to a
                // dedicated scan of up to one more interval.
                let extra_end =
                    (line_start + self.sample_interval).min(self.file_size);
                let extra = reader.get_bytes(line_start, extra_end);
                extra
                    .iter()
                    .position(|&b| b == b'\n')
                    .map(|p| line_start + p)
                    .unwrap_or(extra_end)
            });

        Some((line_start, line_end))
    }

    /// Inverse of `get_line_with_reader`: byte offset → 0-based line number.
    /// Sparse mode scans at most one checkpoint interval to count '\n'
    /// bytes from the nearest checkpoint up to `offset`.
    pub fn find_line_at_offset(&self, offset: usize, reader: &FileReader) -> usize {
        if self.sample_interval == 0 {
            return match self.line_offsets.binary_search(&offset) {
                Ok(line) => line,
                Err(line) => line.saturating_sub(1),
            };
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
        let newlines = bytecount_newlines(bytes);
        cp.line_index + newlines
    }

    pub fn total_lines(&self) -> usize {
        self.total_lines
    }
}

#[inline]
fn bytecount_newlines(bytes: &[u8]) -> usize {
    bytes.iter().filter(|&&b| b == b'\n').count()
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
        // Generate a file large enough to trigger the sparse threshold
        // (> 10 MB) with lines of varying length so the answer can't be
        // faked by `offset / avg_line_length`.
        let mut file = NamedTempFile::new()?;
        let mut expected_offsets = vec![0usize];
        let mut total = 0usize;
        for i in 0..200_000u32 {
            // Alternate short and long lines so avg_line_length differs
            // from any single line's length.
            let s = if i % 3 == 0 {
                format!("short-{}\n", i)
            } else if i % 3 == 1 {
                format!("medium-{}-ABCDEFGHIJKLMNOPQRSTUVWXYZ\n", i)
            } else {
                format!(
                    "long-{}-{}\n",
                    i,
                    "x".repeat(128),
                )
            };
            file.write_all(s.as_bytes())?;
            total += s.len();
            expected_offsets.push(total);
        }
        // Strip the final phantom entry; that offset is `file_size` and
        // there is no line starting there (file ends with `\n`).
        expected_offsets.pop();
        let path = file.path().to_path_buf();
        let reader = FileReader::new(path, detect_encoding(b""))?;
        assert!(reader.len() > 10_000_000, "test file should hit sparse path");

        let mut indexer = LineIndexer::new();
        indexer.index_file(&reader);

        assert_eq!(indexer.sample_interval, 10_000_000);
        assert_eq!(indexer.total_lines, 200_000);

        // Probe a scattered set of lines. Every one must round-trip
        // exactly through (line → offset → line).
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
}
