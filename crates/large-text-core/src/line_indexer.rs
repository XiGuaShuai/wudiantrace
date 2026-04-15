use crate::file_reader::FileReader;
use memchr::memchr_iter;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver};
use std::sync::Arc;
use std::thread;

/// 大文件稀疏索引里的一个 checkpoint。
///
/// **不变式**:`byte_pos` 必须是某一行的**起点**(等于 0,或紧跟在某个
/// `\n` 之后)。`line_index` 是该行在整个文件中的 0-based 行号。只要
/// checkpoint 都落在行边界上,查询时从最近的 checkpoint 扫至多一个
/// interval 的字节就能精确回答"字节 offset ↔ 行号"的映射 —— 这是
/// "主视图行号"和"污点面板行号"能对齐的关键(历史上出现过稀疏模式
/// 下两边行号差几十行的 bug)。
#[derive(Clone, Copy, Debug)]
struct SparseCheckpoint {
    byte_pos: usize,
    line_index: usize,
}

/// 后台扫描 worker 回传给主线程的消息。
///
/// 两阶段推送:
/// - `Seed`:10MB 采样结束后立刻发,把估算从"file_size / 80 的粗估"
///   升级到"根据本文件真实行密度估算"。用于让 UI 首帧响应后的短时间
///   内(全扫还没结束时)行数/滚动位置看起来更合理。
/// - `Exact`:整个文件扫完后发,带完整的 checkpoint 列表和精确行数。
///   主线程此时切到精确查询模式(`exact_ready = true`)。
///
/// 之前同步做 Seed 采样时,冷磁盘上第一次 touch 10MB 会触发 page
/// fault(SATA SSD ~300ms,HDD ~1s),拖放 50GB 文件会卡一下才加载。
/// 把 Seed 也挪到后台线程后,主线程从 `index_file_async` 返回 <1ms。
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

/// 正在跑的后台扫描句柄。LineIndexer 被 drop 或开启新扫描时,把
/// `cancel` 置 true,worker 线程在下一次 cancel 检查时退出。
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

    /// 同步建索引。函数返回时"精确行号"已就绪,后续查询直接拿精确
    /// 结果。适合小文件和测试用;GUI 里要用 `index_file_async`,否则
    /// 几 GB 文件会把主线程卡住几秒。
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

    /// 非阻塞建索引。函数立刻返回(仅设置一个 file_size/80 的粗估
    /// `avg_line_length`),真正的 10MB 采样和全文件 `\n` 扫描都在
    /// 后台线程里做。主线程每帧调 `poll()` 吃消息把结果合进来。
    ///
    /// 索引未完成时,查询走 `avg_line_length` 估算路径 —— 够用于滚动
    /// 和粗略行号展示。一旦 `Exact` 消息到达,需要精确数字的场景
    /// (污点命中跳转行号、Go-To-Line 定位、搜索结果行号)自动切到
    /// 精确模式,无需调用方介入。
    ///
    /// 之所以把 10MB 采样也放到后台:冷磁盘首次 touch 10MB 会触发
    /// page fault,SATA SSD 约 300ms / HDD 约 1s,拖放 50GB 文件
    /// 主线程会卡一下"白一下"才渲染。放后台后主线程 <1ms 返回。
    pub fn index_file_async(&mut self, reader: Arc<FileReader>) {
        self.abort_pending();
        self.reset_for_new_file(reader.len());

        const FULL_INDEX_THRESHOLD: usize = 10_000_000;

        if self.file_size <= FULL_INDEX_THRESHOLD {
            // 小文件直接同步建全量索引:≤10MB 的 memchr 扫 \n 几毫秒
            // 就完事了,起个 worker 线程的开销反而更大。
            self.full_index(reader.all_data());
            self.sample_interval = 0;
            self.total_lines = self.line_offsets.len();
            self.indexed = true;
            return;
        }

        self.sample_interval = SPARSE_CHECKPOINT_INTERVAL;
        // 把能立刻设的最粗估算先设上,让 UI 这一帧就有"行数""avg"等
        // 字段可用(哪怕不准)。常见 ASCII 日志行 ~80 字节,file_size/80
        // 作为数量级对了就行。几百毫秒后 Seed 消息到达会刷新为实测的
        // 10MB 平均值;几秒后 Exact 消息到达再替换为精确总行数。
        self.avg_line_length = 80.0;
        self.total_lines = self.file_size / 80;

        let (tx, rx) = channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let cancel_for_worker = cancel.clone();
        let reader_for_worker = reader;

        thread::spawn(move || {
            // Phase 1:10MB 采样得到真实 avg_line_length。
            // 冷磁盘下这 10MB 首次 touch 会 page fault 从磁盘读,
            // SATA SSD ~300ms,HDD 能到 1s。放后台线程做,主线程
            // 的"拖放响应"就不会被这段 I/O 卡住。
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

            // Phase 2:全量扫 → 精确 checkpoints + 总行数。
            if let Some((checkpoints, total_lines)) =
                sparse_scan_for_exact_index(bytes_all, SPARSE_CHECKPOINT_INTERVAL, &cancel_for_worker)
            {
                // 接收端被 drop(换文件 / 退出 app)时 send 会 Err,
                // 无声忽略即可 —— 对端不再关心结果。
                let _ = tx.send(IndexMsg::Exact {
                    checkpoints,
                    total_lines,
                });
            }
        });

        self.pending = Some(PendingExactIndex { rx, cancel });
        self.indexed = true; // 估算值本帧已可用
    }

    /// 推进后台异步索引。当"最终精确结果"(Exact 消息)本次调用落地时
    /// 返回 `true`,调用方可据此触发 UI 重绘 / 缓存失效。中间的 Seed
    /// 消息只是 refine 估算,不翻 `exact_ready`,返回 `false`。
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
                    // Seed 阶段只刷估算:用户看到行数从"file_size/80
                    // 粗估"→"本文件真实行密度估算"→(Exact 到达后)
                    // "精确行数" 三段收敛。
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
                    // Worker 退出了(cancelled / panic / 已发完消息
                    // 并 drop sender)。清掉 pending 让后续查询别等了。
                    self.pending = None;
                    break;
                }
            }
        }
        exact_landed
    }

    /// 后台精确索引还没 ready 就返回 true。UI 可据此显示"建索引中"
    /// 提示 + `~N` 前缀标识总行数是估算值。
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
        // memchr 的 SIMD(AVX2 / SSE2)扫描比 `iter().filter` 裸循环
        // 快 5-10 倍。即便是 ≤10MB 的全量索引路径也受益。
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

    /// 把 0-based 的 `line_num` 解析到它精确的 `[start, end)` 字节区间。
    /// 稀疏模式下 exact_ready 前走估算路径,到达后走 checkpoint 扫描
    /// 路径(精确)。
    ///
    /// 精确路径是解决"主视图行号和污点面板行号对不齐"的关键:主视图
    /// 拿行号查字节,污点面板拿字节查行号,两侧都走精确路径才能对上。
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
            // 精确索引还没到,退化到估算:offset / avg_line_length。
            // 在多 GB 文件靠近末尾的位置会偏几十行,但仅作 UI 状态
            // 占位用,Exact 到达后会自动切回精确路径。
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

/// 把整个文件走一遍,用 memchr(SIMD)数 `\n`,每跨过一个
/// `interval` 字节边界就在下一个行起点落一个 checkpoint。总体 O(file_size)
/// 内存带宽,几乎不分配堆。每数满 2^20 个 `\n` 检查一次 cancel 标志,
/// 换文件时上一次扫描能及时退出。
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
