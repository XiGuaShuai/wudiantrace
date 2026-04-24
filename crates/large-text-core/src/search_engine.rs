use crate::file_reader::FileReader;
use regex::Regex;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    mpsc::SyncSender,
    Arc,
};
use std::thread;

pub struct SearchEngine {
    query: String,
    use_regex: bool,
    case_sensitive: bool,
    regex: Option<Regex>,
    results: Vec<SearchResult>,
    total_results: usize,
}

#[derive(Clone, Debug)]
pub struct SearchResult {
    pub byte_offset: usize,
    pub match_len: usize,
}

pub struct ChunkSearchResult {
    pub matches: Vec<SearchResult>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SearchType {
    Count,
    Fetch,
}

pub enum SearchMessage {
    ChunkResult(ChunkSearchResult),
    CountResult(usize),
    Done(SearchType),
    Error(String),
}

impl Default for SearchEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl SearchEngine {
    pub fn new() -> Self {
        Self {
            query: String::new(),
            use_regex: false,
            case_sensitive: false,
            regex: None,
            results: Vec::new(),
            total_results: 0,
        }
    }

    pub fn set_query(&mut self, query: String, use_regex: bool, case_sensitive: bool) {
        self.query = query;
        self.use_regex = use_regex;
        self.case_sensitive = case_sensitive;

        let pattern = if use_regex {
            if !case_sensitive {
                format!("(?i){}", self.query)
            } else {
                self.query.clone()
            }
        } else if !case_sensitive {
            format!("(?i){}", regex::escape(&self.query))
        } else {
            regex::escape(&self.query)
        };

        self.regex = Regex::new(&pattern).ok();

        self.results.clear();
    }

    pub fn find_in_text(&self, text: &str) -> Vec<(usize, usize)> {
        let mut matches = Vec::new();
        if self.query.is_empty() {
            return matches;
        }

        if let Some(re) = &self.regex {
            for m in re.find_iter(text) {
                matches.push((m.start(), m.end()));
            }
        }
        matches
    }

    pub fn count_matches(
        &self,
        reader: Arc<FileReader>,
        tx: SyncSender<SearchMessage>,
        cancel_token: Arc<AtomicBool>,
    ) {
        let file_len = reader.len();
        if file_len == 0 || self.query.is_empty() {
            let _ = tx.send(SearchMessage::CountResult(0));
            let _ = tx.send(SearchMessage::Done(SearchType::Count));
            return;
        }

        let num_threads = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .max(1);

        let chunk_size = file_len.div_ceil(num_threads);
        let query_len = self.query.len();
        let overlap = query_len.saturating_sub(1).max(1000);

        let regex = self.regex.clone();

        thread::spawn(move || {
            let mut handles = vec![];

            for i in 0..num_threads {
                let thread_start = i * chunk_size;
                if thread_start >= file_len {
                    break;
                }
                let thread_end = (thread_start + chunk_size).min(file_len);

                let reader_clone = reader.clone();
                let tx_clone = tx.clone();
                let regex_clone = regex.clone();
                let cancel_token_clone = cancel_token.clone();

                let handle = thread::spawn(move || {
                    if let Some(regex) = regex_clone {
                        let mut pos = thread_start;
                        // Process in smaller batches to keep per-thread memory bounded.
                        // Bigger batch = fewer loop iterations, fewer cancel-token
                        // checks, better regex warm-up. For mmap backing there is
                        // no extra cost to reading a larger slice.
                        const BATCH_SIZE: usize = 16 * 1024 * 1024; // 16MB
                        let mut local_count: usize = 0;

                        while pos < thread_end {
                            if cancel_token_clone.load(Ordering::Relaxed) {
                                return;
                            }

                            let batch_end = (pos + BATCH_SIZE).min(thread_end);
                            let read_end = (batch_end + overlap).min(file_len);
                            let chunk_bytes = reader_clone.get_bytes(pos, read_end);

                            // Borrow directly when the slice is valid UTF-8 (the
                            // common case for ASCII traces) — zero allocation,
                            // zero memcpy. Only pay decode cost when the file
                            // really isn't UTF-8.
                            let chunk_text: std::borrow::Cow<str> =
                                match std::str::from_utf8(chunk_bytes) {
                                    Ok(t) => std::borrow::Cow::Borrowed(t),
                                    Err(_) => {
                                        let (cow, _, _) =
                                            reader_clone.encoding().decode(chunk_bytes);
                                        cow
                                    }
                                };

                            let relative_batch_end = batch_end - pos;
                            for mat in regex.find_iter(&chunk_text) {
                                let match_start = mat.start();
                                // Drop matches that start inside the overlap region —
                                // the next batch is responsible for them.
                                if match_start >= relative_batch_end {
                                    continue;
                                }
                                local_count += 1;
                            }

                            pos = batch_end;
                        }
                        let _ = tx_clone.send(SearchMessage::CountResult(local_count));
                    } else {
                        let _ = tx_clone.send(SearchMessage::Error("Invalid regex".to_string()));
                    }
                });
                handles.push(handle);
            }

            for h in handles {
                let _ = h.join();
            }
            if !cancel_token.load(Ordering::Relaxed) {
                let _ = tx.send(SearchMessage::Done(SearchType::Count));
            }
        });
    }

    pub fn fetch_matches(
        &self,
        reader: Arc<FileReader>,
        tx: SyncSender<SearchMessage>,
        start_offset: usize,
        max_results: usize,
        cancel_token: Arc<AtomicBool>,
    ) {
        let file_len = reader.len();
        if file_len == 0 || self.query.is_empty() {
            let _ = tx.send(SearchMessage::Done(SearchType::Fetch));
            return;
        }

        let regex = self.regex.clone();
        let query_len = self.query.len();
        let overlap = query_len.saturating_sub(1).max(1000);

        thread::spawn(move || {
            if let Some(regex) = regex {
                // Bigger chunk = fewer allocations of local match vectors and
                // fewer overlap re-scans. mmap makes large slices free.
                const CHUNK_SIZE: usize = 32 * 1024 * 1024; // 32 MB
                let mut chunk_start = start_offset;
                let mut results_found = 0;

                while chunk_start < file_len && results_found < max_results {
                    if cancel_token.load(Ordering::Relaxed) {
                        return;
                    }

                    let chunk_end = (chunk_start + CHUNK_SIZE).min(file_len);
                    let chunk_bytes = reader.get_bytes(chunk_start, chunk_end);

                    // Zero-copy UTF-8 path for the common case.
                    let chunk_text: std::borrow::Cow<str> = match std::str::from_utf8(chunk_bytes) {
                        Ok(t) => std::borrow::Cow::Borrowed(t),
                        Err(_) => {
                            let (cow, _, _) = reader.encoding().decode(chunk_bytes);
                            cow
                        }
                    };

                    let valid_end = if chunk_end >= file_len {
                        file_len
                    } else {
                        chunk_end - overlap
                    };
                    let relative_valid_end = valid_end - chunk_start;
                    // Pre-size: most result sets yield ~hundreds of matches per
                    // 32 MB; avoids multiple reallocs.
                    let mut local_matches = Vec::with_capacity(256);

                    for mat in regex.find_iter(&chunk_text) {
                        if results_found >= max_results {
                            break;
                        }
                        let match_start = mat.start();
                        if match_start >= relative_valid_end {
                            continue;
                        }
                        local_matches.push(SearchResult {
                            byte_offset: chunk_start + match_start,
                            match_len: mat.end() - mat.start(),
                        });
                        results_found += 1;
                    }

                    if !local_matches.is_empty()
                        && tx
                            .send(SearchMessage::ChunkResult(ChunkSearchResult {
                                matches: local_matches,
                            }))
                            .is_err()
                    {
                        return;
                    }

                    if chunk_end >= file_len {
                        break;
                    }
                    chunk_start = chunk_end - overlap;
                }
                if !cancel_token.load(Ordering::Relaxed) {
                    let _ = tx.send(SearchMessage::Done(SearchType::Fetch));
                }
            } else {
                let _ = tx.send(SearchMessage::Error("Invalid regex".to_string()));
            }
        });
    }

    /// Find All 的单次并行扫:在同一次遍历里**同时**计数和收集命中位置。
    /// 替换掉老的双 pass 流程(`count_matches` 并行数 → `fetch_matches`
    /// 串行收位置),老流程字节读了两遍,而且收集位置那半还是单线程。
    ///
    /// 每个 worker 扫自己那段字节:
    /// * 把本地命中收进 Vec,受本线程配额限制(`max_results / 线程数`)
    /// * 始终对**所有**命中计数(不管收不收),保证全局 count 精确
    /// * 随时往 UI 发 `ChunkResult`(位置)和 `CountResult`(本段计数)
    ///
    /// UI 侧每帧对 `search_results` 做 `sort_by_key(byte_offset)`(原本
    /// 就有这个逻辑),所以最终展示顺序和老的串行 fetch 完全一致 ——
    /// 只是快 N 倍(多核 I/O 并发,不再是单线程从 byte 0 线性走到尾)。
    ///
    /// **权衡**:病态查询(命中数远超 `max_results`)情况下,展示的前
    /// `max_results` 条是"**大致**前 N 条" —— 每个 chunk 内部是精确
    /// 排序的,但如果某个 chunk 命中超过本地配额,后面 chunk 的命中
    /// 可能"插队"进来。全局 count 始终精确。常见场景(几十~几千命中
    /// 稀疏分布)显示结果与串行完全一致。
    pub fn find_all_parallel(
        &self,
        reader: Arc<FileReader>,
        tx: SyncSender<SearchMessage>,
        max_results: usize,
        cancel_token: Arc<AtomicBool>,
    ) {
        let file_len = reader.len();
        if file_len == 0 || self.query.is_empty() {
            let _ = tx.send(SearchMessage::CountResult(0));
            let _ = tx.send(SearchMessage::Done(SearchType::Fetch));
            return;
        }

        let num_threads = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .max(1);
        let chunk_size = file_len.div_ceil(num_threads);
        let query_len = self.query.len();
        let overlap = query_len.saturating_sub(1).max(1000);
        let regex = self.regex.clone();
        // One extra "safety slot" per thread keeps the displayed set
        // roughly in-order for moderate result counts while keeping peak
        // memory bounded.
        let per_thread_cap = max_results.div_ceil(num_threads).max(128);
        // Shared stop-condition: once the global collected-positions count
        // exceeds `max_results`, later threads can stop collecting (but
        // keep counting for the exact total).
        let global_collected = Arc::new(AtomicUsize::new(0));

        thread::spawn(move || {
            let mut handles = vec![];
            for i in 0..num_threads {
                let thread_start = i * chunk_size;
                if thread_start >= file_len {
                    break;
                }
                let thread_end = (thread_start + chunk_size).min(file_len);

                let reader_clone = reader.clone();
                let tx_clone = tx.clone();
                let regex_clone = regex.clone();
                let cancel_clone = cancel_token.clone();
                let global_collected_clone = global_collected.clone();

                let handle = thread::spawn(move || {
                    let Some(regex) = regex_clone else {
                        let _ = tx_clone.send(SearchMessage::Error("Invalid regex".to_string()));
                        return;
                    };
                    const BATCH_SIZE: usize = 16 * 1024 * 1024;
                    let mut pos = thread_start;
                    let mut local_count: usize = 0;
                    let mut local_matches: Vec<SearchResult> =
                        Vec::with_capacity(per_thread_cap.min(1024));

                    while pos < thread_end {
                        if cancel_clone.load(Ordering::Relaxed) {
                            return;
                        }
                        let batch_end = (pos + BATCH_SIZE).min(thread_end);
                        let read_end = (batch_end + overlap).min(file_len);
                        let chunk_bytes = reader_clone.get_bytes(pos, read_end);
                        let chunk_text: std::borrow::Cow<str> =
                            match std::str::from_utf8(chunk_bytes) {
                                Ok(t) => std::borrow::Cow::Borrowed(t),
                                Err(_) => {
                                    let (cow, _, _) = reader_clone.encoding().decode(chunk_bytes);
                                    cow
                                }
                            };
                        let relative_batch_end = batch_end - pos;

                        for mat in regex.find_iter(&chunk_text) {
                            let match_start = mat.start();
                            if match_start >= relative_batch_end {
                                continue;
                            }
                            local_count += 1;
                            // Collect when local_matches still has room
                            // *and* the global quota isn't full yet.
                            if local_matches.len() < per_thread_cap
                                && global_collected_clone.load(Ordering::Relaxed) < max_results
                            {
                                local_matches.push(SearchResult {
                                    byte_offset: pos + match_start,
                                    match_len: mat.end() - mat.start(),
                                });
                                global_collected_clone.fetch_add(1, Ordering::Relaxed);
                            }
                        }

                        // 本线程本地槽满 + 全局配额满,继续扫只数不
                        // 收 —— 省得占额外内存。全局 count 仍然精确,
                        // 因为上面的 `local_count += 1` 不受配额限制。
                        if local_matches.len() >= per_thread_cap
                            && global_collected_clone.load(Ordering::Relaxed) >= max_results
                        {
                            // 继续扫,不再 push 到 local_matches。
                        }

                        pos = batch_end;
                    }

                    if !local_matches.is_empty() {
                        let _ = tx_clone.send(SearchMessage::ChunkResult(ChunkSearchResult {
                            matches: local_matches,
                        }));
                    }
                    let _ = tx_clone.send(SearchMessage::CountResult(local_count));
                });
                handles.push(handle);
            }

            for h in handles {
                let _ = h.join();
            }
            if !cancel_token.load(Ordering::Relaxed) {
                let _ = tx.send(SearchMessage::Done(SearchType::Fetch));
            }
        });
    }

    pub fn clear(&mut self) {
        self.query.clear();
        self.results.clear();
        self.regex = None;
        self.total_results = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file_reader::detect_encoding;
    use std::io::Write;
    use std::sync::mpsc;
    use tempfile::NamedTempFile;

    #[test]
    fn test_find_in_text() {
        let mut engine = SearchEngine::new();
        engine.set_query("test".to_string(), false, false);

        let text = "This is a test string. Another test.";
        let matches = engine.find_in_text(text);
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0], (10, 14));
        assert_eq!(matches[1], (31, 35));
    }

    #[test]
    fn test_find_in_text_regex() {
        let mut engine = SearchEngine::new();
        engine.set_query(r"\d+".to_string(), true, false);

        let text = "There are 123 apples and 456 oranges.";
        let matches = engine.find_in_text(text);
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0], (10, 13)); // "123"
        assert_eq!(matches[1], (25, 28)); // "456"
    }

    #[test]
    fn test_count_matches() -> anyhow::Result<()> {
        let mut file = NamedTempFile::new()?;
        write!(file, "test\ntest\ntest")?;
        let path = file.path().to_path_buf();

        let reader = Arc::new(FileReader::new(path, detect_encoding(b""))?);
        let mut engine = SearchEngine::new();
        engine.set_query("test".to_string(), false, false);

        let (tx, rx) = mpsc::sync_channel(10);
        let cancel_token = Arc::new(AtomicBool::new(false));

        engine.count_matches(reader, tx, cancel_token);

        let mut count = 0;
        loop {
            match rx.recv() {
                Ok(SearchMessage::CountResult(c)) => count += c,
                Ok(SearchMessage::Done(SearchType::Count)) => break,
                Ok(SearchMessage::Error(e)) => panic!("Error: {}", e),
                Ok(_) => continue,
                Err(_) => break,
            }
        }

        assert_eq!(count, 3);
        Ok(())
    }
}
