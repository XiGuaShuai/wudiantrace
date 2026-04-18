use eframe::egui;
use encoding_rs::Encoding;
use notify::{RecursiveMode, Result as NotifyResult, Watcher};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use large_text_core::file_reader::{available_encodings, detect_encoding, FileReader};
use large_text_core::line_indexer::LineIndexer;
use large_text_core::replacer::{ReplaceMessage, Replacer};
use large_text_core::search_engine::{SearchEngine, SearchMessage, SearchResult, SearchType};

use crate::taint::TaintState;

pub struct TextViewerApp {
    file_reader: Option<Arc<FileReader>>,
    line_indexer: LineIndexer,
    search_engine: SearchEngine,

    // UI State
    scroll_line: usize,
    visible_lines: usize,
    font_size: f32,
    wrap_mode: bool,
    dark_mode: bool,
    show_line_numbers: bool,

    // Search UI
    search_query: String,
    replace_query: String,
    show_search_bar: bool,
    show_replace: bool,
    use_regex: bool,
    case_sensitive: bool,
    search_results: Vec<SearchResult>,
    current_result_index: usize, // Global index (0 to total_results - 1)
    total_search_results: usize,
    search_page_start_index: usize, // Global index of the first result in search_results
    page_offsets: Vec<usize>,       // Map of page_index -> start_byte_offset
    search_error: Option<String>,
    search_in_progress: bool,
    search_find_all: bool,
    search_message_rx: Option<Receiver<SearchMessage>>,
    search_cancellation_token: Option<Arc<AtomicBool>>,
    search_count_done: bool,
    search_fetch_done: bool,
    /// 本次搜索是否已经把视口自动跳转到第一条命中过了。
    /// 并行 Find All 的 ChunkResult 是乱序到达的,如果每次
    /// `search_results` 更新都触发自动跳转,视口会在文件不同
    /// 位置之间来回跳。用这个 flag 保证只跳一次。
    search_first_jump_done: bool,

    // Replace UI
    replace_in_progress: bool,
    replace_message_rx: Option<Receiver<ReplaceMessage>>,
    replace_cancellation_token: Option<Arc<AtomicBool>>,
    replace_progress: Option<f32>,
    replace_status_message: Option<String>,

    // Go to line
    goto_line_input: String,

    // File info
    show_file_info: bool,

    // Tail mode
    tail_mode: bool,
    watcher: Option<Box<dyn Watcher>>,
    file_change_rx: Option<Receiver<()>>,

    // Status messages
    status_message: String,

    // Encoding
    selected_encoding: &'static Encoding,
    show_encoding_selector: bool,

    // —— 滚动模型:`scroll_line` 是权威"视口顶行",整数驱动 ——
    //
    // egui 的 ScrollArea 内部用 f32 存 offset,在多 GB 字节位置上精度
    // 只剩 ~30 行/quantum。滚轮小量 delta 会被 f32 直接吃掉,滚几格
    // 不动然后突然跳一下 —— 就是"滚动不流畅"的根因。
    //
    // 这里把"滚到哪行"的真相攥在我们手里:每帧主动拦 smooth_scroll_delta,
    // 按 line_height 换算成整数行更新 `scroll_line`,然后强制
    // ScrollArea 的 vertical_scroll_offset 为 `scroll_line * line_height`。
    // ScrollArea 只是反映我们的选择,精度由我们控制,滚轮每格 N 行
    // 稳定一致。
    /// 下一帧要跳到的顶行号。`scroll_to_row_centered` / `open_file` 等
    /// "程序化跳转"路径写这里,`render_text_area` 开头 take 掉并覆盖
    /// `scroll_line`。
    scroll_to_row: Option<usize>,
    /// 亚整数行的滚轮像素累积。满一行(= `line_height`)就进位到
    /// `scroll_line`,不满留着等下次滚轮凑够。这样连续慢滚不丢精度。
    wheel_accum: f32,

    // Focus control
    focus_search_input: bool,

    // Unsaved changes
    unsaved_changes: bool,
    pending_replacements: Vec<PendingReplacement>,

    // Performance measurement
    open_start_time: Option<std::time::Instant>,
    search_count_start_time: Option<std::time::Instant>,

    // Taint tracking
    pub(crate) taint: TaintState,

    // Occurrence highlight (double-click a word → highlight all same words)
    occurrence_word: Option<String>,

    // Search results list panel (010-Editor-style)
    show_search_list: bool,
    search_list_dock: crate::taint::DockSide,
    /// 每页的预览字符串缓存。搜索结果面板里每行显示一个 160 字节的
    /// 预览 + UTF-8 解码,不缓存的话每帧要对每行重算一次,可见行一多
    /// 帧率明显下降。按"页索引 + 查询词"做 cache key,翻页 / 改 query
    /// 时清掉,不变则沿用。
    search_preview_cache: HashMap<usize, String>,
    /// 同一逻辑适用于"行号"列:`LineIndexer::find_line_at_offset` 在
    /// 稀疏模式下每次最多要扫一个 checkpoint interval(~10MB),可见
    /// 行一多就把主线程塞住 —— 之前踩过一次大坑:搜索结果列表每帧
    /// 对每行调一次,导致 Ctrl+F 搜索框收不到键盘事件(IME 路由被
    /// 卡住)。缓存进来后热路径 O(1)。
    search_line_cache: HashMap<usize, usize>,
    /// 上面两个 cache 共用的 key:`(page_start_index, page_len, query)`。
    /// 三者任一变了就整页清空重建。
    search_preview_cache_key: Option<(usize, usize, String)>,
}

#[derive(Clone)]
struct PendingReplacement {
    offset: usize,
    old_len: usize,
    new_text: String,
}

impl Default for TextViewerApp {
    fn default() -> Self {
        Self {
            file_reader: None,
            line_indexer: LineIndexer::new(),
            search_engine: SearchEngine::new(),
            scroll_line: 0,
            visible_lines: 50,
            font_size: 14.0,
            wrap_mode: false,
            dark_mode: true,
            show_line_numbers: true,
            search_query: String::new(),
            replace_query: String::new(),
            show_search_bar: false,
            show_replace: false,
            use_regex: false,
            case_sensitive: false,
            search_results: Vec::new(),
            current_result_index: 0,
            total_search_results: 0,
            search_page_start_index: 0,
            page_offsets: Vec::new(),
            search_error: None,
            search_in_progress: false,
            search_find_all: true,
            search_message_rx: None,
            search_cancellation_token: None,
            search_count_done: false,
            search_fetch_done: false,
            search_first_jump_done: false,
            replace_in_progress: false,
            replace_message_rx: None,
            replace_cancellation_token: None,
            replace_progress: None,
            replace_status_message: None,
            goto_line_input: String::new(),
            show_file_info: false,
            tail_mode: false,
            watcher: None,
            file_change_rx: None,
            status_message: String::new(),
            selected_encoding: encoding_rs::UTF_8,
            show_encoding_selector: false,
            focus_search_input: false,
            scroll_to_row: None,
            wheel_accum: 0.0,
            unsaved_changes: false,
            pending_replacements: Vec::new(),
            open_start_time: None,
            search_count_start_time: None,
            taint: TaintState::default(),
            occurrence_word: None,
            show_search_list: true,
            search_list_dock: crate::taint::DockSide::Bottom,
            search_preview_cache: HashMap::new(),
            search_line_cache: HashMap::new(),
            search_preview_cache_key: None,
        }
    }
}

impl TextViewerApp {
    /// Sniff the first 4 KB for BOM/UTF-8 to pick an encoding, then load the
    /// file via `open_file`. Used by both the File > Open dialog and the
    /// drag-and-drop handler.
    fn load_file_with_auto_encoding(&mut self, path: PathBuf) {
        if let Ok(mut file) = std::fs::File::open(&path) {
            let mut buffer = [0u8; 4096];
            if let Ok(n) = std::io::Read::read(&mut file, &mut buffer) {
                self.selected_encoding = detect_encoding(&buffer[..n]);
            }
        }
        self.open_file(path);
    }

    /// 稀疏索引版本的"字节 offset → 行号"快捷调用。
    ///
    /// 底层稀疏路径要用原始字节从最近 checkpoint 扫到目标 offset 数
    /// `\n`,所以必须带 `&FileReader`。任何处理字节 offset 的代码路径
    /// (搜索跳转、污点面板双击跳转、Go-To-Line 等)都是在"已有文件"
    /// 的前提下触发的,所以下面的 `expect` 是前提条件而不是猜测。
    fn line_at(&self, offset: usize) -> usize {
        let reader = self
            .file_reader
            .as_ref()
            .expect("file must be loaded before resolving a line number");
        self.line_indexer.find_line_at_offset(offset, reader)
    }

    /// 程序化滚动跳转,让 `target_row` 落到视口纵向**中部**而不是顶部。
    /// 搜索命中 / 污点命中 / Go-To-Line 都走这条路径。
    ///
    /// 计算 `top = target - visible_lines/2`,塞进 `scroll_to_row`,下一帧
    /// `render_text_area` 开头 take 掉并覆盖 `scroll_line`。顺便把
    /// `wheel_accum` 清零 —— 跳转是"硬定位",之前攒着的半行滚轮增量
    /// 不应该跨越跳转延续下去。
    fn scroll_to_row_centered(&mut self, target_row: usize) {
        let half = self.visible_lines.saturating_sub(1) / 2;
        let top = target_row.saturating_sub(half);
        self.scroll_to_row = Some(top);
        self.wheel_accum = 0.0;
    }

    fn open_file(&mut self, path: PathBuf) {
        self.open_start_time = Some(std::time::Instant::now());
        match FileReader::new(path.clone(), self.selected_encoding) {
            Ok(reader) => {
                self.file_reader = Some(Arc::new(reader));
                // 后台线程建精确行索引。多 GB 文件也不会卡主线程 ——
                // 索引完成前的查询走 `avg_line_length` 估算路径,完成后
                // 由 `update()` 里的 `line_indexer.poll()` 原子切到精确路径。
                self.line_indexer
                    .index_file_async(self.file_reader.as_ref().unwrap().clone());
                self.scroll_line = 0;
                self.scroll_to_row = Some(0); // 新文件从顶部开始
                self.wheel_accum = 0.0;
                self.status_message = format!("Opened: {}", path.display());
                self.search_engine.clear();
                self.search_results.clear();
                self.total_search_results = 0;
                self.search_page_start_index = 0;
                self.page_offsets.clear();
                self.current_result_index = 0;
                // 下面这些 cache 和状态都以上一个文件的字节 offset 为 key
                // 或按字节位置染色,不清掉会跨文件"串场":切新文件后,旧
                // 文件的污点命中会继续在新文件同字节位置画紫色高亮,搜索
                // 预览也是旧的内容 —— 看上去像"加载失败"。
                self.search_preview_cache.clear();
                self.search_line_cache.clear();
                self.search_preview_cache_key = None;
                self.taint.clear_results();
                self.pending_replacements.clear();

                // Setup file watcher if tail mode is enabled
                if self.tail_mode {
                    self.setup_file_watcher();
                }
            }
            Err(e) => {
                self.status_message = format!("Error opening file: {}", e);
            }
        }
    }

    fn setup_file_watcher(&mut self) {
        if let Some(ref reader) = self.file_reader {
            let (tx, rx) = channel();
            let path = reader.path().clone();

            if let Ok(mut watcher) =
                notify::recommended_watcher(move |res: NotifyResult<notify::Event>| {
                    if let Ok(_event) = res {
                        let _ = tx.send(());
                    }
                })
            {
                if watcher.watch(&path, RecursiveMode::NonRecursive).is_ok() {
                    self.watcher = Some(Box::new(watcher));
                    self.file_change_rx = Some(rx);
                }
            }
        }
    }

    fn check_file_changes(&mut self) {
        if let Some(ref rx) = self.file_change_rx {
            if rx.try_recv().is_ok() {
                // File changed, reload
                if let Some(ref reader) = self.file_reader {
                    let path = reader.path().clone();
                    let encoding = reader.encoding();
                    self.selected_encoding = encoding;
                    self.open_file(path);

                    // Scroll to bottom in tail mode
                    if self.tail_mode {
                        let total_lines = self.line_indexer.total_lines();
                        let target_line = total_lines.saturating_sub(self.visible_lines);
                        self.scroll_line = target_line;
                        self.scroll_to_row = Some(target_line);
                    }
                }
            }
        }
    }

    fn perform_search(&mut self, find_all: bool) {
        self.search_error = None;
        self.search_results.clear();
        self.current_result_index = 0;
        self.total_search_results = 0;
        self.search_page_start_index = 0;
        self.page_offsets.clear();
        self.search_engine.clear();
        // 搜索结果面板的缓存以 byte_offset 为 key,换一次搜索后
        // 命中位置完全不同,旧缓存全部失效。之前漏清了这三个,
        // 导致"多次搜索后行号全变 1、预览空白"(新 byte_offset
        // 在旧 cache 里查不到 → unwrap_or(0) / unwrap_or_default)。
        self.search_preview_cache.clear();
        self.search_line_cache.clear();
        self.search_preview_cache_key = None;

        if self.search_in_progress {
            self.status_message = "Search already running...".to_string();
            return;
        }

        let Some(ref reader) = self.file_reader else {
            self.status_message = "Open a file before searching".to_string();
            return;
        };

        if self.search_query.is_empty() {
            self.status_message = "Enter a search query first".to_string();
            return;
        }

        self.search_engine.set_query(
            self.search_query.clone(),
            self.use_regex,
            self.case_sensitive,
        );

        let reader = reader.clone();
        // Use a bounded channel to provide backpressure to search threads
        // This prevents memory explosion if the UI thread can't keep up with results
        let (tx, rx) = std::sync::mpsc::sync_channel(10_000);

        self.search_message_rx = Some(rx);
        self.search_in_progress = true;
        self.search_find_all = find_all;
        self.search_count_done = false;
        self.search_fetch_done = false;
        self.search_first_jump_done = false;

        let cancel_token = Arc::new(AtomicBool::new(false));
        self.search_cancellation_token = Some(cancel_token.clone());

        self.status_message = if find_all {
            "Searching all matches...".to_string()
        } else {
            "Searching first match...".to_string()
        };

        if find_all {
            self.search_count_start_time = Some(std::time::Instant::now());
            // 单次并行扫(原来是 count 并行 + fetch 串行两趟):每个
            // worker 线程扫自己那段字节,同时记本地 count(→ CountResult)
            // 和本地命中位置(→ ChunkResult)。UI 侧的 poller 把 count
            // 累加,ChunkResult 按 byte_offset 排序,最终呈现顺序与老的
            // 串行 fetch 完全一致 —— 只是 N 倍更快,因为 I/O 在多核
            // 并发,不再是单线程从 byte 0 线性走到结尾。
            //
            // 之前用户报 "count 秒出 12,结果还要等十几秒才显示" 就是
            // 因为 fetch 那一趟是单线程。
            let tx_all = tx.clone();
            let reader_all = reader.clone();
            let query = self.search_query.clone();
            let use_regex = self.use_regex;
            let case_sensitive = self.case_sensitive;
            let cancel_token_all = cancel_token.clone();

            std::thread::spawn(move || {
                let mut engine = SearchEngine::new();
                engine.set_query(query, use_regex, case_sensitive);
                engine.find_all_parallel(reader_all, tx_all, 1000, cancel_token_all);
            });
        } else {
            // Find first match only
            let tx_fetch = tx.clone();
            let reader_fetch = reader.clone();
            let query = self.search_query.clone();
            let use_regex = self.use_regex;
            let case_sensitive = self.case_sensitive;
            let cancel_token_fetch = cancel_token.clone();

            std::thread::spawn(move || {
                let mut engine = SearchEngine::new();
                engine.set_query(query, use_regex, case_sensitive);
                engine.fetch_matches(reader_fetch, tx_fetch, 0, 1, cancel_token_fetch);
            });
        }
    }

    fn poll_search_results(&mut self) {
        if !self.search_in_progress {
            return;
        }

        if let Some(ref rx) = self.search_message_rx {
            let mut new_results_added = false;
            // Process all available messages
            while let Ok(msg) = rx.try_recv() {
                match msg {
                    SearchMessage::CountResult(count) => {
                        self.total_search_results += count;
                        if self.search_find_all {
                            self.status_message =
                                format!("Found {} matches...", self.total_search_results);
                        }
                    }
                    SearchMessage::ChunkResult(chunk_result) => {
                        // Add results
                        self.search_results.extend(chunk_result.matches);
                        new_results_added = true;
                    }
                    SearchMessage::Done(search_type) => {
                        match search_type {
                            SearchType::Count => {
                                self.search_count_done = true;
                                if let Some(start_time) = self.search_count_start_time {
                                    let elapsed = start_time.elapsed();
                                    println!("Search count completed in: {:.2?}", elapsed);
                                    self.status_message = format!(
                                        "{} (Counted in {:.2?})",
                                        self.status_message, elapsed
                                    );
                                    self.search_count_start_time = None;
                                }
                            }
                            SearchType::Fetch => self.search_fetch_done = true,
                        }

                        if self.search_find_all
                            && self.search_count_done
                            && self.search_results.len() == self.total_search_results
                        {
                            if let Some(token) = &self.search_cancellation_token {
                                token.store(true, Ordering::Relaxed);
                            }
                        }
                    }
                    SearchMessage::Error(e) => {
                        self.search_in_progress = false;
                        self.search_message_rx = None;
                        self.search_error = Some(e.clone());
                        self.status_message = format!("Search failed: {}", e);
                        return; // Stop processing messages
                    }
                }
            }

            // Check if channel is disconnected
            if let Err(std::sync::mpsc::TryRecvError::Disconnected) = rx.try_recv() {
                self.search_in_progress = false;
                self.search_message_rx = None;

                // Final sort to ensure everything is in order
                self.search_results.sort_by_key(|r| r.byte_offset);

                // If we are in "Find All" mode, total_results should be at least search_results.len()
                // But count task might be slower or faster.
                // If count task finished, total_results is correct.
                // If fetch task finished, search_results is populated.

                // If we are not finding all, total_results might be 0 (since we didn't run count task).
                if !self.search_find_all {
                    self.total_search_results = self.search_results.len();
                } else {
                    // Ensure total is at least what we have
                    self.total_search_results =
                        self.total_search_results.max(self.search_results.len());
                }

                let total = self.total_search_results;
                if total > 0 {
                    if self.search_find_all {
                        self.status_message = format!("Found {} matches", total);
                    } else {
                        self.status_message =
                            "Showing first match. Run Find All to see every result.".to_string();
                    }

                    // Ensure we scroll to the first result if we haven't yet.
                    // 只跳一次(见 `search_first_jump_done` 字段注释)。
                    if !self.search_first_jump_done && !self.search_results.is_empty() {
                        let target_line = self.line_at(self.search_results[0].byte_offset);
                        self.scroll_to_row_centered(target_line);
                        self.search_first_jump_done = true;
                    }
                } else {
                    self.status_message = "No matches found".to_string();
                }
            }

            if new_results_added {
                // Sort results by byte offset to keep them in order
                // Only sort once per frame after processing all available chunks
                self.search_results.sort_by_key(|r| r.byte_offset);

                // Check for scroll update after sort. 同样只跳一次。
                if !self.search_first_jump_done
                    && !self.search_results.is_empty()
                    && self.current_result_index == 0
                {
                    let target_line = self.line_at(self.search_results[0].byte_offset);
                    self.scroll_to_row_centered(target_line);
                    self.search_first_jump_done = true;
                }
            }
        }
    }

    fn poll_replace_results(&mut self) {
        if !self.replace_in_progress {
            return;
        }

        let mut done = false;
        if let Some(ref rx) = self.replace_message_rx {
            while let Ok(msg) = rx.try_recv() {
                match msg {
                    ReplaceMessage::Progress(processed, total) => {
                        let progress = processed as f32 / total as f32;
                        self.replace_progress = Some(progress);
                        self.replace_status_message =
                            Some(format!("Replacing... {:.1}%", progress * 100.0));
                    }
                    ReplaceMessage::Done => {
                        self.replace_status_message = Some("Replacement complete.".to_string());
                        self.status_message = "Replacement complete.".to_string();
                        done = true;
                    }
                    ReplaceMessage::Error(e) => {
                        self.replace_status_message = Some(format!("Replace failed: {}", e));
                        self.status_message = format!("Replace failed: {}", e);
                        done = true;
                    }
                }
            }
        }

        if done {
            self.replace_in_progress = false;
            self.replace_message_rx = None;
            self.replace_cancellation_token = None;
            self.replace_progress = None;
        }
    }

    fn perform_single_replace(&mut self) {
        if self.search_results.is_empty() {
            return;
        }

        let local_index = if self.current_result_index >= self.search_page_start_index {
            self.current_result_index - self.search_page_start_index
        } else {
            return;
        };

        if local_index >= self.search_results.len() {
            return;
        }

        let sr = &self.search_results[local_index];

        // Queue the replacement
        self.pending_replacements.push(PendingReplacement {
            offset: sr.byte_offset,
            old_len: sr.match_len,
            new_text: self.replace_query.clone(),
        });
        self.unsaved_changes = true;
        self.status_message = "Replacement pending. Save to apply changes.".to_string();
    }

    fn save_file(&mut self) {
        let Some(ref reader) = self.file_reader else {
            return;
        };
        let input_path = reader.path().clone();
        let encoding = reader.encoding();

        if let Some(output_path) = rfd::FileDialog::new()
            .set_file_name(input_path.file_name().map(|n| n.to_string_lossy()).unwrap_or_default())
            .save_file()
        {
            // If saving to the same file
            if output_path == input_path {
                // Apply pending replacements in-place if possible
                // We need to close the reader first to release the lock
                self.file_reader = None;

                let mut success = true;
                for replacement in &self.pending_replacements {
                    if let Err(e) = Replacer::replace_single(
                        &input_path,
                        replacement.offset,
                        replacement.old_len,
                        &replacement.new_text,
                    ) {
                        self.status_message = format!("Error saving: {}", e);
                        success = false;
                        break;
                    }
                }

                if success {
                    self.pending_replacements.clear();
                    self.unsaved_changes = false;
                    self.status_message = "File saved successfully".to_string();
                }

                // Re-open file
                match FileReader::new(input_path.clone(), encoding) {
                    Ok(reader) => {
                        self.file_reader = Some(Arc::new(reader));
                        self.line_indexer
                            .index_file(self.file_reader.as_ref().unwrap());
                        self.perform_search(self.search_find_all);
                    }
                    Err(e) => {
                        self.status_message = format!("Error re-opening file: {}", e);
                    }
                }
            } else {
                // Saving to a different file
                // Fallback: Copy file to output, then apply replacements in-place on the output file.
                if std::fs::copy(&input_path, &output_path).is_ok() {
                    let mut success = true;
                    for replacement in &self.pending_replacements {
                        if let Err(e) = Replacer::replace_single(
                            &output_path,
                            replacement.offset,
                            replacement.old_len,
                            &replacement.new_text,
                        ) {
                            self.status_message = format!("Error saving: {}", e);
                            success = false;
                            break;
                        }
                    }
                    if success {
                        self.pending_replacements.clear();
                        self.unsaved_changes = false;
                        self.status_message = "File saved successfully".to_string();
                        self.open_file(output_path);
                    }
                } else {
                    self.status_message = "Error copying file for save".to_string();
                }
            }
        }
    }

    fn perform_replace(&mut self) {
        if self.replace_in_progress {
            return;
        }

        let Some(ref reader) = self.file_reader else {
            return;
        };
        let input_path = reader.path().clone();
        let file_size = reader.len();

        // 全量 Replace All 本质是"把整个文件复制一遍写到临时文件,再
        // 原子 rename 回去"。50GB trace 上这一下磁盘读 + 磁盘写 = 双向
        // 100GB I/O,不仅要几分钟,还要同等大小的自由空间。用户多半是
        // 误点(想替换的是当前页里的命中),给个明确阻止优于静默跑十
        // 分钟。2GB 是一个比较宽松的阈值。
        const REPLACE_MAX_BYTES: usize = 2 * 1024 * 1024 * 1024;
        if file_size > REPLACE_MAX_BYTES {
            self.status_message = format!(
                "Replace All 禁用:文件 {:.1} GB 超过 {} GB 阈值。\
                 全量替换要把整个文件复制一遍,50GB 级 trace 文件上基本\
                 不可用,也不是此工具的设计目标。",
                file_size as f64 / 1024.0 / 1024.0 / 1024.0,
                REPLACE_MAX_BYTES / 1024 / 1024 / 1024
            );
            return;
        }

        // Ask for output file
        if let Some(output_path) = rfd::FileDialog::new()
            .set_file_name(format!(
                "{}.modified",
                input_path.file_name().map(|n| n.to_string_lossy()).unwrap_or_default()
            ))
            .save_file()
        {
            let query = self.search_query.clone();
            let replace_with = self.replace_query.clone();
            let use_regex = self.use_regex;

            let (tx, rx) = std::sync::mpsc::channel();
            self.replace_message_rx = Some(rx);
            self.replace_in_progress = true;
            self.replace_progress = Some(0.0);
            self.replace_status_message = None;

            let cancel_token = Arc::new(AtomicBool::new(false));
            self.replace_cancellation_token = Some(cancel_token.clone());

            std::thread::spawn(move || {
                Replacer::replace_all(
                    &input_path,
                    &output_path,
                    &query,
                    &replace_with,
                    use_regex,
                    tx,
                    cancel_token,
                );
            });
        }
    }

    fn go_to_next_result(&mut self) {
        if self.total_search_results == 0 {
            return;
        }

        let next_index = (self.current_result_index + 1) % self.total_search_results;

        // Check if next_index is within current page
        let page_end_index = self.search_page_start_index + self.search_results.len();

        if next_index >= self.search_page_start_index && next_index < page_end_index {
            // In current page
            self.current_result_index = next_index;
            let local_index = next_index - self.search_page_start_index;
            let result = &self.search_results[local_index];
            let target_line = self.line_at(result.byte_offset);
            self.scroll_to_row_centered(target_line);
        } else {
            // Need to fetch next page
            // If we are wrapping around to 0
            if next_index == 0 {
                self.fetch_page(0, 0);
            } else {
                // Fetch next page starting from the end of current page
                // We need the byte offset to start searching from.
                // If we are just moving to the next page sequentially, we can use the last result's offset.
                if let Some(last_result) = self.search_results.last() {
                    // We should record the current page start offset before moving
                    if self.page_offsets.len() <= next_index / 1000 && self.page_offsets.is_empty()
                    {
                        self.page_offsets.push(0);
                    }

                    let start_offset = last_result.byte_offset + 1;
                    self.fetch_page(next_index, start_offset);
                } else {
                    // Should not happen if total > 0
                    self.fetch_page(0, 0);
                }
            }
            self.current_result_index = next_index;
        }
    }

    fn go_to_previous_result(&mut self) {
        if self.total_search_results == 0 {
            return;
        }

        let prev_index = if self.current_result_index == 0 {
            self.total_search_results - 1
        } else {
            self.current_result_index - 1
        };

        // Check if prev_index is within current page
        let page_end_index = self.search_page_start_index + self.search_results.len();

        if prev_index >= self.search_page_start_index && prev_index < page_end_index {
            // In current page
            self.current_result_index = prev_index;
            let local_index = prev_index - self.search_page_start_index;
            let result = &self.search_results[local_index];
            let target_line = self.line_at(result.byte_offset);
            self.scroll_to_row_centered(target_line);
        } else {
            // Need to fetch previous page (or last page if wrapping)
            if prev_index == self.total_search_results - 1 {
                self.status_message = "Cannot wrap to end in paginated mode yet.".to_string();
            } else {
                // Fetch previous page
                // We need the start offset of the page containing `prev_index`.
                // We assume pages are 1000 items.
                let target_page_idx = prev_index / 1000;
                let target_page_start_index = target_page_idx * 1000;

                if let Some(&offset) = self.page_offsets.get(target_page_idx) {
                    self.fetch_page(target_page_start_index, offset);
                    self.current_result_index = prev_index;
                } else {
                    // Fallback: Search from 0
                    self.fetch_page(0, 0);
                    self.current_result_index = 0; // Reset to 0 if lost
                }
            }
        }
    }

    fn fetch_page(&mut self, start_index: usize, start_offset: usize) {
        if self.search_in_progress {
            return;
        }

        let Some(ref reader) = self.file_reader else {
            return;
        };

        self.search_results.clear();
        self.search_page_start_index = start_index;

        // Update page_offsets
        let page_idx = start_index / 1000;
        if page_idx >= self.page_offsets.len() {
            if page_idx == self.page_offsets.len() {
                self.page_offsets.push(start_offset);
            }
        } else {
            // Update existing?
            self.page_offsets[page_idx] = start_offset;
        }

        let reader = reader.clone();
        let query = self.search_query.clone();
        let use_regex = self.use_regex;
        let case_sensitive = self.case_sensitive;
        let (tx, rx) = std::sync::mpsc::sync_channel(10_000);
        self.search_message_rx = Some(rx);
        self.search_in_progress = true;

        let cancel_token = Arc::new(AtomicBool::new(false));
        self.search_cancellation_token = Some(cancel_token.clone());

        self.status_message = format!(
            "Loading results {}...{}",
            start_index + 1,
            start_index + 1000
        );

        std::thread::spawn(move || {
            let mut engine = SearchEngine::new();
            engine.set_query(query, use_regex, case_sensitive);
            engine.fetch_matches(reader, tx, start_offset, 1000, cancel_token);
        });
    }

    fn go_to_line(&mut self) {
        if let Ok(line_num) = self.goto_line_input.parse::<usize>() {
            if line_num > 0 && line_num <= self.line_indexer.total_lines() {
                let target_line = line_num - 1; // 0-indexed
                self.scroll_to_row_centered(target_line);
                self.status_message = format!("Jumped to line {}", line_num);
            } else {
                self.status_message = "Line number out of range".to_string();
            }
        } else {
            self.status_message = "Invalid line number".to_string();
        }
    }

    fn render_menu_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("menu_bar").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("Open...").clicked() {
                        if let Some(path) = rfd::FileDialog::new().pick_file() {
                            self.load_file_with_auto_encoding(path);
                        }
                        ui.close_menu();
                    }

                    if ui
                        .add_enabled(self.unsaved_changes, egui::Button::new("Save (Ctrl+S)"))
                        .clicked()
                    {
                        self.save_file();
                        ui.close_menu();
                    }

                    if ui.button("File Info").clicked() {
                        self.show_file_info = !self.show_file_info;
                        ui.close_menu();
                    }

                    if ui.button("Exit").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });

                ui.menu_button("View", |ui| {
                    ui.checkbox(&mut self.wrap_mode, "Word Wrap");
                    ui.checkbox(&mut self.show_line_numbers, "Line Numbers");
                    ui.checkbox(&mut self.dark_mode, "Dark Mode");

                    ui.separator();

                    ui.label("Font Size:");
                    ui.add(egui::Slider::new(&mut self.font_size, 8.0..=32.0));

                    ui.separator();

                    if ui.button("Select Encoding").clicked() {
                        self.show_encoding_selector = true;
                        ui.close_menu();
                    }
                });

                ui.menu_button("Search", |ui| {
                    if ui
                        .add(egui::Button::new("Find").shortcut_text("Ctrl+F"))
                        .clicked()
                    {
                        self.show_search_bar = true;
                        self.focus_search_input = true;
                        ui.close_menu();
                    }
                    if ui
                        .add(egui::Button::new("Replace").shortcut_text("Ctrl+R"))
                        .clicked()
                    {
                        self.show_search_bar = true;
                        self.show_replace = !self.show_replace;
                        ui.close_menu();
                    }
                    if ui
                        .add(egui::Button::new("搜索结果列表").shortcut_text("Ctrl+L"))
                        .on_hover_text("在悬浮窗中列出当前页全部匹配,双击跳转")
                        .clicked()
                    {
                        self.show_search_list = !self.show_search_list;
                        ui.close_menu();
                    }
                    ui.separator();
                    ui.checkbox(&mut self.use_regex, "Use Regex");
                    ui.checkbox(&mut self.case_sensitive, "Match Case");
                });

                ui.menu_button("Tools", |ui| {
                    if ui
                        .checkbox(&mut self.tail_mode, "Tail Mode (Auto-refresh)")
                        .changed()
                    {
                        if self.tail_mode {
                            self.setup_file_watcher();
                        } else {
                            self.watcher = None;
                            self.file_change_rx = None;
                        }
                    }
                    ui.separator();
                    if ui
                        .add_enabled(
                            self.file_reader.is_some(),
                            egui::Button::new("污点追踪..."),
                        )
                        .on_hover_text("对当前 trace 运行 ARM64 xgtrace 污点传播分析")
                        .clicked()
                    {
                        self.taint.open_dialog(self.scroll_line);
                        ui.close_menu();
                    }
                    if ui
                        .add_enabled(
                            self.taint.completed.is_some(),
                            egui::Button::new("显示污点结果面板"),
                        )
                        .clicked()
                    {
                        self.taint.show_panel = true;
                        ui.close_menu();
                    }
                    if ui
                        .add_enabled(
                            self.taint.completed.is_some() || self.taint.running,
                            egui::Button::new("清空污点结果"),
                        )
                        .clicked()
                    {
                        self.taint.clear_results();
                        ui.close_menu();
                    }
                });
            });
        });
    }

    fn render_toolbar(&mut self, ctx: &egui::Context) {
        if !self.show_search_bar {
            return;
        }
        egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label("Search:");
                // Stable id so we can probe focus status from elsewhere
                // (status bar) without holding the response.
                let response = ui.add(
                    egui::TextEdit::singleline(&mut self.search_query)
                        .id(egui::Id::new("search_toolbar_input"))
                        .desired_width(300.0),
                );

                // egui's request_focus takes effect on the *next* frame, so a
                // single request after Ctrl+F is racy — if any other widget
                // also tries to set focus that frame we lose. Keep retrying
                // every frame until the TextEdit actually owns focus, then
                // clear the flag.
                if self.focus_search_input {
                    response.request_focus();
                    if response.has_focus() {
                        self.focus_search_input = false;
                    }
                }

                ui.checkbox(&mut self.case_sensitive, "Aa")
                    .on_hover_text("Match Case");
                ui.checkbox(&mut self.use_regex, ".*")
                    .on_hover_text("Use Regex");

                if response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    self.perform_search(false);
                }

                if ui
                    .add_enabled(!self.search_in_progress, egui::Button::new("🔍 Find"))
                    .clicked()
                {
                    self.perform_search(false);
                }

                if ui
                    .add_enabled(!self.search_in_progress, egui::Button::new("🔎 Find All"))
                    .clicked()
                {
                    self.perform_search(true);
                }

                if ui.button("⬆ Previous").clicked() {
                    self.go_to_previous_result();
                }

                if ui.button("⬇ Next").clicked() {
                    self.go_to_next_result();
                }

                if self.search_in_progress {
                    ui.add(egui::Spinner::new().size(18.0));
                    ui.label("Searching...");
                    if ui.button("Stop").clicked() {
                        if let Some(token) = &self.search_cancellation_token {
                            token.store(true, Ordering::Relaxed);
                        }
                        self.search_in_progress = false;
                        self.status_message = "Search stopped by user".to_string();
                    }
                }

                let total_results = self.total_search_results;
                if total_results > 0 {
                    // Show current position over total
                    let current = (self.current_result_index + 1).min(total_results);
                    ui.label(format!("{}/{}", current, total_results));
                }

                ui.separator();

                ui.label("Go to line:");
                let response = ui
                    .add(egui::TextEdit::singleline(&mut self.goto_line_input).desired_width(80.0));

                if response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    self.go_to_line();
                }

                if ui.button("Go").clicked() {
                    self.go_to_line();
                }
            });

            if self.show_replace {
                ui.separator();
                ui.horizontal(|ui| {
                    ui.label("Replace with:");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.replace_query)
                            .desired_width(200.0)
                            .hint_text("Replacement text..."),
                    );

                    if self.replace_in_progress {
                        if ui.button("Stop Replace").clicked() {
                            if let Some(token) = &self.replace_cancellation_token {
                                token.store(true, std::sync::atomic::Ordering::Relaxed);
                            }
                        }
                        ui.spinner();
                        if let Some(progress) = self.replace_progress {
                            ui.label(format!("{:.1}%", progress * 100.0));
                        }
                    } else {
                        if ui.button("Replace").clicked() {
                            self.perform_single_replace();
                        }
                        if ui.button("Replace All").clicked() {
                            self.perform_replace();
                        }
                    }
                });

                if let Some(ref msg) = self.replace_status_message {
                    ui.label(msg);
                }
            }

            if let Some(ref error) = self.search_error {
                ui.colored_label(egui::Color32::RED, format!("Search error: {}", error));
            }
        });
    }

    fn render_status_bar(&mut self, ctx: &egui::Context) {
        // Probe focus before drawing so we can show it on the right side of
        // the bar — useful when debugging "the search bar swallowed my keys".
        let search_id = egui::Id::new("search_toolbar_input");
        let search_focused = ctx.memory(|m| m.has_focus(search_id));
        let any_focused_id = ctx.memory(|m| m.focused());

        egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if let Some(ref reader) = self.file_reader {
                    ui.label(format!("File: {}", reader.path().display()));
                    ui.separator();
                    ui.label(format!("Size: {} bytes", reader.len()));
                    ui.separator();
                    // `~` while the background exact-index scan is running
                    // — the count is an avg-line-length estimate during
                    // that window. Once `poll` lands the scan result, the
                    // same code path prints the exact total.
                    let line_prefix = if self.line_indexer.is_indexing() {
                        "~"
                    } else {
                        ""
                    };
                    ui.label(format!(
                        "Lines: {}{}",
                        line_prefix,
                        self.line_indexer.total_lines()
                    ));
                    if self.line_indexer.is_indexing() {
                        ui.add(egui::Spinner::new().size(12.0));
                        ui.label(
                            egui::RichText::new("建索引中")
                                .size(11.0)
                                .color(egui::Color32::from_rgb(200, 180, 120)),
                        );
                    }
                    ui.separator();
                    ui.label(format!("Encoding: {}", reader.encoding().name()));
                    ui.separator();
                    ui.label(format!("Line: {}", self.scroll_line + 1));
                } else {
                    ui.label("No file opened - Click File → Open to start");
                }

                if !self.status_message.is_empty() {
                    ui.separator();
                    ui.label(&self.status_message);
                }

                if self.taint.running {
                    ui.separator();
                    ui.spinner();
                    ui.label(format!("污点: {}", self.taint.status_text));
                } else if let Some(c) = &self.taint.completed {
                    ui.separator();
                    ui.label(format!(
                        "污点: {} 条命中({})",
                        c.hits.len(),
                        match c.mode {
                            large_text_taint::engine::TrackMode::Forward => "向前",
                            large_text_taint::engine::TrackMode::Backward => "向后",
                        }
                    ));
                }

                // Right-aligned focus indicator for the search box. Helpful
                // when debugging "Ctrl+F won't accept input" — if this shows
                // ✗ while the search bar is open, focus is being stolen.
                if self.show_search_bar {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let (mark, color) = if search_focused {
                            ("✓", egui::Color32::from_rgb(140, 230, 140))
                        } else {
                            ("✗", egui::Color32::from_rgb(240, 150, 150))
                        };
                        ui.label(
                            egui::RichText::new(format!("搜索框焦点 {}", mark))
                                .size(11.0)
                                .color(color),
                        );
                        if !search_focused {
                            if let Some(other) = any_focused_id {
                                ui.label(
                                    egui::RichText::new(format!(
                                        "(焦点在 {:?})  ",
                                        other
                                    ))
                                    .size(10.0)
                                    .color(egui::Color32::from_rgb(180, 180, 100)),
                                );
                            }
                        }
                    });
                }
            });
        });
    }

    fn render_text_area(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            if let Some(ref reader) = self.file_reader {
                let available_height = ui.available_height();
                let font_id = egui::FontId::monospace(self.font_size);
                let line_height = ui.fonts(|f| f.row_height(&font_id));
                self.visible_lines =
                    ((available_height / line_height).ceil() as usize).saturating_add(2);

                let mut scroll_area = if self.wrap_mode {
                    egui::ScrollArea::vertical()
                } else {
                    egui::ScrollArea::both()
                }
                // Tie scroll memory to the current file path so new files start at the top
                .id_salt(
                    self.file_reader
                        .as_ref()
                        .map(|r| r.path().display().to_string())
                        .unwrap_or_else(|| "no_file".to_string()),
                )
                .auto_shrink([false, false])
                .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysVisible)
                .drag_to_scroll(true);

                // —— 整数滚动模型:我们自己数"到第几行了",不走 f32 ——
                //
                // 1) 程序化跳转:`scroll_to_row` 一旦有值就 take 并覆盖
                //    到 `scroll_line`。搜索命中 / 污点命中 / Go-To-Line
                //    等都走这条路。
                if let Some(target_row) = self.scroll_to_row.take() {
                    self.scroll_line = target_row;
                    self.wheel_accum = 0.0;
                }

                // 2) 鼠标滚轮:仅在指针落在中央文本区才算本面板的滚轮
                //    事件(否则滚动工具栏、搜索面板等其它区域会误触)。
                //    把本帧的 smooth_scroll_delta.y 消费掉,ScrollArea
                //    就不再自己处理它 —— 避免"egui 按 f32 滚一档 + 我们
                //    按整数滚一档"的双倍滚动。攒到 `line_height` 的整
                //    数倍才进位到 `scroll_line`,不足的留下来等下次。
                let panel_rect = ui.available_rect_before_wrap();
                let pointer_in_panel = ctx
                    .input(|i| i.pointer.hover_pos())
                    .map(|p| panel_rect.contains(p))
                    .unwrap_or(false);
                if pointer_in_panel {
                    let wheel_dy = ctx.input_mut(|i| {
                        let dy = i.smooth_scroll_delta.y;
                        i.smooth_scroll_delta.y = 0.0;
                        dy
                    });
                    // egui 约定 delta.y 正 = 内容下移(用户向上滚);
                    // 我们的 `scroll_line` 是顶行号,向上滚对应行号变小。
                    // 所以方向是 `scroll_line -= wheel / line_height`。
                    self.wheel_accum -= wheel_dy;
                    if line_height > 0.0 {
                        let rows = (self.wheel_accum / line_height) as i64;
                        if rows != 0 {
                            let total = self.line_indexer.total_lines() as i64;
                            let upper = (total - 1).max(0);
                            let new_line = (self.scroll_line as i64 + rows).clamp(0, upper);
                            self.scroll_line = new_line as usize;
                            self.wheel_accum -= rows as f32 * line_height;
                        }
                    }
                }

                // 3) 每帧把 ScrollArea 的 offset 强制对齐到整数行。
                //    ScrollArea 现在只负责画滚动条的 thumb 位置,它自己
                //    对 f32 的量化不再影响我们显示哪一行。
                scroll_area = scroll_area
                    .vertical_scroll_offset(self.scroll_line as f32 * line_height);

                let mut first_visible_row = None;

                let output = scroll_area.show_rows(
                    ui,
                    line_height,
                    self.line_indexer.total_lines(),
                    |ui, row_range| {
                        // 不再信任 ScrollArea 给的 `row_range.start`(它
                        // 来自 f32 offset,多 GB 文件上会量化抖动)。权威
                        // 顶行号用我们自己的 `self.scroll_line`。
                        // `row_range.len()` 还是用 ScrollArea 算的 —— 它
                        // 基于视口高度,就是我们该渲染几行。
                        let corrected_start_line = self.scroll_line;

                        if first_visible_row.is_none() {
                            first_visible_row = Some(corrected_start_line);
                        }

                        // For contiguous rendering, we find the start offset of the first line
                        // and then read sequentially.
                        let mut current_offset = if let Some((start, _)) = self
                            .line_indexer
                            .get_line_with_reader(corrected_start_line, reader)
                        {
                            start
                        } else {
                            return;
                        };

                        // We iterate over the count of rows requested, but starting from our corrected line
                        let count = row_range.end - row_range.start;
                        let render_range = corrected_start_line..(corrected_start_line + count);


                        for line_num in render_range {
                            // Read line starting at current_offset
                            // We need to find the end of the line
                            let chunk_size = 4096; // Read in chunks to find newline
                            let mut line_end = current_offset;
                            let mut found_newline = false;

                            // Scan for newline
                            while !found_newline {
                                let chunk = reader.get_bytes(line_end, line_end + chunk_size);
                                if chunk.is_empty() {
                                    break;
                                }

                                if let Some(pos) = chunk.iter().position(|&b| b == b'\n') {
                                    line_end += pos + 1; // Include newline
                                    found_newline = true;
                                } else {
                                    line_end += chunk.len();
                                }

                                if line_end >= reader.len() {
                                    break;
                                }
                            }

                            let start = current_offset;
                            let end = line_end;
                            current_offset = end; // Next line starts here

                            if start >= reader.len() {
                                break;
                            }

                            let mut line_text_owned = reader.get_chunk(start, end);

                            // Apply pending replacements to the view
                            for replacement in &self.pending_replacements {
                                let rep_start = replacement.offset;
                                let rep_end = rep_start + replacement.old_len;

                                if rep_start >= start && rep_end <= end {
                                    let rel_start = rep_start - start;
                                    let rel_end = rep_end - start;

                                    if line_text_owned.is_char_boundary(rel_start)
                                        && line_text_owned.is_char_boundary(rel_end)
                                    {
                                        line_text_owned.replace_range(
                                            rel_start..rel_end,
                                            &replacement.new_text,
                                        );
                                    }
                                }
                            }

                            let line_text = line_text_owned
                                .trim_end_matches('\n')
                                .trim_end_matches('\r');

                            // Collect matches that fall within this line's byte span; this works even with sparse line indexing
                            // (start, end, is_selected, is_occurrence)
                            let mut line_matches: Vec<(usize, usize, bool, bool)> = Vec::new();

                            // Determine the byte offset of the currently selected result
                            let selected_offset = if self.total_search_results > 0
                                && self.current_result_index >= self.search_page_start_index
                            {
                                let local_idx =
                                    self.current_result_index - self.search_page_start_index;
                                self.search_results.get(local_idx).map(|r| r.byte_offset)
                            } else {
                                None
                            };

                            if self.search_find_all {
                                // Use find_in_text to find matches in the current line (highlight all visible)
                                for (m_start, m_end) in self.search_engine.find_in_text(line_text) {
                                    let abs_start = start + m_start;
                                    let is_selected = Some(abs_start) == selected_offset;
                                    line_matches.push((m_start, m_end, is_selected, false));
                                }
                            } else {
                                // Only highlight results present in search_results (e.g. single find)
                                // Use binary search to find the first potential match
                                // This assumes search_results is sorted by byte_offset
                                let start_idx = self
                                    .search_results
                                    .partition_point(|r| r.byte_offset < start);

                                for (idx, res) in
                                    self.search_results.iter().enumerate().skip(start_idx)
                                {
                                    if res.byte_offset >= end {
                                        break;
                                    }

                                    let rel_start = res.byte_offset.saturating_sub(start);
                                    if rel_start >= line_text.len() {
                                        continue;
                                    }
                                    let rel_end = (rel_start + res.match_len).min(line_text.len());

                                    // Check if this is the currently selected result
                                    // We need to map local index to global index
                                    let global_idx = self.search_page_start_index + idx;
                                    let is_selected = global_idx == self.current_result_index;

                                    line_matches.push((rel_start, rel_end, is_selected, false));
                                }
                            }

                            // Occurrence highlight: find all occurrences of the
                            // double-clicked word in this line. Require word
                            // boundaries so "x1" doesn't highlight inside
                            // "x10".."x19" (register tokens are
                            // alphanumeric+underscore).
                            if let Some(ref occ_word) = self.occurrence_word {
                                let bytes = line_text.as_bytes();
                                let mut search_from = 0;
                                while search_from < line_text.len() {
                                    if let Some(pos) = line_text[search_from..].find(occ_word.as_str()) {
                                        let abs_start = search_from + pos;
                                        let abs_end = abs_start + occ_word.len();
                                        let left_ok = abs_start == 0
                                            || !is_word_byte(bytes[abs_start - 1]);
                                        let right_ok = abs_end >= bytes.len()
                                            || !is_word_byte(bytes[abs_end]);
                                        if left_ok && right_ok {
                                            line_matches.push((abs_start, abs_end, false, true));
                                        }
                                        search_from = abs_end;
                                    } else {
                                        break;
                                    }
                                }
                                // Sort by start position so the LayoutJob segments
                                // are built in order; search matches and occurrence
                                // matches may interleave.
                                line_matches.sort_by_key(|m| m.0);
                            }

                            // Identify the line by its byte offset (exact),
                            // NOT by row index (approximate in sparse mode).
                            let line_off = start as u64;
                            let taint_hit = self.taint.hit_offsets.contains(&line_off);
                            let taint_selected = self.taint.selected_offset == Some(line_off);
                            let taint_bg = if taint_selected {
                                // Match the panel's "selected row" colour so the
                                // main view and the panel highlight the same line
                                // in a coherent, eye-catching hue.
                                egui::Color32::from_rgb(255, 210, 100)
                            } else if taint_hit {
                                if self.dark_mode {
                                    egui::Color32::from_rgb(90, 40, 120)
                                } else {
                                    egui::Color32::from_rgb(235, 200, 255)
                                }
                            } else {
                                egui::Color32::TRANSPARENT
                            };
                            // When the row is the active selection, force dark
                            // text so it stays readable on the bright highlight.
                            let taint_force_dark_text = taint_selected;
                            ui.horizontal(|ui| {
                                if self.show_line_numbers {
                                    let mut ln_text =
                                        egui::RichText::new(format!("{:6} ", line_num + 1))
                                            .monospace()
                                            .color(if taint_selected {
                                                egui::Color32::BLACK
                                            } else {
                                                egui::Color32::DARK_GRAY
                                            });
                                    if taint_hit || taint_selected {
                                        ln_text = ln_text.background_color(taint_bg);
                                    }
                                    // Make line numbers non-selectable so drag-select only captures the content text
                                    ui.add(egui::Label::new(ln_text).selectable(false));
                                }

                                // Build label with highlighted search matches
                                let label = if !line_matches.is_empty() {
                                    // Create a LayoutJob to highlight matches within the line using their byte offsets
                                    let mut job = egui::text::LayoutJob::default();
                                    let mut last_end = 0;

                                    for (abs_start, abs_end, is_selected, is_occurrence) in line_matches.iter() {
                                        if *abs_start > last_end {
                                            job.append(
                                                &line_text[last_end..*abs_start],
                                                0.0,
                                                egui::TextFormat {
                                                    font_id: egui::FontId::monospace(
                                                        self.font_size,
                                                    ),
                                                    color: if taint_force_dark_text {
                                                        egui::Color32::BLACK
                                                    } else if self.dark_mode {
                                                        egui::Color32::LIGHT_GRAY
                                                    } else {
                                                        egui::Color32::BLACK
                                                    },
                                                    background: taint_bg,
                                                    ..Default::default()
                                                },
                                            );
                                        }

                                        let match_end = (*abs_end).min(line_text.len());
                                        let bg = if *is_occurrence {
                                            // Occurrence highlight: subtle blue/cyan
                                            if self.dark_mode {
                                                egui::Color32::from_rgb(60, 100, 160)
                                            } else {
                                                egui::Color32::from_rgb(180, 215, 255)
                                            }
                                        } else if *is_selected {
                                            egui::Color32::from_rgb(255, 200, 0)
                                        } else {
                                            egui::Color32::YELLOW
                                        };
                                        let fg = if *is_occurrence && self.dark_mode {
                                            egui::Color32::WHITE
                                        } else {
                                            egui::Color32::BLACK
                                        };
                                        job.append(
                                            &line_text[*abs_start..match_end],
                                            0.0,
                                            egui::TextFormat {
                                                font_id: egui::FontId::monospace(self.font_size),
                                                color: fg,
                                                background: bg,
                                                ..Default::default()
                                            },
                                        );

                                        last_end = match_end;
                                    }

                                    // Add remaining text after last match
                                    if last_end < line_text.len() {
                                        job.append(
                                            &line_text[last_end..],
                                            0.0,
                                            egui::TextFormat {
                                                font_id: egui::FontId::monospace(self.font_size),
                                                color: if taint_force_dark_text {
                                                    egui::Color32::BLACK
                                                } else if self.dark_mode {
                                                    egui::Color32::LIGHT_GRAY
                                                } else {
                                                    egui::Color32::BLACK
                                                },
                                                background: taint_bg,
                                                ..Default::default()
                                            },
                                        );
                                    }

                                    if self.wrap_mode {
                                        job.wrap = egui::text::TextWrapping {
                                            max_width: ui.available_width(),
                                            ..Default::default()
                                        };
                                    }

                                    ui.add(egui::Label::new(job).extend())
                                } else {
                                    let mut text = egui::RichText::new(line_text)
                                        .monospace()
                                        .size(self.font_size);
                                    if taint_force_dark_text {
                                        text = text.color(egui::Color32::BLACK);
                                    }
                                    if taint_hit || taint_selected {
                                        text = text.background_color(taint_bg);
                                    }

                                    // Apply wrap mode
                                    if self.wrap_mode {
                                        ui.add(egui::Label::new(text).wrap())
                                    } else {
                                        ui.add(egui::Label::new(text).extend())
                                    }
                                };

                                // Enable text selection for copy-paste
                                if label.hovered() {
                                    ui.output_mut(|o| o.cursor_icon = egui::CursorIcon::Text);
                                }

                                // Occurrence highlight: double-click a word to
                                // highlight all same words in the viewport.
                                if label.double_clicked() {
                                    if let Some(pos) = ui.input(|i| i.pointer.interact_pos()) {
                                        // Layout the line once to translate the
                                        // click position into a char index.
                                        // Using the galley handles tabs, wide
                                        // chars, and kerning precisely — unlike
                                        // rel_x / mono_char_width, which drifts
                                        // on any line containing '\t'.
                                        let rel = pos - label.rect.left_top();
                                        let font_id = egui::FontId::monospace(self.font_size);
                                        let galley = ui.fonts(|f| {
                                            f.layout_no_wrap(
                                                line_text.to_string(),
                                                font_id,
                                                egui::Color32::TRANSPARENT,
                                            )
                                        });
                                        let cursor = galley.cursor_from_pos(rel);
                                        let char_idx = cursor.ccursor.index;
                                        let word = extract_word_at(line_text, char_idx);
                                        if word.is_empty() {
                                            self.occurrence_word = None;
                                        } else {
                                            self.occurrence_word = Some(word);
                                        }
                                    }
                                } else if label.clicked() {
                                    // Single click clears occurrence highlight.
                                    self.occurrence_word = None;
                                }

                                // Right-click: taint tracking menu for this line.
                                label.clone().context_menu(|ui| {
                                    let start_line_1based = (line_num as u32).saturating_add(1);
                                    // Parse this single line so we can offer one-click quick
                                    // targets for its registers / memory operands.
                                    let parsed = large_text_taint::parser::TraceParser::parse_single_line(
                                        line_text.as_bytes(),
                                        start_line_1based,
                                        0,
                                    );
                                    let mut chosen: Option<(
                                        large_text_taint::engine::TrackMode,
                                        large_text_taint::engine::TaintSource,
                                    )> = None;

                                    ui.label(format!("第 {} 行", start_line_1based));
                                    ui.separator();

                                    if let Some(tl) = &parsed {
                                        let raw_line = line_text.as_bytes();
                                        let targets = crate::taint::collect_targets(tl, raw_line);
                                        let addr_targets = crate::taint::collect_addr_source_targets(tl, raw_line);
                                        if targets.is_empty() {
                                            ui.label(
                                                egui::RichText::new(
                                                    "(本行无寄存器/内存操作数)",
                                                )
                                                .small()
                                                .italics(),
                                            );
                                        } else {
                                            ui.menu_button("向后追踪起点...", |ui| {
                                                for src in &targets {
                                                    if ui
                                                        .button(crate::taint::source_display(src))
                                                        .clicked()
                                                    {
                                                        chosen = Some((
                                                            large_text_taint::engine::TrackMode::Backward,
                                                            *src,
                                                        ));
                                                        ui.close_menu();
                                                    }
                                                }
                                            });
                                            // For Load/Store: offer a separate
                                            // sub-menu that tracks address-source
                                            // registers directly (skipping the
                                            // Load/Store propagation on the start
                                            // line).
                                            if !addr_targets.is_empty() {
                                                ui.menu_button("向后追踪地址来源...", |ui| {
                                                    for src in &addr_targets {
                                                        if ui
                                                            .button(crate::taint::source_display(src))
                                                            .clicked()
                                                        {
                                                            chosen = Some((
                                                                large_text_taint::engine::TrackMode::Backward,
                                                                *src,
                                                            ));
                                                            ui.close_menu();
                                                        }
                                                    }
                                                });
                                            }
                                            ui.menu_button("向前追踪起点...", |ui| {
                                                for src in &targets {
                                                    if ui
                                                        .button(crate::taint::source_display(src))
                                                        .clicked()
                                                    {
                                                        chosen = Some((
                                                            large_text_taint::engine::TrackMode::Forward,
                                                            *src,
                                                        ));
                                                        ui.close_menu();
                                                    }
                                                }
                                            });
                                            ui.separator();
                                        }
                                    } else {
                                        ui.label(
                                            egui::RichText::new("(此行不是指令行)")
                                                .small()
                                                .italics(),
                                        );
                                        ui.separator();
                                    }

                                    if ui.button("用对话框从本行启动...").clicked() {
                                        self.taint.open_dialog(line_num);
                                        ui.close_menu();
                                    }

                                    if let Some((mode, source)) = chosen {
                                        if let Some(reader) = self.file_reader.as_ref() {
                                            if let Err(e) = self.taint.quick_start(
                                                reader.clone(),
                                                mode,
                                                source,
                                                // exact byte offset of the clicked line — authoritative
                                                start as u64,
                                                // line number is only a UI hint (may be approximate under sparse index)
                                                start_line_1based,
                                            ) {
                                                self.status_message = format!("污点: {}", e);
                                            }
                                        }
                                    }
                                });

                                // Ensure labels don't consume scroll events
                                label.surrender_focus();
                            });
                        }
                    },
                );

                // 滚动条被拖拽检测:
                //
                // 正常帧里 ScrollArea 的 offset 应该 ≈ `scroll_line *
                // line_height`(我们上面 vertical_scroll_offset 强制过)。
                // 如果本帧结束后 offset 显著大于/小于这个值,说明用户
                // 直接拖拽了滚动条 thumb —— 反向折算成整数行写回
                // `scroll_line`,下一帧重新锁定。
                //
                // 容差取 2 × line_height:小于这个差值认为只是 f32 的
                // 量化抖动,不作反应;超过则必然是用户操作。
                let expected_offset = self.scroll_line as f32 * line_height;
                let actual_offset = output.state.offset.y;
                let scrollbar_dragged = line_height > 0.0
                    && (actual_offset - expected_offset).abs() > 2.0 * line_height;
                if scrollbar_dragged {
                    let total = self.line_indexer.total_lines() as i64;
                    let upper = (total - 1).max(0);
                    let dragged_line =
                        (actual_offset / line_height).round() as i64;
                    self.scroll_line = dragged_line.clamp(0, upper) as usize;
                    self.wheel_accum = 0.0;
                }

                // 保底:把渲染实际选用的顶行写回 `scroll_line`,让状态栏
                // "Line: N" 这种 UI 反映真实显示内容。
                // 滚动条拖拽时跳过——否则会覆盖刚检测到的拖拽目标行。
                if !scrollbar_dragged {
                    if let Some(first_row) = first_visible_row {
                        self.scroll_line = first_row;
                    }
                }
            } else {
                ui.centered_and_justified(|ui| {
                    ui.vertical_centered(|ui| {
                        ui.add_space(80.0);
                        ui.label(
                            egui::RichText::new("西瓜污点分析")
                                .size(36.0)
                                .strong()
                                .color(egui::Color32::WHITE),
                        );
                        ui.add_space(12.0);
                        ui.label(
                            egui::RichText::new(
                                "点击 文件 → 打开,或直接拖入一个文本 / trace 文件",
                            )
                            .size(14.0)
                            .color(egui::Color32::from_rgb(200, 200, 200)),
                        );
                    });
                });
            }
        });
    }

    fn render_encoding_selector(&mut self, ctx: &egui::Context) {
        if self.show_encoding_selector {
            egui::Window::new("Select Encoding")
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    for (name, encoding) in available_encodings() {
                        if ui
                            .selectable_label(std::ptr::eq(self.selected_encoding, encoding), name)
                            .clicked()
                        {
                            self.selected_encoding = encoding;

                            // Reload file with new encoding
                            if let Some(ref reader) = self.file_reader {
                                let path = reader.path().clone();
                                self.open_file(path);
                            }

                            self.show_encoding_selector = false;
                        }
                    }

                    if ui.button("Cancel").clicked() {
                        self.show_encoding_selector = false;
                    }
                });
        }
    }

    /// 010-Editor-style floating list of search hits. Shows the matches in
    /// the current search page with a one-line preview; double-click jumps
    /// there. Uses the existing paged `search_results` so huge result sets
    /// remain memory-bounded.
    fn render_search_list_window(&mut self, ctx: &egui::Context) {
        if !self.show_search_list {
            return;
        }
        use crate::taint::DockSide;
        use egui_extras::{Column, TableBuilder};

        let Some(reader) = self.file_reader.clone() else {
            return;
        };
        let total = self.total_search_results;
        let page_start = self.search_page_start_index;
        let rows_count = self.search_results.len();
        let current_global = self.current_result_index;

        // Incremental preview cache:
        //  * on page-index or query change → full clear (stale previews)
        //  * on rows_count growth (Find-All streaming in new chunks) → only
        //    compute previews for byte_offsets that aren't cached yet
        // Net: each preview is computed at most once for its lifetime in the
        // panel — O(n) total work, instead of O(n²) when rebuilt every chunk.
        let page_or_query_changed = match &self.search_preview_cache_key {
            Some((pstart, _, q)) => *pstart != page_start || *q != self.search_query,
            None => true,
        };
        if page_or_query_changed {
            self.search_preview_cache.clear();
            self.search_preview_cache.reserve(rows_count);
            self.search_line_cache.clear();
            self.search_line_cache.reserve(rows_count);
        }
        if page_or_query_changed
            || self.search_preview_cache.len() < rows_count
        {
            // Same cache-build pass for both preview strings and line
            // numbers. Keep them side-by-side so the check at the top of
            // the frame covers both — otherwise each visible row would
            // re-run the sparse-index newline scan and block the UI
            // enough that the Ctrl+F TextEdit drops keystrokes.
            for r in &self.search_results {
                self.search_preview_cache
                    .entry(r.byte_offset)
                    .or_insert_with(|| preview_for_match(&reader, r));
                if let std::collections::hash_map::Entry::Vacant(e) =
                    self.search_line_cache.entry(r.byte_offset)
                {
                    e.insert(self.line_indexer.find_line_at_offset(r.byte_offset, &reader));
                }
            }
            self.search_preview_cache_key =
                Some((page_start, rows_count, self.search_query.clone()));
        }

        let mut jump_global_idx: Option<usize> = None;
        let mut close_clicked = false;
        let mut dock_side = self.search_list_dock;

        let body = |ui: &mut egui::Ui| {
            // Header: title + counts + dock switch + close
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("🔎 搜索结果列表")
                        .size(13.0)
                        .strong()
                        .color(egui::Color32::from_rgb(255, 210, 100)),
                );
                ui.separator();
                ui.label(
                    egui::RichText::new("停靠")
                        .size(11.0)
                        .color(egui::Color32::from_rgb(150, 150, 150)),
                );
                let mut dock_btn = |ui: &mut egui::Ui, label: &str, side: DockSide, tip: &str| {
                    let selected = dock_side == side;
                    let btn = egui::Button::new(
                        egui::RichText::new(label)
                            .size(14.0)
                            .color(if selected {
                                egui::Color32::BLACK
                            } else {
                                egui::Color32::from_rgb(210, 210, 210)
                            }),
                    )
                    .fill(if selected {
                        egui::Color32::from_rgb(255, 210, 100)
                    } else {
                        egui::Color32::TRANSPARENT
                    })
                    .min_size(egui::vec2(26.0, 22.0));
                    if ui.add(btn).on_hover_text(tip).clicked() {
                        dock_side = side;
                    }
                };
                dock_btn(ui, "⬅", DockSide::Left, "停靠到左侧");
                dock_btn(ui, "⬇", DockSide::Bottom, "停靠到底部");
                dock_btn(ui, "➡", DockSide::Right, "停靠到右侧");
                ui.separator();
                if ui
                    .add(egui::Button::new(egui::RichText::new("✖ 关闭").size(12.0)))
                    .on_hover_text("关闭面板(菜单可重新打开,Ctrl+L)")
                    .clicked()
                {
                    close_clicked = true;
                }
            });
            ui.separator();
                if total == 0 {
                    ui.label(
                        egui::RichText::new("暂无搜索结果,先按 Ctrl+F 搜索一下")
                            .color(egui::Color32::from_rgb(150, 150, 150))
                            .italics(),
                    );
                    return;
                }

                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new(format!(
                            "当前页 {} 条 · 全局共 {} 条",
                            rows_count, total
                        ))
                        .size(12.0)
                        .color(egui::Color32::from_rgb(200, 200, 200)),
                    );
                    ui.separator();
                    ui.label(
                        egui::RichText::new(format!(
                            "显示全局索引 [{}..{})",
                            page_start,
                            page_start + rows_count
                        ))
                        .size(11.0)
                        .color(egui::Color32::from_rgb(150, 150, 150)),
                    );
                });
                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new(
                        "提示:双击一行跳转。翻页用搜索工具栏的 ← / → 按钮(每页 1000 条)",
                    )
                    .size(11.0)
                    .color(egui::Color32::from_rgb(150, 150, 150)),
                );
                ui.separator();

                let text_h = ui.text_style_height(&egui::TextStyle::Monospace);
                let row_h = text_h + 6.0;

                TableBuilder::new(ui)
                    .striped(true)
                    .resizable(true)
                    // Give rows (not individual labels) click sense so
                    // TextEdit focus elsewhere isn't stolen by cell labels.
                    .sense(egui::Sense::click())
                    .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                    .column(Column::initial(60.0).at_least(40.0))
                    .column(Column::initial(90.0).at_least(60.0))
                    .column(Column::initial(130.0).at_least(80.0))
                    .column(Column::remainder().at_least(200.0))
                    .header(22.0, |mut header| {
                        let hfmt = |s: &str| {
                            egui::RichText::new(s)
                                .size(12.0)
                                .strong()
                                .color(egui::Color32::from_rgb(210, 210, 210))
                        };
                        header.col(|ui| {
                            ui.label(hfmt("#"));
                        });
                        header.col(|ui| {
                            ui.label(hfmt("行号"));
                        });
                        header.col(|ui| {
                            ui.label(hfmt("字节偏移"));
                        });
                        header.col(|ui| {
                            ui.label(hfmt("预览"));
                        });
                    })
                    .body(|body| {
                        body.rows(row_h, rows_count, |mut row| {
                            let local_i = row.index();
                            let result = &self.search_results[local_i];
                            let global_idx = page_start + local_i;
                            let is_current = global_idx == current_global;
                            row.set_selected(is_current);

                            // O(1) cached lookup — the per-page cache above
                            // populated this entry during the frame's build
                            // pass. Avoids sparse-index scans per row.
                            let viewer_line = self
                                .search_line_cache
                                .get(&result.byte_offset)
                                .copied()
                                .unwrap_or(0);

                            // O(1) cached lookup (built once per page above).
                            let preview = self
                                .search_preview_cache
                                .get(&result.byte_offset)
                                .cloned()
                                .unwrap_or_default();

                            let idx_color = if is_current {
                                egui::Color32::from_rgb(255, 210, 100)
                            } else {
                                egui::Color32::from_rgb(180, 180, 180)
                            };
                            let line_color = egui::Color32::from_rgb(255, 210, 120);
                            let off_color = egui::Color32::from_rgb(160, 200, 240);
                            let prev_color = egui::Color32::from_rgb(225, 225, 225);

                            // Cells are plain labels with no Sense — the row's
                            // interact rect (enabled by .sense(click) on
                            // TableBuilder) is what captures click events.
                            row.col(|ui| {
                                ui.add(
                                    egui::Label::new(
                                        egui::RichText::new(format!("{}", global_idx + 1))
                                            .monospace()
                                            .size(12.0)
                                            .color(idx_color),
                                    )
                                    .selectable(false),
                                );
                            });
                            row.col(|ui| {
                                ui.add(
                                    egui::Label::new(
                                        egui::RichText::new(format!("{}", viewer_line + 1))
                                            .monospace()
                                            .size(12.0)
                                            .color(line_color),
                                    )
                                    .selectable(false),
                                );
                            });
                            row.col(|ui| {
                                ui.add(
                                    egui::Label::new(
                                        egui::RichText::new(format!("0x{:x}", result.byte_offset))
                                            .monospace()
                                            .size(12.0)
                                            .color(off_color),
                                    )
                                    .selectable(false),
                                );
                            });
                            row.col(|ui| {
                                ui.add(
                                    egui::Label::new(
                                        egui::RichText::new(&preview)
                                            .monospace()
                                            .size(12.0)
                                            .color(prev_color),
                                    )
                                    .selectable(false)
                                    .truncate(),
                                );
                            });

                            let row_resp = row.response().on_hover_text(&preview);
                            if row_resp.double_clicked() {
                                jump_global_idx = Some(global_idx);
                            }
                        });
                    });
        };

        // 内层 `ScrollArea` 是面板宽度稳定的关键,不是样式。
        // 详见 `src/taint.rs` 对应位置的注释 —— 同一套机制。
        // 简述:egui SidePanel 的 rect 会被内容 min_rect 反推,内容宽度
        // 随帧波动(预览字符串长度、列宽变化、行数变化)会让面板抖动,
        // 连带导致 TextEdit 事件路由间歇失效。ScrollArea 的 outer rect
        // 由 allocation 而非 content 决定,正好截断这条传播链。
        // `auto_shrink([false, false])` 防止内容少时反向缩小。
        match self.search_list_dock {
            DockSide::Right => {
                egui::SidePanel::right("search_list_right")
                    .resizable(true)
                    .default_width(360.0)
                    .min_width(240.0)
                    .show(ctx, |ui| {
                        egui::ScrollArea::horizontal()
                            .auto_shrink([false, false])
                            .show(ui, body);
                    });
            }
            DockSide::Left => {
                egui::SidePanel::left("search_list_left")
                    .resizable(true)
                    .default_width(360.0)
                    .min_width(240.0)
                    .show(ctx, |ui| {
                        egui::ScrollArea::horizontal()
                            .auto_shrink([false, false])
                            .show(ui, body);
                    });
            }
            DockSide::Bottom => {
                egui::TopBottomPanel::bottom("search_list_bottom")
                    .resizable(true)
                    .default_height(150.0)
                    .min_height(80.0)
                    .show(ctx, |ui| {
                        egui::ScrollArea::vertical()
                            .auto_shrink([false, false])
                            .show(ui, body);
                    });
            }
        }
        self.search_list_dock = dock_side;
        if close_clicked {
            self.show_search_list = false;
        }

        if let Some(global_idx) = jump_global_idx {
            // Jump only works within the currently loaded page — which is the
            // only thing the list actually shows anyway.
            if global_idx >= page_start && global_idx < page_start + rows_count {
                let local = global_idx - page_start;
                let result = &self.search_results[local];
                let target_line = self.line_at(result.byte_offset);
                self.current_result_index = global_idx;
                self.scroll_to_row_centered(target_line);
            }
        }
    }

    fn render_file_info(&mut self, ctx: &egui::Context) {
        if self.show_file_info {
            if let Some(ref reader) = self.file_reader {
                egui::Window::new("File Information")
                    .collapsible(false)
                    .resizable(false)
                    .show(ctx, |ui| {
                        ui.label(format!("Path: {}", reader.path().display()));
                        ui.label(format!(
                            "Size: {} bytes ({:.2} MB)",
                            reader.len(),
                            reader.len() as f64 / 1_000_000.0
                        ));
                        ui.label(format!("Lines: ~{}", self.line_indexer.total_lines()));
                        ui.label(format!("Encoding: {}", reader.encoding().name()));

                        if ui.button("Close").clicked() {
                            self.show_file_info = false;
                        }
                    });
            }
        }
    }
}

impl eframe::App for TextViewerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // ---- Drag-and-drop file loading -----------------------------------
        // Grab any files released this frame. When multiple files are dropped
        // we only load the first one — the viewer is single-file at a time.
        let dropped: Vec<PathBuf> = ctx.input(|i| {
            i.raw
                .dropped_files
                .iter()
                .filter_map(|f| f.path.clone())
                .collect()
        });
        if let Some(path) = dropped.into_iter().next() {
            self.load_file_with_auto_encoding(path);
        }

        if let Some(start_time) = self.open_start_time {
            let elapsed = start_time.elapsed();
            println!("File opened and first frame rendered in: {:.2?}", elapsed);
            self.status_message = format!("{} (Rendered in {:.2?})", self.status_message, elapsed);
            self.open_start_time = None;
        }

        // Update window title
        let title = if self.unsaved_changes {
            "西瓜污点分析 *"
        } else {
            "西瓜污点分析"
        };
        ctx.send_viewport_cmd(egui::ViewportCommand::Title(title.to_string()));

        // Handle keyboard shortcuts
        if ctx.input_mut(|i| i.consume_key(egui::Modifiers::CTRL, egui::Key::S)) {
            self.save_file();
        }
        if ctx.input_mut(|i| i.consume_key(egui::Modifiers::CTRL, egui::Key::R)) {
            self.show_search_bar = true;
            self.show_replace = !self.show_replace;
        }
        if ctx.input_mut(|i| i.consume_key(egui::Modifiers::CTRL, egui::Key::F)) {
            self.show_search_bar = !self.show_search_bar;
            if self.show_search_bar {
                self.focus_search_input = true;
            }
        }
        if ctx.input_mut(|i| i.consume_key(egui::Modifiers::CTRL, egui::Key::L)) {
            self.show_search_list = !self.show_search_list;
        }

        // Set theme
        if self.dark_mode {
            ctx.set_visuals(egui::Visuals::dark());
        } else {
            ctx.set_visuals(egui::Visuals::light());
        }

        // Check for file changes in tail mode
        if self.tail_mode {
            self.check_file_changes();
            ctx.request_repaint(); // Keep refreshing
        }

        self.poll_search_results();
        self.poll_replace_results();
        if self.taint.poll() || self.taint.running {
            // ~20 fps is plenty to animate the spinner / status text; a full
            // 60 fps repaint loop while a background job runs eats CPU and
            // makes every other widget feel sluggish.
            ctx.request_repaint_after(std::time::Duration::from_millis(50));
        }

        // 推进后台异步索引:把 worker 线程发来的消息吃掉。
        // 建索引期间查询走估算路径,所以希望 Exact 消息一到就切精确
        // 模式。`poll()` 本身 O(1),返回 true 意味着 Exact 本帧刚到
        // → 重绘一次刷新可见面板里的行号缓存。`is_indexing()` 为 true
        // 时 100ms 请求一次重绘,不至于漏掉 Exact 的到达。
        if self.line_indexer.poll() {
            ctx.request_repaint();
        } else if self.line_indexer.is_indexing() {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }

        if self.search_in_progress || self.replace_in_progress {
            ctx.request_repaint_after(std::time::Duration::from_millis(50));
        }

        self.render_menu_bar(ctx);
        self.render_toolbar(ctx);
        self.render_status_bar(ctx);
        // All dockable SidePanel / TopBottomPanel must be declared BEFORE the
        // CentralPanel (render_text_area), otherwise egui can't subtract their
        // space and the bottom panel ends up overlapping the text area.
        if let Some(offset) = crate::taint::render_panel(ctx, &mut self.taint) {
            // `line_at` resolves exactly even in sparse mode — the panel's
            // line number and the viewer row we scroll to now agree.
            let row = self.line_at(offset as usize);
            self.scroll_to_row_centered(row);
        }
        self.render_search_list_window(ctx);
        self.render_text_area(ctx);
        crate::taint::render_dialog(ctx, &mut self.taint, self.file_reader.as_ref());
        self.render_encoding_selector(ctx);
        self.render_file_info(ctx);

        // Drop-zone overlay: when the OS reports files being dragged over the
        // window, dim the screen and show an instruction. Painted last so it
        // sits above every panel.
        let hovered = ctx.input(|i| i.raw.hovered_files.len());
        if hovered > 0 {
            let screen = ctx.screen_rect();
            let painter = ctx.layer_painter(egui::LayerId::new(
                egui::Order::Foreground,
                egui::Id::new("drop_zone_overlay"),
            ));
            painter.rect_filled(screen, 0.0, egui::Color32::from_black_alpha(180));
            let label = if hovered == 1 {
                "📂  松开以加载该文件".to_string()
            } else {
                format!("📂  松开以加载第 1 个文件(共拖入 {})", hovered)
            };
            painter.text(
                screen.center(),
                egui::Align2::CENTER_CENTER,
                label,
                egui::FontId::proportional(28.0),
                egui::Color32::from_rgb(255, 220, 120),
            );
            // Sub-hint
            painter.text(
                screen.center() + egui::vec2(0.0, 36.0),
                egui::Align2::CENTER_CENTER,
                "(自动检测编码)",
                egui::FontId::proportional(13.0),
                egui::Color32::from_rgb(200, 200, 200),
            );
            ctx.request_repaint();
        }
    }
}

/// One-line preview of a match (~32 bytes before, ~128 bytes after, trimmed
/// to the current line, tabs/whitespace collapsed).
/// Extract the word (alphanumeric + underscore) surrounding character index
/// `char_idx` in `text`. Returns an empty string if the index falls on a
/// non-word character or is out of bounds.
fn extract_word_at(text: &str, char_idx: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    if char_idx >= chars.len() || !is_word_char(chars[char_idx]) {
        return String::new();
    }
    let mut start = char_idx;
    while start > 0 && is_word_char(chars[start - 1]) {
        start -= 1;
    }
    let mut end = char_idx;
    while end + 1 < chars.len() && is_word_char(chars[end + 1]) {
        end += 1;
    }
    chars[start..=end].iter().collect()
}

fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn preview_for_match(reader: &FileReader, m: &SearchResult) -> String {
    const BEFORE: usize = 32;
    const AFTER: usize = 128;
    let start = m.byte_offset.saturating_sub(BEFORE);
    let end = (m.byte_offset + m.match_len + AFTER).min(reader.len());
    if start >= end {
        return String::new();
    }
    let chunk = reader.get_chunk(start, end);
    let left = m.byte_offset - start;
    let split = left.min(chunk.len());
    let (prefix, suffix) = chunk.split_at(split);
    let prefix = match prefix.rfind('\n') {
        Some(p) => &prefix[p + 1..],
        None => prefix,
    };
    let suffix = match suffix.find('\n') {
        Some(p) => &suffix[..p],
        None => suffix,
    };
    let mut line: String = prefix.to_string();
    line.push_str(suffix);
    let mut out = String::with_capacity(line.len());
    let mut prev_space = false;
    for c in line.chars() {
        let c = if c == '\t' { ' ' } else { c };
        if c == ' ' {
            if !prev_space {
                out.push(' ');
            }
            prev_space = true;
        } else {
            out.push(c);
            prev_space = false;
        }
    }
    out.trim().to_string()
}
