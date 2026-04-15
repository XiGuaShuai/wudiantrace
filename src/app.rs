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

    // Programmatic scroll control
    scroll_to_row: Option<usize>,
    // Correction for f32 scroll precision issues in large files
    scroll_correction: i64,
    pending_scroll_target: Option<usize>,
    last_scroll_offset: f32,

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

    // Search results list panel (010-Editor-style)
    show_search_list: bool,
    search_list_dock: crate::taint::DockSide,
    /// Per-page preview cache. Computing a 160-byte preview + UTF-8 decode for
    /// every visible row every frame dropped UI FPS noticeably; caching the
    /// strings for as long as the search page doesn't change is O(page_size)
    /// once and O(1) per frame.
    search_preview_cache: HashMap<usize, String>,
    /// Same deal for the "line number" column: `LineIndexer::find_line_at_offset`
    /// scans up to one checkpoint interval (≤10 MB) in sparse mode, so doing
    /// it per visible row per frame previously blocked the UI hard enough
    /// that keystrokes to the Ctrl+F search box stopped registering.
    search_line_cache: HashMap<usize, usize>,
    /// Identity of the page currently cached — (page_start_index, page_len,
    /// query string). When any of these differ from the live state we rebuild.
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
            scroll_correction: 0,
            pending_scroll_target: None,
            last_scroll_offset: 0.0,
            unsaved_changes: false,
            pending_replacements: Vec::new(),
            open_start_time: None,
            search_count_start_time: None,
            taint: TaintState::default(),
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

    /// Sparse-aware wrapper for `LineIndexer::find_line_at_offset`. The
    /// underlying sparse path needs the raw bytes to scan newlines between
    /// a checkpoint and the query offset; we always hold them in
    /// `file_reader` during any code path that operates on byte offsets
    /// (searching, taint jumping, etc.), so the `expect` below is a
    /// precondition, not a guess.
    fn line_at(&self, offset: usize) -> usize {
        let reader = self
            .file_reader
            .as_ref()
            .expect("file must be loaded before resolving a line number");
        self.line_indexer.find_line_at_offset(offset, reader)
    }

    fn open_file(&mut self, path: PathBuf) {
        self.open_start_time = Some(std::time::Instant::now());
        match FileReader::new(path.clone(), self.selected_encoding) {
            Ok(reader) => {
                self.file_reader = Some(Arc::new(reader));
                self.line_indexer
                    .index_file(self.file_reader.as_ref().unwrap());
                self.scroll_line = 0;
                self.scroll_to_row = Some(0); // Reset scroll to top for new file
                self.status_message = format!("Opened: {}", path.display());
                self.search_engine.clear();
                self.search_results.clear();
                self.total_search_results = 0;
                self.search_page_start_index = 0;
                self.page_offsets.clear();
                self.current_result_index = 0;

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

        let cancel_token = Arc::new(AtomicBool::new(false));
        self.search_cancellation_token = Some(cancel_token.clone());

        self.status_message = if find_all {
            "Searching all matches...".to_string()
        } else {
            "Searching first match...".to_string()
        };

        if find_all {
            self.search_count_start_time = Some(std::time::Instant::now());
            // Start two tasks:
            // 1. Count all matches (parallel)
            // 2. Fetch first page of matches (sequential/chunked)

            let tx_count = tx.clone();
            let reader_count = reader.clone();
            let query = self.search_query.clone();
            let use_regex = self.use_regex;
            let case_sensitive = self.case_sensitive;
            let cancel_token_count = cancel_token.clone();

            std::thread::spawn(move || {
                // Task 1: Count
                let mut engine = SearchEngine::new();
                engine.set_query(query, use_regex, case_sensitive);
                engine.count_matches(reader_count, tx_count, cancel_token_count);
            });

            let tx_fetch = tx.clone();
            let reader_fetch = reader.clone();
            let query_fetch = self.search_query.clone();
            let cancel_token_fetch = cancel_token.clone();

            std::thread::spawn(move || {
                // Task 2: Fetch first page
                let mut engine = SearchEngine::new();
                engine.set_query(query_fetch, use_regex, case_sensitive);
                engine.fetch_matches(reader_fetch, tx_fetch, 0, 1000, cancel_token_fetch);
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

                    // Ensure we scroll to the first result if we haven't yet
                    if self.scroll_to_row.is_none() && !self.search_results.is_empty() {
                        let target_line = self.line_at(self.search_results[0].byte_offset);
                        self.scroll_line = target_line;
                        self.scroll_to_row = Some(target_line);
                    }
                } else {
                    self.status_message = "No matches found".to_string();
                }
            }

            if new_results_added {
                // Sort results by byte offset to keep them in order
                // Only sort once per frame after processing all available chunks
                self.search_results.sort_by_key(|r| r.byte_offset);

                // Check for scroll update after sort
                if self.scroll_to_row.is_none()
                    && !self.search_results.is_empty()
                    && self.current_result_index == 0
                {
                    let target_line = self.line_at(self.search_results[0].byte_offset);
                    self.scroll_line = target_line;
                    self.scroll_to_row = Some(target_line);
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

        let match_info = self.search_results[local_index].clone();

        // Queue the replacement
        self.pending_replacements.push(PendingReplacement {
            offset: match_info.byte_offset,
            old_len: match_info.match_len,
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
            .set_file_name(input_path.file_name().unwrap().to_string_lossy())
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

        // Ask for output file
        if let Some(output_path) = rfd::FileDialog::new()
            .set_file_name(format!(
                "{}.modified",
                input_path.file_name().unwrap().to_string_lossy()
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
            self.scroll_line = target_line;
            self.scroll_to_row = Some(target_line);
            self.pending_scroll_target = Some(target_line);
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
            self.scroll_line = target_line;
            self.scroll_to_row = Some(target_line);
            self.pending_scroll_target = Some(target_line);
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
                                                // Show a few lines of context above the target line for better orientation
                self.scroll_line = target_line.saturating_sub(3);
                self.scroll_to_row = Some(target_line);
                self.pending_scroll_target = Some(target_line);
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
                    ui.label(format!("Lines: ~{}", self.line_indexer.total_lines()));
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

                // Apply programmatic scroll if requested
                let mut programmatic_scroll = false;
                if let Some(target_row) = self.scroll_to_row.take() {
                    scroll_area =
                        scroll_area.vertical_scroll_offset(target_row as f32 * line_height);
                    programmatic_scroll = true;
                }

                let mut first_visible_row = None;

                let output = scroll_area.show_rows(
                    ui,
                    line_height,
                    self.line_indexer.total_lines(),
                    |ui, row_range| {
                        // Calculate scroll correction if we just jumped
                        if let Some(target) = self.pending_scroll_target.take() {
                            self.scroll_correction = target as i64 - row_range.start as i64;
                        }

                        // Apply correction to find the actual start line we want to render
                        let corrected_start_line =
                            (row_range.start as i64 + self.scroll_correction).max(0) as usize;

                        // Capture the first visible row (corrected)
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
                            let mut line_matches: Vec<(usize, usize, bool)> = Vec::new();

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
                                    line_matches.push((m_start, m_end, is_selected));
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

                                    line_matches.push((rel_start, rel_end, is_selected));
                                }
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

                                    for (abs_start, abs_end, is_selected) in line_matches.iter() {
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
                                        job.append(
                                            &line_text[*abs_start..match_end],
                                            0.0,
                                            egui::TextFormat {
                                                font_id: egui::FontId::monospace(self.font_size),
                                                color: egui::Color32::BLACK,
                                                background: if *is_selected {
                                                    egui::Color32::from_rgb(255, 200, 0)
                                                // orange-ish for current match
                                                } else {
                                                    egui::Color32::YELLOW
                                                },
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
                                        let targets = crate::taint::collect_targets(tl);
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

                // Check for manual scroll
                let current_offset = output.state.offset.y;
                if !programmatic_scroll && (current_offset - self.last_scroll_offset).abs() > 1.0 {
                    // Manual scroll detected (drag or wheel)
                    // Reset correction as user is establishing new position
                    self.scroll_correction = 0;
                }
                self.last_scroll_offset = current_offset;

                // Update scroll_line to match what was actually displayed
                if let Some(first_row) = first_visible_row {
                    self.scroll_line = first_row;
                }
            } else {
                ui.centered_and_justified(|ui| {
                    ui.heading("Large Text Viewer");
                    ui.label("\nClick File → Open to load a text file");
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

        // The inner `ScrollArea` is load-bearing, not cosmetic: egui's panel
        // persists `inner_response.response.rect` as the panel's new size
        // every frame, so content whose `min_rect` varies (long preview
        // strings, wide columns, changing row count) would make the panel
        // oscillate. A ScrollArea's outer rect is driven by its *allocation*
        // not its inner content (egui `scroll_area.rs:553`), so it cleanly
        // absorbs those variations. `auto_shrink([false, false])` keeps the
        // scroll area filling the panel even when content is small.
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
                self.scroll_line = target_line;
                self.scroll_to_row = Some(target_line);
                self.pending_scroll_target = Some(target_line);
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
            "Large Text Viewer *"
        } else {
            "Large Text Viewer"
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
            self.scroll_to_row = Some(row);
            self.pending_scroll_target = Some(row);
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
