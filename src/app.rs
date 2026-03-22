use crate::mcp_install::{
    detect_any_global_mcp, detect_supported_client_names, install_to_detected_clients,
    preferred_global_config_paths, remove_from_detected_clients,
};
use arm64_taint_core::{
    trace_backward_streaming, BackwardTaintOptions, BackwardTaintReport, BackwardTaintRequest,
    Confidence, DataFlowNode, EdgeReason, StreamingTrace, TargetKind,
};
use eframe::egui;
use encoding_rs::Encoding;
use notify::{RecursiveMode, Result as NotifyResult, Watcher};
use regex::Regex;
use serde_json::{Map, Value, json};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::sync::OnceLock;

use content_search_core::file_reader::{available_encodings, detect_encoding, FileReader};
use content_search_core::line_indexer::{
    IndexBuildReport, IndexCacheStatus, IndexMode, LineIndexer,
};
use content_search_core::replacer::{ReplaceMessage, Replacer};
use content_search_core::search_engine::{SearchEngine, SearchMessage, SearchResult, SearchType};

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
    ui_language: UiLanguage,

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
    last_index_report: Option<IndexBuildReport>,

    // Tail mode
    tail_mode: bool,
    watcher: Option<Box<dyn Watcher>>,
    file_change_rx: Option<Receiver<()>>,

    // Status messages
    status_message: String,
    mcp_status_message: Option<String>,

    // Encoding
    selected_encoding: &'static Encoding,
    show_encoding_selector: bool,

    // Programmatic scroll control
    scroll_to_row: Option<usize>,

    // Focus control
    focus_search_input: bool,

    // Unsaved changes
    unsaved_changes: bool,
    pending_replacements: Vec<PendingReplacement>,

    // Performance measurement
    open_start_time: Option<std::time::Instant>,
    search_count_start_time: Option<std::time::Instant>,

    // Taint UI
    taint_target_mode: TaintTargetMode,
    taint_line_input: String,
    taint_reg_input: String,
    taint_mem_input: String,
    taint_bit_lo_input: String,
    taint_bit_hi_input: String,
    taint_depth_input: String,
    taint_output_limit_input: String,
    taint_prune_equal_value_loads: bool,
    taint_in_progress: bool,
    taint_message_rx: Option<Receiver<TaintUiMessage>>,
    taint_report: Option<BackwardTaintReport>,
    taint_error: Option<String>,
    taint_selected_line: Option<usize>,
    taint_hover_target: Option<TaintSelectionTarget>,
    taint_last_target: Option<TaintSelectionTarget>,
    mcp_enabled: bool,
    mcp_detected_clients: Vec<String>,
}

#[derive(Clone)]
struct PendingReplacement {
    offset: usize,
    old_len: usize,
    new_text: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TaintTargetMode {
    Reg,
    Mem,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum UiLanguage {
    English,
    Chinese,
}

fn tr_lang<'a>(lang: UiLanguage, en: &'a str, zh: &'a str) -> &'a str {
    match lang {
        UiLanguage::English => en,
        UiLanguage::Chinese => zh,
    }
}

const MCP_SERVER_NAME: &str = "taint-rev-trace";

#[derive(Clone)]
struct McpLaunchSpec {
    command: String,
    args: Vec<String>,
}

#[derive(Clone)]
#[allow(dead_code)]
struct McpConfigOutcome {
    path: PathBuf,
    method: &'static str,
}

enum TaintUiMessage {
    Done(BackwardTaintReport),
    Error(String),
}

#[derive(Clone)]
struct TaintCandidate {
    kind: TaintTargetMode,
    text: String,
}

#[derive(Clone)]
struct TaintCandidateMatch {
    candidate: TaintCandidate,
    start: usize,
    end: usize,
}

#[derive(Clone)]
struct TaintSelectionTarget {
    line_no: usize,
    candidate: TaintCandidate,
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
            ui_language: UiLanguage::English,
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
            last_index_report: None,
            tail_mode: false,
            watcher: None,
            file_change_rx: None,
            status_message: String::new(),
            mcp_status_message: None,
            selected_encoding: encoding_rs::UTF_8,
            show_encoding_selector: false,
            focus_search_input: false,
            scroll_to_row: None,
            unsaved_changes: false,
            pending_replacements: Vec::new(),
            open_start_time: None,
            search_count_start_time: None,
            taint_target_mode: TaintTargetMode::Reg,
            taint_line_input: String::new(),
            taint_reg_input: "x8".to_string(),
            taint_mem_input: String::new(),
            taint_bit_lo_input: "0".to_string(),
            taint_bit_hi_input: "31".to_string(),
            taint_depth_input: "64".to_string(),
            taint_output_limit_input: "10000".to_string(),
            taint_prune_equal_value_loads: true,
            taint_in_progress: false,
            taint_message_rx: None,
            taint_report: None,
            taint_error: None,
            taint_selected_line: None,
            taint_hover_target: None,
            taint_last_target: None,
            mcp_enabled: detect_global_mcp_enabled(),
            mcp_detected_clients: detect_supported_client_names(),
        }
    }
}

impl TextViewerApp {
    fn tr<'a>(&self, en: &'a str, zh: &'a str) -> &'a str {
        match self.ui_language {
            UiLanguage::English => en,
            UiLanguage::Chinese => zh,
        }
    }

    fn app_title(&self) -> &'static str {
        self.tr("Taint Rev Trace", "Taint Rev Trace")
    }

    fn app_title_unsaved(&self) -> &'static str {
        self.tr("Taint Rev Trace *", "Taint Rev Trace *")
    }

    fn workspace_root(&self) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    fn global_mcp_config_path(&self) -> Option<PathBuf> {
        vscode_user_mcp_config_path()
    }

    #[allow(dead_code)]
    fn mcp_config_path(&self) -> PathBuf {
        self.global_mcp_config_path()
            .unwrap_or_else(|| self.workspace_root().join(".vscode").join("mcp.json"))
    }

    fn trace_search_mcp_launch_spec(&self) -> McpLaunchSpec {
        let workspace_root = self.workspace_root();
        let executable_name = if cfg!(windows) {
            "trace-search-mcp.exe"
        } else {
            "trace-search-mcp"
        };

        for candidate in [
            workspace_root.join("target").join("debug").join(executable_name),
            workspace_root.join("target").join("release").join(executable_name),
        ] {
            if candidate.exists() {
                return McpLaunchSpec {
                    command: candidate.display().to_string(),
                    args: Vec::new(),
                };
            }
        }

        McpLaunchSpec {
            command: "cargo".to_string(),
            args: vec![
                "run".to_string(),
                "--manifest-path".to_string(),
                workspace_root.join("Cargo.toml").display().to_string(),
                "-p".to_string(),
                "arm64-taint-core".to_string(),
                "--bin".to_string(),
                "trace-search-mcp".to_string(),
            ],
        }
    }

    #[allow(dead_code)]
    fn set_mcp_enabled(&mut self, enabled: bool) {
        match update_workspace_mcp_config(&self.trace_search_mcp_launch_spec(), enabled) {
            Ok(path) => {
                self.mcp_enabled = enabled;
                self.mcp_status_message = Some(if enabled {
                    self.tr(
                        "Workspace MCP config enabled.",
                        "工作区 MCP 配置已启用。",
                    )
                    .to_string()
                } else {
                    self.tr(
                        "Workspace MCP config disabled.",
                        "工作区 MCP 配置已关闭。",
                    )
                    .to_string()
                });
                self.status_message = if enabled {
                    format!(
                        "{}: {}",
                        self.tr("MCP config written", "MCP 配置已写入"),
                        path.display()
                    )
                } else {
                    format!(
                        "{}: {}",
                        self.tr("MCP config updated", "MCP 配置已更新"),
                        path.display()
                    )
                };
            }
            Err(err) => {
                self.mcp_enabled = detect_workspace_mcp_enabled();
                self.mcp_status_message = Some(format!(
                    "{}: {}",
                    self.tr("MCP update failed", "MCP 更新失败"),
                    err
                ));
            }
        }
    }

    #[allow(dead_code)]
    fn configure_mcp_one_click(&mut self) {
        self.set_mcp_enabled(true);
    }

    fn set_global_mcp_enabled(&mut self, enabled: bool) {
        let launch = self.trace_search_mcp_launch_spec();
        let report = if enabled {
            install_to_detected_clients(MCP_SERVER_NAME, &launch.command, &launch.args)
        } else {
            remove_from_detected_clients(MCP_SERVER_NAME)
        };

        self.mcp_detected_clients = report.detected_clients.clone();
        self.mcp_enabled = detect_global_mcp_enabled();
        self.status_message = report.summary_text();
        self.mcp_status_message = Some(report.detail_text());

        if report.success_count() == 0 && report.has_errors() {
            self.mcp_status_message = Some(format!(
                "{}: {}",
                self.tr("MCP update failed", "MCP 更新失败"),
                report.detail_text()
            ));
        }
    }

    fn configure_global_mcp_one_click(&mut self) {
        self.set_global_mcp_enabled(true);
    }

    #[allow(dead_code)]
    fn render_global_mcp_section(&mut self, ui: &mut egui::Ui) {
        ui.strong(self.tr("MCP", "MCP"));
        let launch = self.trace_search_mcp_launch_spec();

        let mut enabled = self.mcp_enabled;
        if ui
            .checkbox(
                &mut enabled,
                self.tr(
                    "Enable global MCP install",
                    "启用全局 MCP 安装",
                ),
            )
            .changed()
        {
            self.set_global_mcp_enabled(enabled);
        }

        if ui
            .button(self.tr(
                "One-click Install To Detected Clients",
                "一键安装到已检测客户端",
            ))
            .clicked()
        {
            self.configure_global_mcp_one_click();
        }

        ui.small(self.tr(
            "This installs the MCP server into detected global IDE and CLI configs on this machine, not just this workspace.",
            "这会把 MCP 服务安装到这台机器上已检测到的 IDE 和 CLI 的全局配置里，而不只是当前工作区。",
        ));
        ui.small(self.tr(
            "It uses each client's global config or official CLI flow when available.",
            "它会优先使用各客户端自己的全局配置或官方 CLI 安装流程。",
        ));
        ui.small(format!(
            "{}: {}",
            self.tr("Detected Clients", "已检测客户端"),
            if self.mcp_detected_clients.is_empty() {
                self.tr("none", "无").to_string()
            } else {
                self.mcp_detected_clients.join(", ")
            }
        ));
        ui.small(format!(
            "{}: {}",
            self.tr("Primary Config Paths", "主要配置路径"),
            {
                let paths = preferred_global_config_paths();
                if paths.is_empty() {
                    self.tr("Unavailable on this platform", "当前平台不可用").to_string()
                } else {
                    paths
                        .into_iter()
                        .take(3)
                        .map(|path| path.display().to_string())
                        .collect::<Vec<_>>()
                        .join(" | ")
                }
            }
        ));
        ui.small(format!(
            "{}: {} {}",
            self.tr("Server Command", "服务命令"),
            launch.command,
            launch.args.join(" ")
        ));

        if let Some(message) = &self.mcp_status_message {
            ui.small(message);
        }
    }

    fn render_global_mcp_section_compact(&mut self, ui: &mut egui::Ui) {
        ui.strong(self.tr("MCP", "MCP"));

        let mut enabled = self.mcp_enabled;
        if ui
            .checkbox(
                &mut enabled,
                self.tr("Enable global MCP install", "启用全局 MCP 安装"),
            )
            .changed()
        {
            self.set_global_mcp_enabled(enabled);
        }

        if ui
            .button(self.tr(
                "One-click Install To Detected Clients",
                "一键安装到已检测客户端",
            ))
            .clicked()
        {
            self.configure_global_mcp_one_click();
        }
        ui.small(format!(
            "{}: {}",
            self.tr("Detected Clients", "已检测客户端"),
            if self.mcp_detected_clients.is_empty() {
                self.tr("none", "无").to_string()
            } else {
                self.mcp_detected_clients.join(", ")
            }
        ));

        if let Some(message) = &self.mcp_status_message {
            ui.small(message);
        }
    }

    #[allow(dead_code)]
    fn render_mcp_section(&mut self, ui: &mut egui::Ui) {
        let launch = self.trace_search_mcp_launch_spec();
        ui.strong(self.tr("MCP", "MCP"));
        let mut enabled = self.mcp_enabled;
        if ui
            .checkbox(
                &mut enabled,
                self.tr(
                    "Enable workspace MCP config",
                    "启用工作区 MCP 配置",
                ),
            )
            .changed()
        {
            self.set_mcp_enabled(enabled);
        }

        if ui
            .button(self.tr(
                "One-click Configure VS Code",
                "一键配置 VS Code MCP",
            ))
            .clicked()
        {
            self.configure_mcp_one_click();
        }

        ui.small(self.tr(
            "This writes or updates .vscode/mcp.json for the current workspace.",
            "这会为当前工作区写入或更新 .vscode/mcp.json。",
        ));
        ui.small(format!(
            "{}: {}",
            self.tr("Config Path", "配置路径"),
            self.mcp_config_path().display()
        ));
        ui.small(format!(
            "{}: {} {}",
            self.tr("Server Command", "服务命令"),
            launch.command,
            launch.args.join(" ")
        ));

        if let Some(message) = &self.mcp_status_message {
            ui.small(message);
        }
    }

    #[allow(dead_code)]
    fn format_status_opened(&self, path: &std::path::Path) -> String {
        match self.ui_language {
            UiLanguage::English => format!("Opened: {}", path.display()),
            UiLanguage::Chinese => format!("已打开: {}", path.display()),
        }
    }

    fn describe_index_mode(&self, mode: IndexMode) -> &'static str {
        match (self.ui_language, mode) {
            (UiLanguage::English, IndexMode::Full) => "full index",
            (UiLanguage::English, IndexMode::Sparse) => "sparse index",
            (UiLanguage::Chinese, IndexMode::Full) => "完整索引",
            (UiLanguage::Chinese, IndexMode::Sparse) => "稀疏索引",
        }
    }

    fn describe_index_cache_status(&self, status: IndexCacheStatus) -> &'static str {
        match (self.ui_language, status) {
            (UiLanguage::English, IndexCacheStatus::Hit) => "cache hit",
            (UiLanguage::English, IndexCacheStatus::MissStored) => "cache built",
            (UiLanguage::English, IndexCacheStatus::MissSkipped) => "cache unavailable",
            (UiLanguage::Chinese, IndexCacheStatus::Hit) => "缓存命中",
            (UiLanguage::Chinese, IndexCacheStatus::MissStored) => "已构建缓存",
            (UiLanguage::Chinese, IndexCacheStatus::MissSkipped) => "缓存不可用",
        }
    }

    fn format_status_opened_with_index(
        &self,
        path: &std::path::Path,
        report: &IndexBuildReport,
    ) -> String {
        match self.ui_language {
            UiLanguage::English => format!(
                "Opened: {} [{}; {}]",
                path.display(),
                self.describe_index_mode(report.mode),
                self.describe_index_cache_status(report.cache_status)
            ),
            UiLanguage::Chinese => format!(
                "已打开: {} [{}; {}]",
                path.display(),
                self.describe_index_mode(report.mode),
                self.describe_index_cache_status(report.cache_status)
            ),
        }
    }

    fn format_status_open_error(&self, err: &dyn std::fmt::Display) -> String {
        match self.ui_language {
            UiLanguage::English => format!("Error opening file: {}", err),
            UiLanguage::Chinese => format!("打开文件失败: {}", err),
        }
    }

    fn format_status_rendered(&self, base: &str, elapsed: std::time::Duration) -> String {
        match self.ui_language {
            UiLanguage::English => format!("{} (Rendered in {:.2?})", base, elapsed),
            UiLanguage::Chinese => format!("{} (渲染耗时 {:.2?})", base, elapsed),
        }
    }

    fn format_status_jumped_to_line(&self, line_num: usize) -> String {
        match self.ui_language {
            UiLanguage::English => format!("Jumped to line {}", line_num),
            UiLanguage::Chinese => format!("已跳转到第 {} 行", line_num),
        }
    }

    fn format_taint_success_status(&self, roots: usize, _chains: usize) -> String {
        match self.ui_language {
            UiLanguage::English => {
                format!("Backward taint complete: {} source(s)", roots)
            }
            UiLanguage::Chinese => format!("反向污点完成: {} 个数据源", roots),
        }
    }

    fn format_taint_failed_status(&self, err: &str) -> String {
        match self.ui_language {
            UiLanguage::English => format!("Backward taint failed: {}", err),
            UiLanguage::Chinese => format!("反向污点失败: {}", err),
        }
    }

    fn quick_token_target(&self) -> Option<TaintSelectionTarget> {
        self.taint_hover_target
            .clone()
            .or_else(|| self.taint_last_target.clone())
    }

    fn exact_line_for_offset(&self, offset: usize) -> usize {
        self.line_indexer
            .find_line_at_offset(offset, self.file_reader.as_deref())
    }

    fn request_scroll_to_line(&mut self, target_line: usize, context_lines: usize) {
        let top_line = target_line.saturating_sub(context_lines);
        self.scroll_line = top_line;
        self.scroll_to_row = Some(top_line);
    }

    fn jump_to_search_offset(&mut self, byte_offset: usize) {
        let target_line = self.exact_line_for_offset(byte_offset);
        self.request_scroll_to_line(target_line, 3);
    }

    fn seed_search_from_quick_target(&mut self) -> bool {
        let Some(target) = self.quick_token_target() else {
            return false;
        };

        self.search_query = target.candidate.text;
        self.show_search_bar = true;
        self.focus_search_input = true;
        self.status_message = match self.ui_language {
            UiLanguage::English => format!("Search target set to {}", self.search_query),
            UiLanguage::Chinese => format!("搜索目标已设为 {}", self.search_query),
        };
        true
    }

    fn cancel_search(&mut self) {
        if let Some(token) = &self.search_cancellation_token {
            token.store(true, Ordering::Relaxed);
        }
        self.search_in_progress = false;
        self.search_message_rx = None;
        self.status_message = self
            .tr("Search stopped by user", "搜索已由用户停止")
            .to_string();
    }

    fn open_file(&mut self, path: PathBuf) {
        self.open_start_time = Some(std::time::Instant::now());
        match FileReader::new(path.clone(), self.selected_encoding) {
            Ok(reader) => {
                self.file_reader = Some(Arc::new(reader));
                let index_report = self
                    .line_indexer
                    .index_file_cached(self.file_reader.as_ref().unwrap());
                self.last_index_report = Some(index_report.clone());
                self.scroll_line = 0;
                self.scroll_to_row = Some(0); // Reset scroll to top for new file
                self.status_message =
                    self.format_status_opened_with_index(&path, &index_report);
                self.search_engine.clear();
                self.search_results.clear();
                self.total_search_results = 0;
                self.search_page_start_index = 0;
                self.page_offsets.clear();
                self.current_result_index = 0;
                self.taint_report = None;
                self.taint_error = None;
                self.taint_selected_line = None;
                self.taint_hover_target = None;
                self.taint_last_target = None;
                if self.taint_line_input.is_empty() {
                    self.taint_line_input = "1".to_string();
                }

                // Setup file watcher if tail mode is enabled
                if self.tail_mode {
                    self.setup_file_watcher();
                }
            }
            Err(e) => {
                self.status_message = self.format_status_open_error(&e);
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
            self.status_message = self.tr("Search already running...", "搜索已在进行中...").to_string();
            return;
        }

        let Some(ref reader) = self.file_reader else {
            self.status_message = self.tr("Open a file before searching", "请先打开文件再搜索").to_string();
            return;
        };

        if self.search_query.is_empty() {
            self.status_message = self.tr("Enter a search query first", "请先输入搜索内容").to_string();
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
            self.tr("Searching all matches...", "正在搜索全部匹配项...").to_string()
        } else {
            self.tr("Searching first match...", "正在搜索首个匹配项...").to_string()
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
                            self.status_message = match self.ui_language {
                                UiLanguage::English => {
                                    format!("Found {} matches...", self.total_search_results)
                                }
                                UiLanguage::Chinese => {
                                    format!("已找到 {} 个匹配项...", self.total_search_results)
                                }
                            };
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
                                    self.status_message = match self.ui_language {
                                        UiLanguage::English => {
                                            format!("{} (Counted in {:.2?})", self.status_message, elapsed)
                                        }
                                        UiLanguage::Chinese => {
                                            format!("{} (计数耗时 {:.2?})", self.status_message, elapsed)
                                        }
                                    };
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
                        self.status_message = match self.ui_language {
                            UiLanguage::English => format!("Search failed: {}", e),
                            UiLanguage::Chinese => format!("搜索失败: {}", e),
                        };
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
                        self.status_message = match self.ui_language {
                            UiLanguage::English => format!("Found {} matches", total),
                            UiLanguage::Chinese => format!("找到 {} 个匹配项", total),
                        };
                    } else {
                        self.status_message = self
                            .tr(
                                "Showing first match. Run Find All to see every result.",
                                "当前仅显示首个匹配项。使用“查找全部”可查看所有结果。",
                            )
                            .to_string();
                    }

                    // Ensure we scroll to the first result if we haven't yet
                    if self.scroll_to_row.is_none() && !self.search_results.is_empty() {
                        self.jump_to_search_offset(self.search_results[0].byte_offset);
                    }
                } else {
                    self.status_message = self
                        .tr("No matches found", "未找到匹配项")
                        .to_string();
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
                    self.jump_to_search_offset(self.search_results[0].byte_offset);
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
            self.jump_to_search_offset(result.byte_offset);
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
            self.jump_to_search_offset(result.byte_offset);
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
            "{} {}...{}",
            self.tr("Loading results", "正在加载结果"),
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
                self.jump_to_line_number(line_num);
            } else {
                self.status_message = self
                    .tr(
                        "Line number out of range",
                        "行号超出范围",
                    )
                    .to_string();
            }
        } else {
            self.status_message = self
                .tr("Invalid line number", "无效的行号")
                .to_string();
        }
    }

    fn jump_to_line_number(&mut self, line_num: usize) {
        let target_line = line_num.saturating_sub(1);
        self.request_scroll_to_line(target_line, 3);
        self.goto_line_input = line_num.to_string();
        self.status_message = self.format_status_jumped_to_line(line_num);
    }

    fn run_taint_analysis(&mut self) {
        if self.taint_in_progress {
            return;
        }

        let Some(reader) = self.file_reader.as_ref() else {
            self.taint_error = Some(
                self.tr(
                    "Open a trace file first",
                    "请先打开一个追踪文件",
                )
                .to_string(),
            );
            self.status_message = self
                .tr(
                    "Open a trace file before taint analysis",
                    "进行污点分析前请先打开追踪文件",
                )
                .to_string();
            return;
        };

        let line_no = match self.taint_line_input.trim().parse::<usize>() {
            Ok(value) if value > 0 => value,
            _ => {
                self.taint_error = Some(
                    self.tr(
                        "Invalid target line",
                        "无效的目标行",
                    )
                    .to_string(),
                );
                return;
            }
        };
        let bit_lo = match self.taint_bit_lo_input.trim().parse::<u8>() {
            Ok(value) => value,
            Err(_) => {
                self.taint_error = Some(
                    self.tr(
                        "Invalid low bit",
                        "无效的低位",
                    )
                    .to_string(),
                );
                return;
            }
        };
        let bit_hi = match self.taint_bit_hi_input.trim().parse::<u8>() {
            Ok(value) if value >= bit_lo => value,
            _ => {
                self.taint_error = Some(
                    self.tr(
                        "Invalid high bit",
                        "无效的高位",
                    )
                    .to_string(),
                );
                return;
            }
        };
        let max_depth = match self.taint_depth_input.trim().parse::<usize>() {
            Ok(value) if value > 0 => value,
            _ => {
                self.taint_error = Some(
                    self.tr(
                        "Invalid trace depth",
                        "无效的追踪深度",
                    )
                    .to_string(),
                );
                return;
            }
        };
        let max_nodes = match self.taint_output_limit_input.trim().parse::<usize>() {
            Ok(value) if value > 0 => value,
            _ => {
                self.taint_error = Some(
                    self.tr(
                        "Invalid output limit",
                        "无效的输出上限",
                    )
                    .to_string(),
                );
                return;
            }
        };

        let target_kind = match self.taint_target_mode {
            TaintTargetMode::Reg => TargetKind::RegSlice,
            TaintTargetMode::Mem => TargetKind::MemSlice,
        };
        let reg = if matches!(target_kind, TargetKind::RegSlice) {
            let value = self.taint_reg_input.trim();
            if value.is_empty() {
                self.taint_error = Some(
                    self.tr(
                        "Target register is required",
                        "必须填写目标寄存器",
                    )
                    .to_string(),
                );
                return;
            }
            Some(value.to_string())
        } else {
            None
        };
        let mem_expr = if matches!(target_kind, TargetKind::MemSlice) {
            let value = self.taint_mem_input.trim();
            if value.is_empty() {
                self.taint_error = Some(
                    self.tr(
                        "Target memory expression is required",
                        "必须填写目标内存表达式",
                    )
                    .to_string(),
                );
                return;
            }
            Some(value.to_string())
        } else {
            None
        };

        let request = BackwardTaintRequest {
            target_kind,
            line_no,
            reg,
            mem_expr,
            bit_lo,
            bit_hi,
            options: BackwardTaintOptions {
                max_depth,
                max_nodes,
                prune_equal_value_loads: self.taint_prune_equal_value_loads,
                ..BackwardTaintOptions::default()
            },
        };
        let reader_clone = reader.clone();
        let (tx, rx) = channel();
        self.taint_message_rx = Some(rx);
        self.taint_in_progress = true;
        self.taint_error = None;
        self.taint_selected_line = None;
        self.status_message = self
            .tr(
                "Running backward taint analysis...",
                "正在执行反向污点分析...",
            )
            .to_string();

        std::thread::spawn(move || {
            let result = (|| -> anyhow::Result<BackwardTaintReport> {
                let streaming = StreamingTrace::new(reader_clone);
                trace_backward_streaming(request, &streaming)
            })();

            let _ = match result {
                Ok(report) => tx.send(TaintUiMessage::Done(report)),
                Err(err) => tx.send(TaintUiMessage::Error(err.to_string())),
            };
        });
    }

    fn run_taint_for_candidate(&mut self, line_no: usize, candidate: &TaintCandidate) {
        self.taint_last_target = Some(TaintSelectionTarget {
            line_no,
            candidate: candidate.clone(),
        });
        self.taint_line_input = line_no.to_string();
        match candidate.kind {
            TaintTargetMode::Reg => {
                self.taint_target_mode = TaintTargetMode::Reg;
                self.taint_reg_input = candidate.text.clone();
                if self.taint_bit_lo_input.is_empty() {
                    self.taint_bit_lo_input = "0".to_string();
                }
                if self.taint_bit_hi_input.is_empty() {
                    self.taint_bit_hi_input = "31".to_string();
                }
            }
            TaintTargetMode::Mem => {
                self.taint_target_mode = TaintTargetMode::Mem;
                self.taint_mem_input = candidate.text.clone();
            }
        }
        self.run_taint_analysis();
    }

    fn poll_taint_results(&mut self) {
        if !self.taint_in_progress {
            return;
        }

        let mut finished = false;
        if let Some(rx) = &self.taint_message_rx {
            while let Ok(message) = rx.try_recv() {
                match message {
                    TaintUiMessage::Done(report) => {
                        self.status_message = self.format_taint_success_status(
                            report.summary.root_source_count,
                            report.summary.chain_count,
                        );
                        self.taint_report = Some(report);
                        self.taint_error = None;
                        finished = true;
                    }
                    TaintUiMessage::Error(err) => {
                        self.status_message = self.format_taint_failed_status(&err);
                        self.taint_error = Some(err);
                        finished = true;
                    }
                }
            }
        }

        if finished {
            self.taint_in_progress = false;
            self.taint_message_rx = None;
        }
    }

    fn render_tools_panel(&mut self, ctx: &egui::Context) {
        egui::SidePanel::right("tool_panel")
            .resizable(true)
            .default_width(460.0)
            .show(ctx, |ui| {
                ui.heading(self.tr("Backward Taint", "反向污点追踪"));

                ui.horizontal(|ui| {
                    ui.selectable_value(&mut self.taint_target_mode, TaintTargetMode::Reg, "Reg");
                    ui.selectable_value(&mut self.taint_target_mode, TaintTargetMode::Mem, "Mem");
                    if ui
                        .button(self.tr("Use Current Line", "使用当前行"))
                        .clicked()
                    {
                        self.taint_line_input = (self.scroll_line + 1).to_string();
                    }
                });

                ui.horizontal(|ui| {
                    ui.label(self.tr("Line", "行"));
                    ui.add(egui::TextEdit::singleline(&mut self.taint_line_input).desired_width(70.0));
                    ui.label(self.tr("Bits", "位段"));
                    ui.add(egui::TextEdit::singleline(&mut self.taint_bit_lo_input).desired_width(40.0));
                    ui.label(":");
                    ui.add(egui::TextEdit::singleline(&mut self.taint_bit_hi_input).desired_width(40.0));
                });
                ui.horizontal(|ui| {
                    ui.label(self.tr("Output Limit", "输出上限"));
                    ui.add(
                        egui::TextEdit::singleline(&mut self.taint_output_limit_input)
                            .desired_width(80.0)
                            .hint_text("10000"),
                    );
                    ui.label(self.tr("Depth", "深度"));
                    ui.add(
                        egui::TextEdit::singleline(&mut self.taint_depth_input)
                            .desired_width(56.0)
                            .hint_text("64"),
                    );
                    ui.small(self.tr(
                        "Max nodes and expansion depth in the taint result graph",
                        "污点结果图的最大节点数和展开深度",
                    ));
                });
                let prune_label = self.tr(
                    "Simplify data sources",
                    "精简数据来源",
                );
                ui.checkbox(&mut self.taint_prune_equal_value_loads, prune_label);
                ui.small(self.tr(
                    "If LOAD bytes exactly match the matched STORE bytes, skip the intermediate memory node.",
                    "如果 LOAD 读取字节与匹配 STORE 写出字节完全一致，则跳过中间内存节点。",
                ));

                match self.taint_target_mode {
                    TaintTargetMode::Reg => {
                        ui.horizontal(|ui| {
                            ui.label(self.tr("Reg", "寄存器"));
                            ui.add(
                                egui::TextEdit::singleline(&mut self.taint_reg_input)
                                    .desired_width(180.0)
                                    .hint_text("x8 / w0 / x21"),
                            );
                        });
                    }
                    TaintTargetMode::Mem => {
                        ui.horizontal(|ui| {
                            ui.label(self.tr("Mem", "内存"));
                            ui.add(
                                egui::TextEdit::singleline(&mut self.taint_mem_input)
                                    .desired_width(260.0)
                                    .hint_text("[x21] / [sp,#0x10]"),
                            );
                        });
                    }
                }

                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(
                            !self.taint_in_progress,
                            egui::Button::new(
                                self.tr("Analyze", "开始分析"),
                            ),
                        )
                        .clicked()
                    {
                        self.run_taint_analysis();
                    }
                    if ui
                        .button(self.tr("Clear", "清空"))
                        .clicked()
                    {
                        self.taint_report = None;
                        self.taint_error = None;
                        self.taint_selected_line = None;
                    }
                    if self.taint_in_progress {
                        ui.spinner();
                    }
                });

                if let Some(target) = self
                    .taint_hover_target
                    .as_ref()
                    .or(self.taint_last_target.as_ref())
                {
                    ui.small(format!(
                        "{}: L{} {}",
                        self.tr("Quick target", "快速目标"),
                        target.line_no,
                        taint_candidate_label(&target.candidate),
                    ));
                    ui.small(self.tr(
                        "Right-click the token under the mouse or press Ctrl+Shift+T.",
                        "右键点击鼠标所在的标记，或按 Ctrl+Shift+T 进行追踪。",
                    ));
                }

                if let Some(err) = &self.taint_error {
                    ui.colored_label(egui::Color32::RED, err);
                }

                let Some(report) = self.taint_report.clone() else {
                    ui.separator();
                    ui.label(self.tr(
                        "No taint report yet.",
                        "尚未生成污点报告。",
                    ));
                    return;
                };

                ui.separator();
                egui::ScrollArea::vertical().show(ui, |ui| {
                    self.render_taint_summary_card(ui, &report);
                    ui.add_space(8.0);
                    self.render_taint_source_overview(ui, &report);
                    ui.add_space(8.0);
                    self.render_taint_source_tree(ui, &report);
                    ui.add_space(8.0);
                    self.render_taint_steps(ui, &report);
                });
            });
    }

    fn render_taint_summary_card(
        &mut self,
        ui: &mut egui::Ui,
        report: &BackwardTaintReport,
    ) {
        egui::Frame::group(ui.style())
            .inner_margin(egui::Margin::same(6.0))
            .rounding(egui::Rounding::same(4.0))
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.colored_label(egui::Color32::from_rgb(100, 180, 255), "◎");
                    ui.strong(&report.summary.target);
                });
                ui.add_space(4.0);
                ui.horizontal_wrapped(|ui| {
                    ui.spacing_mut().item_spacing.x = 8.0;
                    ui.label(format!(
                        "{}: {}",
                        self.tr("Sources", "来源"),
                        report.graph.root_sources.len()
                    ));
                    ui.label(format!(
                        "{}: {}",
                        self.tr("Steps", "步骤"),
                        report.steps.len()
                    ));
                    ui.label(format!(
                        "{}: {} {}",
                        self.tr("Limit", "上限"),
                        report.request.options.max_nodes,
                        self.tr("nodes", "节点")
                    ));
                    ui.label(format!(
                        "{}: {}",
                        self.tr("Depth", "深度"),
                        report.request.options.max_depth
                    ));
                });
                ui.add_space(4.0);
                ui.horizontal_wrapped(|ui| {
                    let exact = report.summary.exact_source_count;
                    let possible = report.summary.possible_source_count;
                    let unknown = report.summary.unknown_source_count;
                    if exact > 0 {
                        render_pill_badge(
                            ui,
                            &format!("✓ {} {}", exact, self.tr("exact", "确定")),
                            egui::Color32::from_rgb(80, 200, 120),
                        );
                    }
                    if possible > 0 {
                        render_pill_badge(
                            ui,
                            &format!("? {} {}", possible, self.tr("possible", "可能")),
                            egui::Color32::from_rgb(255, 200, 60),
                        );
                    }
                    if unknown > 0 {
                        render_pill_badge(
                            ui,
                            &format!("✗ {} {}", unknown, self.tr("unknown", "未知")),
                            egui::Color32::from_rgb(255, 100, 100),
                        );
                    }
                });
                if report.summary.truncated {
                    ui.add_space(4.0);
                    ui.colored_label(
                        egui::Color32::YELLOW,
                        self.tr(
                            "⚠ Result truncated by analysis limits.",
                            "⚠ 分析结果因达到限制而被截断。",
                        ),
                    );
                }
            });
    }

    fn render_taint_source_overview(&mut self, ui: &mut egui::Ui, report: &BackwardTaintReport) {
        ui.horizontal(|ui| {
            ui.strong(self.tr("Source Overview", "来源概览"));
            ui.small(format!(
                "{} {}",
                report.graph.root_sources.len(),
                self.tr("items", "项")
            ));
        });

        if report.graph.root_sources.is_empty() {
            ui.small(self.tr(
                "No root sources were produced.",
                "当前没有可展示的来源。",
            ));
            return;
        }

        #[derive(Default)]
        struct SourceGroup {
            kind_name: String,
            total: usize,
            exact: usize,
            possible: usize,
            unknown: usize,
            samples: Vec<String>,
        }

        let mut groups: HashMap<String, SourceGroup> = HashMap::new();
        for source in &report.graph.root_sources {
            let kind_name = format!("{:?}", source.root_kind);
            let group = groups
                .entry(kind_name.clone())
                .or_insert_with(|| SourceGroup {
                    kind_name,
                    ..Default::default()
                });
            group.total += 1;
            match source.confidence {
                Confidence::Exact => group.exact += 1,
                Confidence::Possible => group.possible += 1,
                Confidence::Unknown => group.unknown += 1,
            }
            if group.samples.len() < 3 {
                group.samples.push(source.label.clone());
            }
        }

        let mut groups: Vec<SourceGroup> = groups.into_values().collect();
        groups.sort_by(|left, right| {
            right
                .total
                .cmp(&left.total)
                .then_with(|| left.kind_name.cmp(&right.kind_name))
        });

        for group in groups {
            let (kind_label, kind_color) = data_flow_node_style(&group.kind_name);
            egui::Frame::group(ui.style())
                .inner_margin(egui::Margin::same(6.0))
                .rounding(egui::Rounding::same(4.0))
                .show(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        render_pill_badge(ui, kind_label, kind_color);
                        render_pill_badge(
                            ui,
                            &format!("{} {}", group.total, self.tr("sources", "来源")),
                            egui::Color32::from_rgb(110, 160, 220),
                        );
                        if group.exact > 0 {
                            render_pill_badge(
                                ui,
                                &format!("✓ {}", group.exact),
                                taint_confidence_color(&Confidence::Exact),
                            );
                        }
                        if group.possible > 0 {
                            render_pill_badge(
                                ui,
                                &format!("? {}", group.possible),
                                taint_confidence_color(&Confidence::Possible),
                            );
                        }
                        if group.unknown > 0 {
                            render_pill_badge(
                                ui,
                                &format!("✗ {}", group.unknown),
                                taint_confidence_color(&Confidence::Unknown),
                            );
                        }
                    });
                    if !group.samples.is_empty() {
                        ui.small(
                            egui::RichText::new(group.samples.join("  |  "))
                                .monospace()
                                .color(egui::Color32::from_rgb(160, 160, 160)),
                        );
                    }
                });
            ui.add_space(4.0);
        }
    }

    fn render_taint_source_tree(&mut self, ui: &mut egui::Ui, report: &BackwardTaintReport) {
        ui.horizontal(|ui| {
            ui.strong(self.tr("Source Tree", "来源树"));
            ui.small(format!(
                "{} {}",
                taint_tree_stats(&report.data_flow).leaf_count,
                self.tr("leaf sources", "叶子来源")
            ));
        });

        let root_stats = taint_tree_stats(&report.data_flow);
        egui::Frame::group(ui.style())
            .inner_margin(egui::Margin::same(6.0))
            .rounding(egui::Rounding::same(4.0))
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    render_pill_badge(
                        ui,
                        self.tr("Target", "目标"),
                        egui::Color32::from_rgb(100, 180, 255),
                    );
                    ui.label(
                        egui::RichText::new(taint_tree_node_label(&report.data_flow))
                            .monospace()
                            .strong(),
                    );
                    if report.data_flow.source_line > 0 {
                        self.render_taint_line_jump(ui, report.data_flow.source_line);
                    }
                    render_pill_badge(
                        ui,
                        &format!("{} {}", root_stats.leaf_count, self.tr("leaf sources", "叶子来源")),
                        egui::Color32::from_rgb(90, 120, 170),
                    );
                    if !report.data_flow.sources.is_empty() {
                        render_pill_badge(
                            ui,
                            &format!("{} {}", report.data_flow.sources.len(), self.tr("branches", "分支")),
                            egui::Color32::from_rgb(120, 120, 120),
                        );
                    }
                });
                if !report.data_flow.inst.is_empty() {
                    ui.small(egui::RichText::new(&report.data_flow.inst).monospace());
                }
            });

        if report.data_flow.sources.is_empty() {
            ui.add_space(4.0);
            ui.small(self.tr(
                "The target is already a terminal source.",
                "当前目标本身就是终止来源。",
            ));
            return;
        }

        ui.add_space(6.0);
        let mut branches: Vec<&DataFlowNode> = report.data_flow.sources.iter().collect();
        branches.sort_by(data_flow_node_cmp);
        for branch in branches {
            self.render_taint_tree_node(ui, branch, 0);
            ui.add_space(4.0);
        }
    }

    fn render_taint_tree_node(
        &mut self,
        ui: &mut egui::Ui,
        node: &DataFlowNode,
        depth: usize,
    ) {
        let stats = taint_tree_stats(node);
        let title = self.taint_tree_title(node, &stats);

        if node.sources.is_empty() {
            egui::Frame::group(ui.style())
                .inner_margin(egui::Margin::same(6.0))
                .rounding(egui::Rounding::same(4.0))
                .show(ui, |ui| {
                    self.render_taint_tree_node_details(ui, node, &stats, false);
                });
            return;
        }

        egui::Frame::group(ui.style())
            .inner_margin(egui::Margin::same(6.0))
            .rounding(egui::Rounding::same(4.0))
            .show(ui, |ui| {
                egui::CollapsingHeader::new(title)
                    .default_open(depth == 0 || stats.leaf_count <= 2)
                    .show(ui, |ui| {
                        self.render_taint_tree_node_details(ui, node, &stats, false);
                        ui.add_space(4.0);

                        let mut children: Vec<&DataFlowNode> = node.sources.iter().collect();
                        children.sort_by(data_flow_node_cmp);
                        for child in children {
                            self.render_taint_tree_node(ui, child, depth + 1);
                            ui.add_space(4.0);
                        }
                    });
            });
    }

    fn taint_tree_title(&self, node: &DataFlowNode, stats: &TaintTreeStats) -> String {
        let (kind_label, _) = data_flow_node_style(&node.kind);
        let line_label = if node.source_line > 0 {
            format!("L{}", node.source_line)
        } else {
            self.tr("Synthetic", "合成").to_string()
        };
        let detail = if node.sources.is_empty() {
            String::new()
        } else {
            format!(
                "  |  {} {}  |  {} {}",
                stats.leaf_count,
                self.tr("leaf sources", "叶子来源"),
                node.sources.len(),
                self.tr("branches", "分支")
            )
        };
        format!(
            "{}  {}  |  {}{}",
            kind_label,
            taint_tree_node_label(node),
            line_label,
            detail
        )
    }

    fn render_taint_tree_node_details(
        &mut self,
        ui: &mut egui::Ui,
        node: &DataFlowNode,
        stats: &TaintTreeStats,
        show_target_badge: bool,
    ) {
        let (kind_label, kind_color) = data_flow_node_style(&node.kind);
        ui.horizontal_wrapped(|ui| {
            if show_target_badge {
                render_pill_badge(
                    ui,
                    self.tr("Target", "目标"),
                    egui::Color32::from_rgb(100, 180, 255),
                );
            }
            render_pill_badge(ui, kind_label, kind_color);
            if node.source_line > 0 {
                self.render_taint_line_jump(ui, node.source_line);
            }
            ui.label(
                egui::RichText::new(taint_tree_node_label(node))
                    .monospace()
                    .strong(),
            );
            if !node.pc.is_empty() && node.pc != "0x0" {
                ui.small(&node.pc);
            }
            if !node.sources.is_empty() {
                render_pill_badge(
                    ui,
                    &format!("{} {}", stats.leaf_count, self.tr("leaf sources", "叶子来源")),
                    egui::Color32::from_rgb(90, 120, 170),
                );
                if node.sources.len() > 1 {
                    render_pill_badge(
                        ui,
                        &format!("{} {}", node.sources.len(), self.tr("branches", "分支")),
                        egui::Color32::from_rgb(120, 120, 120),
                    );
                }
            }
        });

        if !node.inst.is_empty() {
            ui.small(
                egui::RichText::new(&node.inst)
                    .monospace()
                    .color(egui::Color32::from_rgb(165, 165, 165)),
            );
        }
    }

    fn render_taint_steps(&mut self, ui: &mut egui::Ui, report: &BackwardTaintReport) {
        egui::CollapsingHeader::new(format!(
            "{} ({})",
            self.tr("Trace Steps", "追踪步骤流"),
            report.steps.len()
        ))
        .default_open(report.steps.len() <= 12)
        .show(ui, |ui| {
            if report.steps.is_empty() {
                ui.small(self.tr(
                    "No trace steps were generated.",
                    "当前没有可展示的追踪步骤。",
                ));
                return;
            }

            for (idx, step) in report.steps.iter().enumerate() {
                let summary = format!(
                    "#{:03}  {}  {}  {} <- {}",
                    step.step_id,
                    self.edge_reason_text(&step.kind),
                    if step.line_no > 0 {
                        format!("L{}", step.line_no)
                    } else {
                        self.tr("Synthetic", "合成节点").to_string()
                    },
                    step.dst,
                    summarize_step_sources(&step.srcs, 3)
                );

                ui.push_id(step.step_id, |ui| {
                    ui.collapsing(summary, |ui| {
                        ui.horizontal_wrapped(|ui| {
                            render_pill_badge(
                                ui,
                                self.confidence_text(&step.confidence),
                                taint_confidence_color(&step.confidence),
                            );
                            render_pill_badge(
                                ui,
                                self.edge_reason_text(&step.kind),
                                taint_step_color(&step.kind),
                            );
                            if step.line_no > 0 {
                                self.render_taint_line_jump(ui, step.line_no);
                            }
                            if step.pc != 0 {
                                ui.small(format!("0x{:x}", step.pc));
                            }
                        });

                        ui.add_space(2.0);
                        ui.label(
                            egui::RichText::new(format!(
                                "{} <- {}",
                                step.dst,
                                step.srcs.join(", ")
                            ))
                            .monospace(),
                        );

                        if !step.inst_text.is_empty() {
                            ui.small(egui::RichText::new(&step.inst_text).monospace());
                        }

                        if step.mem_addr.is_some() || step.data_hex.is_some() {
                            let mut details = Vec::new();
                            if let Some(mem_addr) = &step.mem_addr {
                                details.push(format!("{} {}", self.tr("Addr", "地址"), mem_addr));
                            }
                            if let Some(data_hex) = &step.data_hex {
                                details.push(format!("{} {}", self.tr("Data", "数据"), data_hex));
                            }
                            ui.small(details.join("  |  "));
                        }

                        if !step.note.is_empty() {
                            ui.small(format!("{}: {}", self.tr("Note", "说明"), step.note));
                        }

                        if !step.parent_step_ids.is_empty() {
                            let parents = step
                                .parent_step_ids
                                .iter()
                                .map(|id| format!("#{}", id))
                                .collect::<Vec<_>>()
                                .join(", ");
                            ui.small(format!(
                                "{}: {}",
                                self.tr("Depends on", "依赖步骤"),
                                parents
                            ));
                        }
                    });
                });
                if idx + 1 < report.steps.len() {
                    ui.add_space(4.0);
                }
            }
        });
    }

    fn focus_taint_line(&mut self, line: usize) {
        if line == 0 {
            return;
        }
        self.taint_selected_line = Some(line);
        self.jump_to_line_number(line);
    }

    fn render_taint_line_jump(&mut self, ui: &mut egui::Ui, line_no: usize) {
        let jump = egui::Button::new(
            egui::RichText::new(format!("L{}", line_no))
                .small()
                .color(egui::Color32::from_rgb(130, 170, 220)),
        )
        .frame(false);
        if ui.add(jump).clicked() {
            self.focus_taint_line(line_no);
        }
    }

    fn confidence_text(&self, confidence: &Confidence) -> &'static str {
        match confidence {
            Confidence::Exact => self.tr("Exact", "确定"),
            Confidence::Possible => self.tr("Possible", "可能"),
            Confidence::Unknown => self.tr("Unknown", "未知"),
        }
    }

    fn edge_reason_text(&self, kind: &EdgeReason) -> &'static str {
        match kind {
            EdgeReason::Read => self.tr("Read", "读取"),
            EdgeReason::Write => self.tr("Write", "写入"),
            EdgeReason::Calc => self.tr("Calc", "计算"),
            EdgeReason::Imm => self.tr("Imm", "立即数"),
            EdgeReason::Call => self.tr("Call", "调用返回"),
            EdgeReason::Phi => self.tr("Branch", "分支选择"),
            EdgeReason::Unknown => self.tr("Unknown", "未知"),
        }
    }

    fn render_menu_bar(&mut self, ctx: &egui::Context) {
        let lang = self.ui_language;
        egui::TopBottomPanel::top("menu_bar").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button(self.tr("File", "文件"), |ui| {
                    if ui.button(self.tr("Open...", "打开...")).clicked() {
                        if let Some(path) = rfd::FileDialog::new().pick_file() {
                            // Auto-detect encoding
                            if let Ok(mut file) = std::fs::File::open(&path) {
                                let mut buffer = [0; 4096];
                                if let Ok(n) = std::io::Read::read(&mut file, &mut buffer) {
                                    self.selected_encoding = detect_encoding(&buffer[..n]);
                                }
                            }
                            self.open_file(path);
                        }
                        ui.close_menu();
                    }

                    if ui
                        .add_enabled(
                            self.unsaved_changes,
                            egui::Button::new(
                                self.tr("Save (Ctrl+S)", "保存 (Ctrl+S)"),
                            ),
                        )
                        .clicked()
                    {
                        self.save_file();
                        ui.close_menu();
                    }

                    if ui.button(self.tr("File Info", "文件信息")).clicked()
                    {
                        self.show_file_info = !self.show_file_info;
                        ui.close_menu();
                    }

                    if ui.button(self.tr("Exit", "退出")).clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });

                ui.menu_button(self.tr("View", "视图"), |ui| {
                    ui.checkbox(
                        &mut self.wrap_mode,
                        tr_lang(lang, "Word Wrap", "自动换行"),
                    );
                    ui.checkbox(
                        &mut self.show_line_numbers,
                        tr_lang(lang, "Line Numbers", "行号"),
                    );
                    ui.checkbox(
                        &mut self.dark_mode,
                        tr_lang(lang, "Dark Mode", "深色模式"),
                    );

                    ui.separator();

                    ui.label(self.tr("Font Size:", "字体大小:"));
                    ui.add(egui::Slider::new(&mut self.font_size, 8.0..=32.0));

                    ui.separator();

                    if ui
                        .button(self.tr("Select Encoding", "选择编码"))
                        .clicked()
                    {
                        self.show_encoding_selector = true;
                        ui.close_menu();
                    }
                });

                ui.menu_button(self.tr("Search", "搜索"), |ui| {
                    if ui
                        .add(
                            egui::Button::new(self.tr("Find", "查找"))
                                .shortcut_text("Ctrl+F"),
                        )
                        .clicked()
                    {
                        self.show_search_bar = true;
                        self.focus_search_input = true;
                        ui.close_menu();
                    }
                    if ui
                        .add(
                            egui::Button::new(self.tr("Replace", "替换"))
                                .shortcut_text("Ctrl+R"),
                        )
                        .clicked()
                    {
                        self.show_search_bar = true;
                        self.show_replace = !self.show_replace;
                        ui.close_menu();
                    }
                    ui.separator();
                    ui.checkbox(
                        &mut self.use_regex,
                        tr_lang(lang, "Use Regex", "使用正则"),
                    );
                    ui.checkbox(
                        &mut self.case_sensitive,
                        tr_lang(lang, "Match Case", "区分大小写"),
                    );
                });

                ui.menu_button(self.tr("Tools", "工具"), |ui| {
                    if ui
                        .checkbox(
                            &mut self.tail_mode,
                            tr_lang(
                                lang,
                                "Tail Mode (Auto-refresh)",
                                "Tail 模式（自动刷新）",
                            ),
                        )
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
                    self.render_global_mcp_section_compact(ui);
                });

                ui.menu_button(self.tr("Language", "语言"), |ui| {
                    ui.selectable_value(
                        &mut self.ui_language,
                        UiLanguage::English,
                        "English",
                    );
                    ui.selectable_value(
                        &mut self.ui_language,
                        UiLanguage::Chinese,
                        "中文",
                    );
                });
            });
        });
    }

    fn render_toolbar(&mut self, ctx: &egui::Context) {
        if !self.show_search_bar {
            return;
        }
        let lang = self.ui_language;
        egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(self.tr("Search:", "搜索:"));
                let response = ui.add(
                    egui::TextEdit::singleline(&mut self.search_query).desired_width(300.0),
                );

                if self.focus_search_input {
                    response.request_focus();
                    self.focus_search_input = false;
                }

                ui.checkbox(&mut self.case_sensitive, "Aa").on_hover_text(
                    self.tr("Match Case", "区分大小写"),
                );
                ui.checkbox(&mut self.use_regex, ".*").on_hover_text(
                    self.tr("Use Regex", "使用正则"),
                );

                if response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    self.perform_search(false);
                }

                if ui
                    .add_enabled(
                        !self.search_in_progress,
                        egui::Button::new(self.tr("Find", "查找")),
                    )
                    .clicked()
                {
                    self.perform_search(false);
                }

                if ui
                    .add_enabled(
                        !self.search_in_progress,
                        egui::Button::new(self.tr("Find All", "查找全部")),
                    )
                    .clicked()
                {
                    self.perform_search(true);
                }

                if ui
                    .add_enabled(
                        !self.search_in_progress && self.quick_token_target().is_some(),
                        egui::Button::new(self.tr(
                            "Use Selection",
                            "使用当前选中",
                        )),
                    )
                    .clicked()
                {
                    self.seed_search_from_quick_target();
                    self.perform_search(false);
                }

                if ui
                    .button(self.tr("Previous", "上一个"))
                    .clicked()
                {
                    self.go_to_previous_result();
                }

                if ui.button(self.tr("Next", "下一个")).clicked() {
                    self.go_to_next_result();
                }

                if self.search_in_progress {
                    ui.add(egui::Spinner::new().size(18.0));
                    ui.label(self.tr("Searching...", "搜索中..."));
                    if ui.button(self.tr("Stop", "停止")).clicked() {
                        self.cancel_search();
                    }
                }

                let total_results = self.total_search_results;
                if total_results > 0 {
                    let current = (self.current_result_index + 1).min(total_results);
                    ui.label(format!("{}/{}", current, total_results));
                }

                ui.separator();

                ui.label(self.tr("Go to line:", "跳转到行:"));
                let response = ui
                    .add(egui::TextEdit::singleline(&mut self.goto_line_input).desired_width(80.0));

                if response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    self.go_to_line();
                }

                if ui.button(self.tr("Go", "跳转")).clicked() {
                    self.go_to_line();
                }
            });

            if self.show_replace {
                ui.separator();
                ui.horizontal(|ui| {
                    ui.label(self.tr("Replace with:", "替换为:"));
                    ui.add(
                        egui::TextEdit::singleline(&mut self.replace_query)
                            .desired_width(200.0)
                            .hint_text(tr_lang(
                                lang,
                                "Replacement text...",
                                "替换文本...",
                            )),
                    );

                    if self.replace_in_progress {
                        if ui
                            .button(self.tr("Stop Replace", "停止替换"))
                            .clicked()
                        {
                            if let Some(token) = &self.replace_cancellation_token {
                                token.store(true, std::sync::atomic::Ordering::Relaxed);
                            }
                        }
                        ui.spinner();
                        if let Some(progress) = self.replace_progress {
                            ui.label(format!("{:.1}%", progress * 100.0));
                        }
                    } else {
                        if ui.button(self.tr("Replace", "替换")).clicked() {
                            self.perform_single_replace();
                        }
                        if ui
                            .button(self.tr("Replace All", "全部替换"))
                            .clicked()
                        {
                            self.perform_replace();
                        }
                    }
                });

                if let Some(ref msg) = self.replace_status_message {
                    ui.label(msg);
                }
            }

            if let Some(ref error) = self.search_error {
                ui.colored_label(
                    egui::Color32::RED,
                    match self.ui_language {
                        UiLanguage::English => format!("Search error: {}", error),
                        UiLanguage::Chinese => {
                            format!("搜索错误: {}", error)
                        }
                    },
                );
            }
        });
    }

    fn render_status_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if let Some(ref reader) = self.file_reader {
                    ui.label(match self.ui_language {
                        UiLanguage::English => format!("File: {}", reader.path().display()),
                        UiLanguage::Chinese => {
                            format!("文件: {}", reader.path().display())
                        }
                    });
                    ui.separator();
                    ui.label(match self.ui_language {
                        UiLanguage::English => format!("Size: {} bytes", reader.len()),
                        UiLanguage::Chinese => format!("大小: {} bytes", reader.len()),
                    });
                    ui.separator();
                    ui.label(match self.ui_language {
                        UiLanguage::English => format!("Lines: ~{}", self.line_indexer.total_lines()),
                        UiLanguage::Chinese => {
                            format!("行数: ~{}", self.line_indexer.total_lines())
                        }
                    });
                    ui.separator();
                    ui.label(match self.ui_language {
                        UiLanguage::English => format!("Encoding: {}", reader.encoding().name()),
                        UiLanguage::Chinese => {
                            format!("编码: {}", reader.encoding().name())
                        }
                    });
                    ui.separator();
                    ui.label(match self.ui_language {
                        UiLanguage::English => format!("Line: {}", self.scroll_line + 1),
                        UiLanguage::Chinese => {
                            format!("当前行: {}", self.scroll_line + 1)
                        }
                    });
                } else {
                    ui.label(self.tr(
                        "No file opened - Click File -> Open to start",
                        "尚未打开文件 - 点击“文件” -> “打开”开始",
                    ));
                }

                if !self.status_message.is_empty() {
                    ui.separator();
                    ui.label(&self.status_message);
                }

                if self.search_in_progress {
                    ui.separator();
                    ui.spinner();
                    if ui.button(self.tr("Stop Search", "停止搜索")).clicked() {
                        self.cancel_search();
                    }
                }
            });
        });
    }
    fn render_text_area(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            if let Some(reader) = self.file_reader.clone() {
                let available_height = ui.available_height();
                let font_id = egui::FontId::monospace(self.font_size);
                let line_height = ui.fonts(|f| f.row_height(&font_id));
                let row_height_full = line_height + ui.spacing().item_spacing.y;
                self.visible_lines =
                    ((available_height / row_height_full).ceil() as usize).saturating_add(2);
                let taint_target_line = self.taint_report.as_ref().map(|report| report.request.line_no);
                let taint_graph_lines: HashSet<usize> = self
                    .taint_report
                    .as_ref()
                    .map(|report| {
                        let mut lines = HashSet::new();
                        collect_data_flow_lines(&report.data_flow, &mut lines);
                        lines
                    })
                    .unwrap_or_default();
                let selected_taint_line = self.taint_selected_line;

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

                if let Some(target_row) = self.scroll_to_row.take() {
                    let row_spacing = ui.spacing().item_spacing.y;
                    scroll_area = scroll_area
                        .vertical_scroll_offset(target_row as f32 * (line_height + row_spacing));
                }

                let mut first_visible_row = None;
                let mut pending_taint_action: Option<TaintSelectionTarget> = None;
                let mut hovered_taint_target: Option<TaintSelectionTarget> = None;

                scroll_area.show_rows(
                    ui,
                    line_height,
                    self.line_indexer.total_lines(),
                    |ui, row_range| {
                        // Capture the first visible row reported by the scroll area.
                        if first_visible_row.is_none() {
                            first_visible_row = Some(row_range.start);
                        }

                        let mut current_offset = if let Some((start, _)) = self
                            .line_indexer
                            .get_line_with_reader(row_range.start, reader.as_ref())
                        {
                            start
                        } else {
                            return;
                        };

                        let count = row_range.end - row_range.start;
                        let render_range = row_range.start..(row_range.start + count);

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

                            let taint_style = taint_line_style(
                                line_num + 1,
                                taint_target_line,
                                selected_taint_line,
                                &taint_graph_lines,
                            );
                            let taint_candidate_matches = parse_taint_candidate_matches(line_text);
                            let row_fill = taint_style
                                .map(|(color, _)| color)
                                .unwrap_or(egui::Color32::TRANSPARENT);

                            egui::Frame::default().fill(row_fill).show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    if let Some((_, marker)) = taint_style {
                                        ui.add(
                                            egui::Label::new(
                                                egui::RichText::new(format!("{marker} "))
                                                    .monospace()
                                                    .color(egui::Color32::LIGHT_GREEN),
                                            )
                                            .selectable(false),
                                        );
                                    } else {
                                        ui.add(
                                            egui::Label::new(
                                                egui::RichText::new("  ")
                                                    .monospace()
                                                    .color(egui::Color32::TRANSPARENT),
                                            )
                                            .selectable(false),
                                        );
                                    }

                                if self.show_line_numbers {
                                    let ln_text =
                                        egui::RichText::new(format!("{:6} ", line_num + 1))
                                            .monospace()
                                            .color(egui::Color32::DARK_GRAY);
                                    // Make line numbers non-selectable so drag-select only captures the content text
                                    ui.add(egui::Label::new(ln_text).selectable(false));
                                }

                                // Build label with highlighted search matches
                                let wrap_width = self.wrap_mode.then(|| ui.available_width());
                                let display_job = build_line_layout_job(
                                    line_text,
                                    &line_matches,
                                    self.font_size,
                                    self.dark_mode,
                                    wrap_width,
                                );
                                let display_galley = ui.painter().layout_job(display_job);
                                let hit_test_galley = ui.painter().layout_job(build_plain_line_layout_job(
                                    line_text,
                                    self.font_size,
                                    self.dark_mode,
                                    wrap_width,
                                ));
                                let label = ui.add(egui::Label::new(display_galley.clone()));

                                let line_number = line_num + 1;
                                let hovered_candidate = label
                                    .interact_pointer_pos()
                                    .or_else(|| ui.input(|i| i.pointer.hover_pos()))
                                    .filter(|_| label.hovered() || label.secondary_clicked())
                                    .and_then(|pointer_pos| {
                                        let cursor =
                                            hit_test_galley.cursor_from_pos(pointer_pos - label.rect.min);
                                        let byte_offset =
                                            char_index_to_byte_index(line_text, cursor.ccursor.index);
                                        taint_candidate_at_byte(
                                            &taint_candidate_matches,
                                            byte_offset,
                                        )
                                    });

                                if let Some(candidate) = hovered_candidate.clone() {
                                    hovered_taint_target = Some(TaintSelectionTarget {
                                        line_no: line_number,
                                        candidate,
                                    });
                                }

                                if label.clicked() {
                                    if let Some(candidate) = hovered_candidate.clone() {
                                        self.taint_last_target = Some(TaintSelectionTarget {
                                            line_no: line_number,
                                            candidate,
                                        });
                                    }
                                }

                                if !taint_candidate_matches.is_empty() {
                                    let mut menu_candidates: Vec<TaintCandidate> =
                                        taint_candidate_matches
                                            .iter()
                                            .map(|item| item.candidate.clone())
                                            .collect();
                                    menu_candidates.dedup_by(|left, right| {
                                        left.kind == right.kind && left.text == right.text
                                    });
                                    let preferred_candidate = hovered_candidate.clone();
                                    label.context_menu(|ui| {
                                        ui.label(self.tr("Trace Actions", "追踪操作"));
                                        if let Some(candidate) = &preferred_candidate {
                                            let taint_action = format!(
                                                "{} {}",
                                                self.tr("Trace", "追踪"),
                                                taint_candidate_label(candidate)
                                            );
                                            if ui.button(taint_action).clicked() {
                                                pending_taint_action = Some(TaintSelectionTarget {
                                                    line_no: line_number,
                                                    candidate: candidate.clone(),
                                                });
                                                ui.close_menu();
                                            }
                                            ui.separator();
                                        }
                                        for candidate in &menu_candidates {
                                            let taint_action = format!(
                                                "{} {}",
                                                self.tr("Trace", "追踪"),
                                                taint_candidate_label(candidate)
                                            );
                                            if ui.button(taint_action).clicked() {
                                                pending_taint_action = Some(TaintSelectionTarget {
                                                    line_no: line_number,
                                                    candidate: candidate.clone(),
                                                });
                                                ui.close_menu();
                                            }
                                        }
                                    });
                                }

                                if label.hovered() {
                                    ui.output_mut(|o| o.cursor_icon = egui::CursorIcon::Text);
                                }

                                // Ensure labels don't consume scroll events
                                label.surrender_focus();
                                });
                            });
                        }
                    },
                );

                self.taint_hover_target = hovered_taint_target;
                if let Some(target) = pending_taint_action.take() {
                    self.run_taint_for_candidate(target.line_no, &target.candidate);
                }

                // Update scroll_line to match what was actually displayed
                if let Some(first_row) = first_visible_row {
                    self.scroll_line = first_row;
                }
            } else {
                ui.centered_and_justified(|ui| {
                    ui.heading(self.app_title());
                    ui.label(self.tr(
                        "\nClick File -> Open to load a text file",
                        "\n点击“文件” -> “打开”以加载文本文件",
                    ));
                });
            }
        });
    }

    fn render_encoding_selector(&mut self, ctx: &egui::Context) {
        if self.show_encoding_selector {
            egui::Window::new(self.tr("Select Encoding", "选择编码"))
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

                    if ui.button(self.tr("Cancel", "取消")).clicked() {
                        self.show_encoding_selector = false;
                    }
                });
        }
    }

    fn render_file_info(&mut self, ctx: &egui::Context) {
        if self.show_file_info {
            if let Some(reader) = self.file_reader.clone() {
                let lang = self.ui_language;
                egui::Window::new(self.tr("File Information", "文件信息"))
                    .collapsible(false)
                    .resizable(false)
                    .show(ctx, |ui| {
                        ui.label(match lang {
                            UiLanguage::English => format!("Path: {}", reader.path().display()),
                            UiLanguage::Chinese => {
                                format!("路径: {}", reader.path().display())
                            }
                        });
                        ui.label(match lang {
                            UiLanguage::English => format!(
                                "Size: {} bytes ({:.2} MB)",
                                reader.len(),
                                reader.len() as f64 / 1_000_000.0
                            ),
                            UiLanguage::Chinese => format!(
                                "大小: {} bytes ({:.2} MB)",
                                reader.len(),
                                reader.len() as f64 / 1_000_000.0
                            ),
                        });
                        ui.label(match lang {
                            UiLanguage::English => {
                                format!("Lines: ~{}", self.line_indexer.total_lines())
                            }
                            UiLanguage::Chinese => {
                                format!("行数: ~{}", self.line_indexer.total_lines())
                            }
                        });
                        if let Some(report) = &self.last_index_report {
                            ui.label(match lang {
                                UiLanguage::English => format!(
                                    "Index: {} ({})",
                                    self.describe_index_mode(report.mode),
                                    self.describe_index_cache_status(report.cache_status)
                                ),
                                UiLanguage::Chinese => format!(
                                    "索引: {} ({})",
                                    self.describe_index_mode(report.mode),
                                    self.describe_index_cache_status(report.cache_status)
                                ),
                            });
                        }
                        ui.label(match lang {
                            UiLanguage::English => format!("Encoding: {}", reader.encoding().name()),
                            UiLanguage::Chinese => {
                                format!("编码: {}", reader.encoding().name())
                            }
                        });

                        if ui.button(self.tr("Close", "关闭")).clicked() {
                            self.show_file_info = false;
                        }
                    });
            }
        }
    }
}

impl eframe::App for TextViewerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if let Some(start_time) = self.open_start_time {
            let elapsed = start_time.elapsed();
            println!("File opened and first frame rendered in: {:.2?}", elapsed);
            self.status_message = self.format_status_rendered(&self.status_message, elapsed);
            self.open_start_time = None;
        }

        // Update window title
        let title = if self.unsaved_changes {
            self.app_title_unsaved()
        } else {
            self.app_title()
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
            self.show_search_bar = true;
            self.focus_search_input = true;
            if self.seed_search_from_quick_target() {
                self.perform_search(false);
            }
        }
        if ctx.input_mut(|i| i.consume_key(egui::Modifiers::CTRL | egui::Modifiers::SHIFT, egui::Key::T)) {
            if let Some(target) = self
                .taint_hover_target
                .clone()
                .or_else(|| self.taint_last_target.clone())
            {
                self.run_taint_for_candidate(target.line_no, &target.candidate);
            } else {
                if self.taint_line_input.is_empty() {
                    self.taint_line_input = (self.scroll_line + 1).to_string();
                }
                self.run_taint_analysis();
            }
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
        self.poll_taint_results();

        if self.search_in_progress || self.replace_in_progress || self.taint_in_progress {
            ctx.request_repaint(); // Keep spinner animated during long searches
        }

        self.render_menu_bar(ctx);
        self.render_toolbar(ctx);
        self.render_tools_panel(ctx);
        self.render_status_bar(ctx);
        self.render_text_area(ctx);
        self.render_encoding_selector(ctx);
        self.render_file_info(ctx);
    }
}

fn detect_global_mcp_enabled() -> bool {
    detect_any_global_mcp(MCP_SERVER_NAME)
}

fn vscode_user_mcp_config_path() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .map(|base| base.join("Code").join("User").join("mcp.json"))
    }

    #[cfg(target_os = "macos")]
    {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .map(|base| {
                base.join("Library")
                    .join("Application Support")
                    .join("Code")
                    .join("User")
                    .join("mcp.json")
            })
    }

    #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
    {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .map(|base| base.join(".config").join("Code").join("User").join("mcp.json"))
    }
}

#[allow(dead_code)]
fn mcp_config_contains_server(path: &std::path::Path, server_name: &str) -> bool {
    let Ok(content) = std::fs::read_to_string(path) else {
        return false;
    };
    let Ok(root) = serde_json::from_str::<Value>(&content) else {
        return false;
    };
    root.get("servers")
        .and_then(Value::as_object)
        .map(|servers| servers.contains_key(server_name))
        .unwrap_or(false)
}

#[allow(dead_code)]
fn install_global_mcp_config(launch: &McpLaunchSpec) -> anyhow::Result<McpConfigOutcome> {
    if let Some(outcome) = try_install_global_mcp_via_code_cli(launch)? {
        return Ok(outcome);
    }

    let path = write_named_mcp_server_config(
        vscode_user_mcp_config_path()
            .ok_or_else(|| anyhow::anyhow!("unable to resolve VS Code global mcp.json path"))?,
        Some(launch),
    )?;
    Ok(McpConfigOutcome {
        path,
        method: "direct file write",
    })
}

#[allow(dead_code)]
fn remove_global_mcp_config() -> anyhow::Result<McpConfigOutcome> {
    let path = write_named_mcp_server_config(
        vscode_user_mcp_config_path()
            .ok_or_else(|| anyhow::anyhow!("unable to resolve VS Code global mcp.json path"))?,
        None,
    )?;
    Ok(McpConfigOutcome {
        path,
        method: "direct file write",
    })
}

#[allow(dead_code)]
fn try_install_global_mcp_via_code_cli(
    launch: &McpLaunchSpec,
) -> anyhow::Result<Option<McpConfigOutcome>> {
    let Some(code_cli) = find_vscode_cli() else {
        return Ok(None);
    };

    let payload = serde_json::to_string(&json!({
        "name": MCP_SERVER_NAME,
        "command": launch.command,
        "args": launch.args,
    }))?;

    let output = std::process::Command::new(&code_cli)
        .arg("--add-mcp")
        .arg(payload)
        .output();

    match output {
        Ok(result) if result.status.success() => Ok(Some(McpConfigOutcome {
            path: vscode_user_mcp_config_path()
                .unwrap_or_else(|| PathBuf::from("<VS Code user mcp.json>")),
            method: "code --add-mcp",
        })),
        Ok(_) => Ok(None),
        Err(_) => Ok(None),
    }
}

#[allow(dead_code)]
fn find_vscode_cli() -> Option<PathBuf> {
    let mut candidates = vec![
        PathBuf::from("code"),
        PathBuf::from("code.cmd"),
        PathBuf::from("code-insiders"),
        PathBuf::from("code-insiders.cmd"),
    ];

    if cfg!(target_os = "windows") {
        if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
            let base = PathBuf::from(local_app_data);
            candidates.push(
                base.join("Programs")
                    .join("Microsoft VS Code")
                    .join("bin")
                    .join("code.cmd"),
            );
            candidates.push(
                base.join("Programs")
                    .join("Microsoft VS Code Insiders")
                    .join("bin")
                    .join("code-insiders.cmd"),
            );
        }
    }

    candidates.into_iter().find(|candidate| {
        std::process::Command::new(candidate)
            .arg("--version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    })
}

#[allow(dead_code)]
fn write_named_mcp_server_config(
    path: PathBuf,
    launch: Option<&McpLaunchSpec>,
) -> anyhow::Result<PathBuf> {
    let mut root = if path.exists() {
        let content = std::fs::read_to_string(&path)?;
        serde_json::from_str::<Value>(&content).unwrap_or_else(|_| json!({}))
    } else {
        json!({})
    };

    if !root.is_object() {
        root = json!({});
    }
    let object = root.as_object_mut().expect("object");

    let servers_value = object
        .entry("servers".to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    if !servers_value.is_object() {
        *servers_value = Value::Object(Map::new());
    }

    let servers = servers_value.as_object_mut().expect("servers object");
    if let Some(launch) = launch {
        servers.insert(
            MCP_SERVER_NAME.to_string(),
            json!({
                "command": launch.command,
                "args": launch.args,
            }),
        );
    } else {
        servers.remove(MCP_SERVER_NAME);
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, serde_json::to_string_pretty(&root)?)?;
    Ok(path)
}

#[allow(dead_code)]
fn detect_workspace_mcp_enabled() -> bool {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(".vscode")
        .join("mcp.json");
    let Ok(content) = std::fs::read_to_string(path) else {
        return false;
    };
    let Ok(root) = serde_json::from_str::<Value>(&content) else {
        return false;
    };
    root.get("servers")
        .and_then(Value::as_object)
        .map(|servers| servers.contains_key(MCP_SERVER_NAME))
        .unwrap_or(false)
}

#[allow(dead_code)]
fn update_workspace_mcp_config(launch: &McpLaunchSpec, enabled: bool) -> anyhow::Result<PathBuf> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(".vscode")
        .join("mcp.json");

    let mut root = if path.exists() {
        let content = std::fs::read_to_string(&path)?;
        serde_json::from_str::<Value>(&content).unwrap_or_else(|_| json!({}))
    } else {
        json!({})
    };

    if !root.is_object() {
        root = json!({});
    }
    let object = root.as_object_mut().expect("object");

    let servers_value = object
        .entry("servers".to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    if !servers_value.is_object() {
        *servers_value = Value::Object(Map::new());
    }

    let servers = servers_value.as_object_mut().expect("servers object");
    if enabled {
        servers.insert(
            MCP_SERVER_NAME.to_string(),
            json!({
                "command": launch.command,
                "args": launch.args,
            }),
        );
    } else {
        servers.remove(MCP_SERVER_NAME);
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, serde_json::to_string_pretty(&root)?)?;
    Ok(path)
}

fn data_flow_node_style(kind: &str) -> (&str, egui::Color32) {
    match kind {
        "Reg" => ("REG", egui::Color32::from_rgb(100, 180, 255)),
        "Mem" => ("MEM", egui::Color32::from_rgb(190, 130, 255)),
        "Imm" => ("IMM", egui::Color32::from_rgb(80, 200, 120)),
        "Static" => ("STATIC", egui::Color32::from_rgb(255, 200, 60)),
        "Arg" => ("ARG", egui::Color32::from_rgb(255, 160, 60)),
        "RetVal" => ("RET", egui::Color32::from_rgb(255, 140, 100)),
        "MemLiveIn" => ("MEM_IN", egui::Color32::from_rgb(160, 120, 200)),
        k if k.starts_with("Unknown") => ("UNK", egui::Color32::from_rgb(255, 90, 90)),
        _ => (kind, egui::Color32::GRAY),
    }
}

#[derive(Clone, Copy, Default)]
struct TaintTreeStats {
    total_nodes: usize,
    leaf_count: usize,
    max_depth: usize,
}

fn taint_tree_stats(node: &DataFlowNode) -> TaintTreeStats {
    let mut stats = TaintTreeStats {
        total_nodes: 1,
        leaf_count: if node.sources.is_empty() { 1 } else { 0 },
        max_depth: 1,
    };
    for child in &node.sources {
        let child_stats = taint_tree_stats(child);
        stats.total_nodes += child_stats.total_nodes;
        stats.leaf_count += child_stats.leaf_count;
        stats.max_depth = stats.max_depth.max(child_stats.max_depth + 1);
    }
    stats
}

fn taint_tree_node_label(node: &DataFlowNode) -> String {
    if node.value.is_empty() {
        node.name.clone()
    } else {
        format!("{} = {}", node.name, node.value)
    }
}

fn data_flow_kind_rank(kind: &str) -> u8 {
    match kind {
        "Reg" => 0,
        "Mem" => 1,
        "Imm" => 2,
        "Static" => 3,
        "Arg" => 4,
        "RetVal" => 5,
        "MemLiveIn" => 6,
        k if k.starts_with("Unknown") => 7,
        _ => 8,
    }
}

fn data_flow_node_cmp(left: &&DataFlowNode, right: &&DataFlowNode) -> std::cmp::Ordering {
    sort_line_for_panel(left.source_line)
        .cmp(&sort_line_for_panel(right.source_line))
        .then_with(|| data_flow_kind_rank(&left.kind).cmp(&data_flow_kind_rank(&right.kind)))
        .then_with(|| left.name.cmp(&right.name))
        .then_with(|| left.value.cmp(&right.value))
}

fn render_pill_badge(ui: &mut egui::Ui, label: &str, color: egui::Color32) {
    let bg = egui::Color32::from_rgba_premultiplied(
        color.r() / 3,
        color.g() / 3,
        color.b() / 3,
        200,
    );
    egui::Frame::none()
        .fill(bg)
        .stroke(egui::Stroke::new(1.0, color))
        .rounding(egui::Rounding::same(3.0))
        .inner_margin(egui::Margin::symmetric(4.0, 1.0))
        .show(ui, |ui| {
            ui.label(egui::RichText::new(label).small().strong().color(color));
        });
}

fn taint_confidence_color(confidence: &Confidence) -> egui::Color32 {
    match confidence {
        Confidence::Exact => egui::Color32::from_rgb(80, 200, 120),
        Confidence::Possible => egui::Color32::from_rgb(255, 200, 60),
        Confidence::Unknown => egui::Color32::from_rgb(255, 100, 100),
    }
}

fn taint_step_color(kind: &EdgeReason) -> egui::Color32 {
    match kind {
        EdgeReason::Read => egui::Color32::from_rgb(100, 180, 255),
        EdgeReason::Write => egui::Color32::from_rgb(190, 130, 255),
        EdgeReason::Calc => egui::Color32::from_rgb(255, 200, 60),
        EdgeReason::Imm => egui::Color32::from_rgb(80, 200, 120),
        EdgeReason::Call => egui::Color32::from_rgb(255, 160, 60),
        EdgeReason::Phi => egui::Color32::from_rgb(255, 140, 100),
        EdgeReason::Unknown => egui::Color32::from_rgb(255, 100, 100),
    }
}

fn summarize_step_sources(srcs: &[String], max_items: usize) -> String {
    if srcs.is_empty() {
        return "-".to_string();
    }
    if srcs.len() <= max_items {
        return srcs.join(", ");
    }

    let head = srcs[..max_items].join(", ");
    format!("{head} +{}", srcs.len() - max_items)
}

fn sort_line_for_panel(line_no: usize) -> usize {
    if line_no == 0 { usize::MAX } else { line_no }
}

fn collect_data_flow_lines(node: &DataFlowNode, lines: &mut HashSet<usize>) {
    if node.source_line > 0 {
        lines.insert(node.source_line);
    }
    for child in &node.sources {
        collect_data_flow_lines(child, lines);
    }
}

fn taint_line_style(
    line_no: usize,
    target_line: Option<usize>,
    selected_line: Option<usize>,
    step_lines: &HashSet<usize>,
) -> Option<(egui::Color32, &'static str)> {
    if selected_line == Some(line_no) {
        return Some((egui::Color32::from_rgb(40, 90, 60), "S"));
    }
    if target_line == Some(line_no) {
        return Some((egui::Color32::from_rgb(90, 70, 25), "T"));
    }
    if step_lines.contains(&line_no) {
        return Some((egui::Color32::from_rgb(35, 50, 80), "+"));
    }
    None
}

fn taint_mem_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\[[^\]]+\]").expect("valid mem regex"))
}

fn taint_reg_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\b(?:x\d+|w\d+|sp|fp|lr|xzr|wzr)\b").expect("valid reg regex")
    })
}

fn default_line_text_color(dark_mode: bool) -> egui::Color32 {
    if dark_mode {
        egui::Color32::LIGHT_GRAY
    } else {
        egui::Color32::BLACK
    }
}

fn build_plain_line_layout_job(
    line_text: &str,
    font_size: f32,
    dark_mode: bool,
    wrap_width: Option<f32>,
) -> egui::text::LayoutJob {
    let mut job = egui::text::LayoutJob::default();
    job.append(
        line_text,
        0.0,
        egui::TextFormat {
            font_id: egui::FontId::monospace(font_size),
            color: default_line_text_color(dark_mode),
            ..Default::default()
        },
    );
    if let Some(max_width) = wrap_width {
        job.wrap = egui::text::TextWrapping {
            max_width,
            ..Default::default()
        };
    }
    job
}

fn build_line_layout_job(
    line_text: &str,
    line_matches: &[(usize, usize, bool)],
    font_size: f32,
    dark_mode: bool,
    wrap_width: Option<f32>,
) -> egui::text::LayoutJob {
    if line_matches.is_empty() {
        return build_plain_line_layout_job(line_text, font_size, dark_mode, wrap_width);
    }

    let mut job = egui::text::LayoutJob::default();
    let mut last_end = 0;

    for (abs_start, abs_end, is_selected) in line_matches {
        if *abs_start > last_end {
            job.append(
                &line_text[last_end..*abs_start],
                0.0,
                egui::TextFormat {
                    font_id: egui::FontId::monospace(font_size),
                    color: default_line_text_color(dark_mode),
                    ..Default::default()
                },
            );
        }

        let match_end = (*abs_end).min(line_text.len());
        job.append(
            &line_text[*abs_start..match_end],
            0.0,
            egui::TextFormat {
                font_id: egui::FontId::monospace(font_size),
                color: egui::Color32::BLACK,
                background: if *is_selected {
                    egui::Color32::from_rgb(255, 200, 0)
                } else {
                    egui::Color32::YELLOW
                },
                ..Default::default()
            },
        );

        last_end = match_end;
    }

    if last_end < line_text.len() {
        job.append(
            &line_text[last_end..],
            0.0,
            egui::TextFormat {
                font_id: egui::FontId::monospace(font_size),
                color: default_line_text_color(dark_mode),
                ..Default::default()
            },
        );
    }

    if let Some(max_width) = wrap_width {
        job.wrap = egui::text::TextWrapping {
            max_width,
            ..Default::default()
        };
    }

    job
}

fn parse_taint_candidate_matches(line_text: &str) -> Vec<TaintCandidateMatch> {
    let mut seen = HashSet::new();
    let mut candidates = Vec::new();

    for mat in taint_mem_regex().find_iter(line_text) {
        let text = mat.as_str().trim().to_string();
        if seen.insert((1u8, text.clone())) {
            candidates.push(TaintCandidateMatch {
                candidate: TaintCandidate {
                    kind: TaintTargetMode::Mem,
                    text,
                },
                start: mat.start(),
                end: mat.end(),
            });
        }
    }

    for mat in taint_reg_regex().find_iter(line_text) {
        let text = mat.as_str().trim().to_ascii_lowercase();
        if seen.insert((0u8, text.clone())) {
            candidates.push(TaintCandidateMatch {
                candidate: TaintCandidate {
                    kind: TaintTargetMode::Reg,
                    text,
                },
                start: mat.start(),
                end: mat.end(),
            });
        }
    }

    candidates.sort_by(|left, right| {
        left.start
            .cmp(&right.start)
            .then_with(|| left.end.cmp(&right.end))
            .then_with(|| left.candidate.text.cmp(&right.candidate.text))
    });
    candidates
}

fn taint_candidate_at_byte(
    candidates: &[TaintCandidateMatch],
    byte_offset: usize,
) -> Option<TaintCandidate> {
    candidates
        .iter()
        .find(|candidate| candidate.start <= byte_offset && byte_offset < candidate.end)
        .map(|candidate| candidate.candidate.clone())
}

fn char_index_to_byte_index(text: &str, char_index: usize) -> usize {
    text.char_indices()
        .nth(char_index)
        .map(|(byte_index, _)| byte_index)
        .unwrap_or(text.len())
}

fn taint_candidate_label(candidate: &TaintCandidate) -> String {
    match candidate.kind {
        TaintTargetMode::Reg => format!("reg {}", candidate.text),
        TaintTargetMode::Mem => format!("mem {}", candidate.text),
    }
}

