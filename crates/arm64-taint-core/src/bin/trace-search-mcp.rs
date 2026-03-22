use anyhow::{Context, Result, bail};
use arm64_taint_core::{
    BackwardTaintOptions, BackwardTaintReport, BackwardTaintRequest, Confidence, RootSource,
    StreamingTrace, TargetKind, report_to_json, trace_backward_streaming,
};
use content_search_core::file_reader::{FileReader, available_encodings, detect_encoding};
use content_search_core::line_indexer::{IndexBuildReport, IndexCacheStatus, IndexMode, LineIndexer};
use content_search_core::replacer::{ReplaceMessage, Replacer};
use content_search_core::search_engine::{SearchEngine, SearchMessage, SearchResult, SearchType};
use encoding_rs::Encoding;
use rmcp::{
    Json, ServerHandler, ServiceExt,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{ServerCapabilities, ServerInfo},
    schemars,
    schemars::JsonSchema,
    tool, tool_handler, tool_router,
    transport::stdio,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc,
};

const DEFAULT_MAX_MATCHES: usize = 10;
const DEFAULT_MAX_RESULTS: usize = 100;
const DEFAULT_LINE_COUNT: usize = 20;
const DEFAULT_MAX_DEPTH: usize = 64;
const DEFAULT_MAX_NODES: usize = 2000;
const DEFAULT_BRANCH_BUDGET: usize = 500;
const DEFAULT_PREVIEW_CHARS: usize = 180;
const DEFAULT_LINE_CLIP_CHARS: usize = 400;
const DEFAULT_MAX_ROOT_SOURCES: usize = 5;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
enum McpTargetKind {
    Reg,
    Mem,
}

impl McpTargetKind {
    fn as_target_kind(&self) -> TargetKind {
        match self {
            Self::Reg => TargetKind::RegSlice,
            Self::Mem => TargetKind::MemSlice,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::Reg => "reg",
            Self::Mem => "mem",
        }
    }
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct InspectContentFileRequest {
    #[schemars(description = "Absolute or relative path to the file")]
    file_path: String,
    #[serde(default)]
    #[schemars(description = "Optional encoding override, for example UTF-8 or Windows-1252")]
    encoding: Option<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
struct InspectContentFileResponse {
    file_path: String,
    bytes: usize,
    total_lines: usize,
    encoding: String,
    detected_encoding: String,
    index: IndexSummary,
    supported_encodings: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct ReadContentLinesRequest {
    #[schemars(description = "Absolute or relative path to the file")]
    file_path: String,
    #[serde(default)]
    #[schemars(description = "Optional encoding override, for example UTF-8 or Windows-1252")]
    encoding: Option<String>,
    #[schemars(description = "1-based first line number to read")]
    start_line: usize,
    #[serde(default = "default_line_count")]
    #[schemars(description = "Maximum number of lines to read")]
    line_count: usize,
    #[serde(default = "default_line_clip_chars")]
    #[schemars(description = "Maximum characters returned per line")]
    clip_chars: usize,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
struct ReadContentLinesResponse {
    file_path: String,
    encoding: String,
    detected_encoding: String,
    start_line: usize,
    returned_lines: usize,
    total_lines: usize,
    index: IndexSummary,
    lines: Vec<ContentLine>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
struct ContentLine {
    line_no: usize,
    byte_start: usize,
    byte_end: usize,
    text: String,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct SearchContentRequest {
    #[schemars(description = "Absolute or relative path to the file")]
    file_path: String,
    #[serde(default)]
    #[schemars(description = "Optional encoding override, for example UTF-8 or Windows-1252")]
    encoding: Option<String>,
    #[schemars(description = "Plain text or regex query")]
    query: String,
    #[serde(default)]
    #[schemars(description = "Treat query as a regex when true")]
    use_regex: bool,
    #[serde(default)]
    #[schemars(description = "Use case-sensitive matching when true")]
    case_sensitive: bool,
    #[serde(default)]
    #[schemars(description = "Byte offset to continue searching from")]
    start_offset: usize,
    #[serde(default = "default_max_results")]
    #[schemars(description = "Maximum raw matches or distinct lines to return")]
    max_results: usize,
    #[serde(default = "default_true")]
    #[schemars(description = "Count total matches across the file when true")]
    include_total_count: bool,
    #[serde(default)]
    #[schemars(description = "Collapse raw matches by line when true")]
    collapse_by_line: bool,
    #[serde(default = "default_preview_chars")]
    #[schemars(description = "Maximum preview length per result")]
    preview_chars: usize,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
struct SearchContentResponse {
    file_path: String,
    encoding: String,
    detected_encoding: String,
    query: String,
    use_regex: bool,
    case_sensitive: bool,
    collapse_by_line: bool,
    start_offset: usize,
    next_start_offset: Option<usize>,
    returned_matches: usize,
    raw_matches_processed: usize,
    total_matches: Option<usize>,
    index: IndexSummary,
    matches: Vec<SearchMatchSummary>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
struct SearchMatchSummary {
    line_no: usize,
    byte_offset: usize,
    match_len: usize,
    hit_count_on_line: usize,
    preview: String,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct ReplaceContentMatchRequest {
    #[schemars(description = "Absolute or relative path to the input file")]
    input_file: String,
    #[serde(default)]
    #[schemars(description = "Optional output path. When omitted, a .modified sibling file is created unless in_place=true")]
    output_file: Option<String>,
    #[serde(default)]
    #[schemars(description = "Replace in the original file when true")]
    in_place: bool,
    #[schemars(description = "Byte offset returned by search_content")]
    byte_offset: usize,
    #[schemars(description = "Matched byte length returned by search_content")]
    match_len: usize,
    #[schemars(description = "Replacement text")]
    replacement: String,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
struct ReplaceContentMatchResponse {
    input_file: String,
    output_file: String,
    in_place: bool,
    byte_offset: usize,
    replaced_length: usize,
    replacement_length: usize,
    status: String,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct ReplaceContentAllRequest {
    #[schemars(description = "Absolute or relative path to the input file")]
    input_file: String,
    #[serde(default)]
    #[schemars(description = "Optional encoding override used only for match counting")]
    encoding: Option<String>,
    #[serde(default)]
    #[schemars(description = "Optional output path. When omitted, a .modified sibling file is created unless in_place=true")]
    output_file: Option<String>,
    #[serde(default)]
    #[schemars(description = "Replace in the original file when true")]
    in_place: bool,
    #[schemars(description = "Literal text or regex pattern to replace")]
    query: String,
    #[schemars(description = "Replacement text")]
    replacement: String,
    #[serde(default)]
    #[schemars(description = "Treat query as a regex when true")]
    use_regex: bool,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
struct ReplaceContentAllResponse {
    input_file: String,
    output_file: String,
    in_place: bool,
    query: String,
    use_regex: bool,
    match_count_before_replace: usize,
    bytes_processed: usize,
    total_bytes: usize,
    status: String,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct TraceBackwardToolRequest {
    #[schemars(description = "Absolute or relative path to the trace file")]
    trace_file: String,
    #[serde(default)]
    #[schemars(description = "Optional encoding override, for example UTF-8 or Windows-1252")]
    encoding: Option<String>,
    #[schemars(description = "1-based trace line number to analyze")]
    line_no: usize,
    #[schemars(description = "Taint target kind: reg or mem")]
    target_kind: McpTargetKind,
    #[schemars(description = "Taint target value, for example x8 or [x21]")]
    target: String,
    #[serde(default)]
    #[schemars(description = "Bit range low bound")]
    bit_lo: u8,
    #[serde(default = "default_bit_hi")]
    #[schemars(description = "Bit range high bound")]
    bit_hi: u8,
    #[serde(default = "default_max_depth")]
    #[schemars(description = "Backward taint max depth")]
    max_depth: usize,
    #[serde(default = "default_max_nodes")]
    #[schemars(description = "Backward taint max node count")]
    max_nodes: usize,
    #[serde(default = "default_branch_budget")]
    #[schemars(description = "Per-branch node budget")]
    per_branch_budget: usize,
    #[serde(default = "default_true")]
    #[schemars(description = "Enable equal-value load/store pruning")]
    prune_equal_value_loads: bool,
    #[serde(default = "default_max_root_sources")]
    #[schemars(description = "Maximum root sources returned in the summary")]
    max_root_sources: usize,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
struct TraceBackwardResponse {
    trace_file: String,
    encoding: String,
    detected_encoding: String,
    line_no: usize,
    target_kind: String,
    target: String,
    summary: TaintSummary,
    root_sources: Vec<RootSourceSummary>,
    report_json: String,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct SearchTraceRequest {
    #[schemars(description = "Absolute or relative path to the trace file")]
    trace_file: String,
    #[serde(default)]
    #[schemars(description = "Optional encoding override, for example UTF-8 or Windows-1252")]
    encoding: Option<String>,
    #[schemars(description = "Plain text or regex query used to search the trace")]
    query: String,
    #[serde(default)]
    #[schemars(description = "Treat query as a regex when true")]
    use_regex: bool,
    #[serde(default)]
    #[schemars(description = "Use case-sensitive matching when true")]
    case_sensitive: bool,
    #[serde(default)]
    #[schemars(description = "Byte offset to continue searching from")]
    start_offset: usize,
    #[serde(default = "default_max_matches")]
    #[schemars(description = "Maximum distinct matched lines to analyze")]
    max_matches: usize,
    #[schemars(description = "Taint target kind: reg or mem")]
    target_kind: McpTargetKind,
    #[schemars(description = "Taint target value, for example x8 or [x21]")]
    target: String,
    #[serde(default)]
    #[schemars(description = "Apply taint on matched_line + taint_line_offset")]
    taint_line_offset: i32,
    #[serde(default)]
    #[schemars(description = "Bit range low bound")]
    bit_lo: u8,
    #[serde(default = "default_bit_hi")]
    #[schemars(description = "Bit range high bound")]
    bit_hi: u8,
    #[serde(default = "default_max_depth")]
    #[schemars(description = "Backward taint max depth")]
    max_depth: usize,
    #[serde(default = "default_max_nodes")]
    #[schemars(description = "Backward taint max node count")]
    max_nodes: usize,
    #[serde(default = "default_branch_budget")]
    #[schemars(description = "Per-branch node budget")]
    per_branch_budget: usize,
    #[serde(default = "default_true")]
    #[schemars(description = "Enable equal-value load/store pruning")]
    prune_equal_value_loads: bool,
    #[serde(default = "default_preview_chars")]
    #[schemars(description = "Maximum preview length per matched line")]
    preview_chars: usize,
    #[serde(default = "default_max_root_sources")]
    #[schemars(description = "Maximum root sources returned per analyzed hit")]
    max_root_sources_per_hit: usize,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
struct SearchTraceResponse {
    trace_file: String,
    encoding: String,
    detected_encoding: String,
    query: String,
    use_regex: bool,
    case_sensitive: bool,
    start_offset: usize,
    next_start_offset: Option<usize>,
    matches_returned: usize,
    raw_matches_processed: usize,
    index: IndexSummary,
    hits: Vec<SearchTraceHit>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
struct IndexSummary {
    mode: String,
    cache_status: String,
    total_lines: usize,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
struct SearchTraceHit {
    matched_line_no: usize,
    analysis_line_no: usize,
    hit_count_on_line: usize,
    preview: String,
    status: String,
    taint: Option<TaintSummary>,
    root_sources: Vec<RootSourceSummary>,
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
struct TaintSummary {
    target: String,
    root_source_count: usize,
    exact_source_count: usize,
    possible_source_count: usize,
    unknown_source_count: usize,
    chain_count: usize,
    truncated: bool,
    contains_unknown: bool,
    contains_cycle: bool,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
struct RootSourceSummary {
    label: String,
    explain: String,
    confidence: String,
}

#[derive(Debug, Clone)]
struct SearchLineHit {
    line_idx: usize,
    first_byte_offset: usize,
    first_match_len: usize,
    hit_count: usize,
}

#[derive(Debug, Clone)]
struct CollectedLineHits {
    hits: Vec<SearchLineHit>,
    raw_matches_processed: usize,
    next_start_offset: Option<usize>,
}

struct OpenedContent {
    path: PathBuf,
    reader: Arc<FileReader>,
    encoding_name: String,
    detected_encoding_name: String,
}

struct IndexedContent {
    opened: OpenedContent,
    indexer: LineIndexer,
    index_report: IndexBuildReport,
}

#[derive(Debug, Clone)]
struct SearchTraceMcpServer {
    tool_router: ToolRouter<Self>,
}

impl SearchTraceMcpServer {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }
}

impl Default for SearchTraceMcpServer {
    fn default() -> Self {
        Self::new()
    }
}

#[tool_router]
impl SearchTraceMcpServer {
    #[tool(
        name = "inspect_content_file",
        description = "Inspect a file like the main viewer: detect encoding, build or reuse the line index, and report file stats."
    )]
    async fn inspect_content_file(
        &self,
        Parameters(request): Parameters<InspectContentFileRequest>,
    ) -> std::result::Result<Json<InspectContentFileResponse>, String> {
        execute_inspect_content_file(request)
            .map(Json)
            .map_err(|err| err.to_string())
    }

    #[tool(
        name = "read_content_lines",
        description = "Read a 1-based line window from a file, similar to opening the viewer and jumping to a line."
    )]
    async fn read_content_lines(
        &self,
        Parameters(request): Parameters<ReadContentLinesRequest>,
    ) -> std::result::Result<Json<ReadContentLinesResponse>, String> {
        execute_read_content_lines(request)
            .map(Json)
            .map_err(|err| err.to_string())
    }

    #[tool(
        name = "search_content",
        description = "Search a file with literal or regex matching, optionally count total matches, and page results by byte offset."
    )]
    async fn search_content(
        &self,
        Parameters(request): Parameters<SearchContentRequest>,
    ) -> std::result::Result<Json<SearchContentResponse>, String> {
        execute_search_content(request)
            .map(Json)
            .map_err(|err| err.to_string())
    }

    #[tool(
        name = "replace_content_match",
        description = "Replace one specific match by byte offset and length, typically using a result returned from search_content."
    )]
    async fn replace_content_match(
        &self,
        Parameters(request): Parameters<ReplaceContentMatchRequest>,
    ) -> std::result::Result<Json<ReplaceContentMatchResponse>, String> {
        execute_replace_content_match(request)
            .map(Json)
            .map_err(|err| err.to_string())
    }

    #[tool(
        name = "replace_content_all",
        description = "Run the main executable's streaming replace-all workflow and write either a sibling .modified file or an in-place rewrite."
    )]
    async fn replace_content_all(
        &self,
        Parameters(request): Parameters<ReplaceContentAllRequest>,
    ) -> std::result::Result<Json<ReplaceContentAllResponse>, String> {
        execute_replace_content_all(request)
            .map(Json)
            .map_err(|err| err.to_string())
    }

    #[tool(
        name = "trace_backward",
        description = "Run backward taint on a specific trace line and target, returning both a compact summary and the full report JSON."
    )]
    async fn trace_backward(
        &self,
        Parameters(request): Parameters<TraceBackwardToolRequest>,
    ) -> std::result::Result<Json<TraceBackwardResponse>, String> {
        execute_trace_backward(request)
            .map(Json)
            .map_err(|err| err.to_string())
    }

    #[tool(
        name = "search_trace_sources",
        description = "Search a trace file, collapse hits by line, and run backward taint on each matched line."
    )]
    async fn search_trace_sources(
        &self,
        Parameters(request): Parameters<SearchTraceRequest>,
    ) -> std::result::Result<Json<SearchTraceResponse>, String> {
        execute_search_trace(request).map(Json).map_err(|err| err.to_string())
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for SearchTraceMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
            "Use inspect_content_file, read_content_lines, search_content, replace_content_match, replace_content_all, trace_backward, and search_trace_sources to mirror the main executable's search, replace, and taint workflows.",
        )
    }
}

#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    SearchTraceMcpServer::new()
        .serve(stdio())
        .await
        .context("failed to start MCP stdio server")?
        .waiting()
        .await
        .context("MCP server join failed")?;
    Ok(())
}

fn execute_inspect_content_file(request: InspectContentFileRequest) -> Result<InspectContentFileResponse> {
    let indexed = open_indexed_content(&request.file_path, request.encoding.as_deref())?;
    let index = indexed.index_summary();

    Ok(InspectContentFileResponse {
        file_path: indexed.opened.path.display().to_string(),
        bytes: indexed.opened.reader.len(),
        total_lines: indexed.index_report.total_lines,
        encoding: indexed.opened.encoding_name.clone(),
        detected_encoding: indexed.opened.detected_encoding_name.clone(),
        index,
        supported_encodings: supported_encoding_names(),
    })
}

fn execute_read_content_lines(request: ReadContentLinesRequest) -> Result<ReadContentLinesResponse> {
    if request.start_line == 0 {
        bail!("start_line must be greater than 0");
    }
    if request.line_count == 0 {
        bail!("line_count must be greater than 0");
    }

    let indexed = open_indexed_content(&request.file_path, request.encoding.as_deref())?;
    if request.start_line > indexed.index_report.total_lines {
        bail!(
            "start_line {} exceeds total lines {}",
            request.start_line,
            indexed.index_report.total_lines
        );
    }

    let start_idx = request.start_line - 1;
    let end_idx = (start_idx + request.line_count).min(indexed.index_report.total_lines);
    let mut lines = Vec::with_capacity(end_idx.saturating_sub(start_idx));

    for line_idx in start_idx..end_idx {
        lines.push(load_content_line(
            &indexed.indexer,
            indexed.opened.reader.as_ref(),
            line_idx,
            request.clip_chars,
        )?);
    }
    let index = indexed.index_summary();

    Ok(ReadContentLinesResponse {
        file_path: indexed.opened.path.display().to_string(),
        encoding: indexed.opened.encoding_name,
        detected_encoding: indexed.opened.detected_encoding_name,
        start_line: request.start_line,
        returned_lines: lines.len(),
        total_lines: indexed.index_report.total_lines,
        index,
        lines,
    })
}

fn execute_search_content(request: SearchContentRequest) -> Result<SearchContentResponse> {
    validate_search_request(&request.query, request.max_results)?;

    let indexed = open_indexed_content(&request.file_path, request.encoding.as_deref())?;
    let reader = indexed.opened.reader.clone();
    let mut engine = SearchEngine::new();
    engine.set_query(request.query.clone(), request.use_regex, request.case_sensitive);

    let total_matches = request
        .include_total_count
        .then(|| count_search_matches(&engine, reader.clone()))
        .transpose()?;

    let (matches, raw_matches_processed, next_start_offset) = if request.collapse_by_line {
        let collected = collect_search_line_hits(
            reader.clone(),
            &indexed.indexer,
            &request.query,
            request.use_regex,
            request.case_sensitive,
            request.start_offset,
            request.max_results,
        )?;
        let matches = collected
            .hits
            .into_iter()
            .map(|hit| SearchMatchSummary {
                line_no: hit.line_idx + 1,
                byte_offset: hit.first_byte_offset,
                match_len: hit.first_match_len,
                hit_count_on_line: hit.hit_count,
                preview: load_preview(
                    &indexed.indexer,
                    indexed.opened.reader.as_ref(),
                    hit.line_idx,
                    request.preview_chars,
                )
                .unwrap_or_else(|err| format!("<preview unavailable: {err}>")),
            })
            .collect::<Vec<_>>();
        (
            matches,
            collected.raw_matches_processed,
            collected.next_start_offset,
        )
    } else {
        let batch = fetch_search_batch(
            &engine,
            reader.clone(),
            request.start_offset,
            request.max_results,
        )?;
        let next_start_offset = if batch.len() >= request.max_results {
            batch.last()
                .map(|last| last.byte_offset.saturating_add(last.match_len.max(1)))
                .filter(|offset| *offset < reader.len())
        } else {
            None
        };
        let matches = batch
            .iter()
            .map(|result| build_search_match_summary(&indexed, result, request.preview_chars))
            .collect::<Result<Vec<_>>>()?;
        (matches, batch.len(), next_start_offset)
    };

    let index = indexed.index_summary();
    Ok(SearchContentResponse {
        file_path: indexed.opened.path.display().to_string(),
        encoding: indexed.opened.encoding_name,
        detected_encoding: indexed.opened.detected_encoding_name,
        query: request.query,
        use_regex: request.use_regex,
        case_sensitive: request.case_sensitive,
        collapse_by_line: request.collapse_by_line,
        start_offset: request.start_offset,
        next_start_offset,
        returned_matches: matches.len(),
        raw_matches_processed,
        total_matches,
        index,
        matches,
    })
}

fn execute_replace_content_match(
    request: ReplaceContentMatchRequest,
) -> Result<ReplaceContentMatchResponse> {
    if request.match_len == 0 {
        bail!("match_len must be greater than 0");
    }

    let input_path = PathBuf::from(&request.input_file);
    let output_path = resolve_replace_output_path(
        &input_path,
        request.output_file.as_deref(),
        request.in_place,
    )?;

    let target_path = if output_path == input_path {
        input_path.clone()
    } else {
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed to create output directory {}", parent.display())
            })?;
        }
        fs::copy(&input_path, &output_path).with_context(|| {
            format!(
                "failed to copy {} to {}",
                input_path.display(),
                output_path.display()
            )
        })?;
        output_path.clone()
    };

    Replacer::replace_single(
        &target_path,
        request.byte_offset,
        request.match_len,
        &request.replacement,
    )
    .with_context(|| format!("failed to replace match in {}", target_path.display()))?;

    Ok(ReplaceContentMatchResponse {
        input_file: input_path.display().to_string(),
        output_file: output_path.display().to_string(),
        in_place: output_path == input_path,
        byte_offset: request.byte_offset,
        replaced_length: request.match_len,
        replacement_length: request.replacement.len(),
        status: "ok".to_string(),
    })
}

fn execute_replace_content_all(request: ReplaceContentAllRequest) -> Result<ReplaceContentAllResponse> {
    if request.query.trim().is_empty() {
        bail!("query must not be empty");
    }

    let input_path = PathBuf::from(&request.input_file);
    let final_output_path = resolve_replace_output_path(
        &input_path,
        request.output_file.as_deref(),
        request.in_place,
    )?;
    let working_output_path = if final_output_path == input_path {
        temp_replace_output_path(&input_path)
    } else {
        final_output_path.clone()
    };

    if let Some(parent) = working_output_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create output directory {}", parent.display()))?;
    }

    let match_count_before_replace = count_matches_for_replace(
        &input_path,
        request.encoding.as_deref(),
        &request.query,
        request.use_regex,
    )?;
    let (bytes_processed, total_bytes) = run_replace_all(
        &input_path,
        &working_output_path,
        &request.query,
        &request.replacement,
        request.use_regex,
    )?;

    if working_output_path != final_output_path {
        replace_path(&working_output_path, &final_output_path)?;
    }

    Ok(ReplaceContentAllResponse {
        input_file: input_path.display().to_string(),
        output_file: final_output_path.display().to_string(),
        in_place: final_output_path == input_path,
        query: request.query,
        use_regex: request.use_regex,
        match_count_before_replace,
        bytes_processed,
        total_bytes,
        status: "ok".to_string(),
    })
}

fn execute_trace_backward(request: TraceBackwardToolRequest) -> Result<TraceBackwardResponse> {
    validate_taint_request(
        request.line_no,
        &request.target,
        request.bit_lo,
        request.bit_hi,
        request.max_depth,
        request.max_nodes,
    )?;

    let opened = open_content_reader_with_encoding(
        Path::new(&request.trace_file),
        request.encoding.as_deref(),
    )?;
    let report = run_trace_backward_request(
        &opened.reader,
        request.line_no,
        &request.target_kind,
        &request.target,
        request.bit_lo,
        request.bit_hi,
        request.max_depth,
        request.max_nodes,
        request.per_branch_budget,
        request.prune_equal_value_loads,
    )?;
    let (summary, root_sources) = summarize_report(&report, request.max_root_sources);

    Ok(TraceBackwardResponse {
        trace_file: opened.path.display().to_string(),
        encoding: opened.encoding_name,
        detected_encoding: opened.detected_encoding_name,
        line_no: request.line_no,
        target_kind: request.target_kind.as_str().to_string(),
        target: request.target,
        summary,
        root_sources,
        report_json: report_to_json(&report)?,
    })
}

fn execute_search_trace(request: SearchTraceRequest) -> Result<SearchTraceResponse> {
    validate_search_request(&request.query, request.max_matches)?;
    validate_taint_request(
        1,
        &request.target,
        request.bit_lo,
        request.bit_hi,
        request.max_depth,
        request.max_nodes,
    )?;

    let indexed = open_indexed_content(&request.trace_file, request.encoding.as_deref())?;
    let search_hits = collect_search_line_hits(
        indexed.opened.reader.clone(),
        &indexed.indexer,
        &request.query,
        request.use_regex,
        request.case_sensitive,
        request.start_offset,
        request.max_matches,
    )?;
    let streaming = StreamingTrace::new(indexed.opened.reader.clone());

    let hits = search_hits
        .hits
        .into_iter()
        .map(|hit| {
            build_trace_hit_response(
                &request,
                indexed.opened.reader.as_ref(),
                &indexed.indexer,
                &streaming,
                hit,
            )
        })
        .collect::<Vec<_>>();

    let index = indexed.index_summary();
    Ok(SearchTraceResponse {
        trace_file: indexed.opened.path.display().to_string(),
        encoding: indexed.opened.encoding_name,
        detected_encoding: indexed.opened.detected_encoding_name,
        query: request.query,
        use_regex: request.use_regex,
        case_sensitive: request.case_sensitive,
        start_offset: request.start_offset,
        next_start_offset: search_hits.next_start_offset,
        matches_returned: hits.len(),
        raw_matches_processed: search_hits.raw_matches_processed,
        index,
        hits,
    })
}

fn validate_search_request(query: &str, max_results: usize) -> Result<()> {
    if query.trim().is_empty() {
        bail!("query must not be empty");
    }
    if max_results == 0 {
        bail!("max_results must be greater than 0");
    }
    Ok(())
}

fn validate_taint_request(
    line_no: usize,
    target: &str,
    bit_lo: u8,
    bit_hi: u8,
    max_depth: usize,
    max_nodes: usize,
) -> Result<()> {
    if line_no == 0 {
        bail!("line_no must be greater than 0");
    }
    if target.trim().is_empty() {
        bail!("target must not be empty");
    }
    if bit_lo > bit_hi {
        bail!("invalid bit range: {}:{}", bit_lo, bit_hi);
    }
    if max_depth == 0 {
        bail!("max_depth must be greater than 0");
    }
    if max_nodes == 0 {
        bail!("max_nodes must be greater than 0");
    }
    Ok(())
}

fn open_indexed_content(file_path: &str, encoding_override: Option<&str>) -> Result<IndexedContent> {
    let opened = open_content_reader_with_encoding(Path::new(file_path), encoding_override)?;
    let mut indexer = LineIndexer::new();
    let index_report = indexer.index_file_cached(opened.reader.as_ref());
    Ok(IndexedContent {
        opened,
        indexer,
        index_report,
    })
}

fn open_content_reader_with_encoding(
    path: &Path,
    encoding_override: Option<&str>,
) -> Result<OpenedContent> {
    let sample = read_file_sample(path, 4096)?;
    let detected_encoding = detect_encoding(&sample);
    let selected_encoding = match encoding_override {
        Some(name) if !name.trim().is_empty() && !name.eq_ignore_ascii_case("auto") => {
            resolve_encoding(name)
                .with_context(|| format!("unsupported encoding override {name}"))?
        }
        _ => detected_encoding,
    };

    let reader = Arc::new(
        FileReader::new(path.to_path_buf(), selected_encoding)
            .with_context(|| format!("failed to open {}", path.display()))?,
    );

    Ok(OpenedContent {
        path: path.to_path_buf(),
        reader,
        encoding_name: encoding_display_name(selected_encoding),
        detected_encoding_name: encoding_display_name(detected_encoding),
    })
}

fn resolve_encoding(name: &str) -> Option<&'static Encoding> {
    let trimmed = name.trim();
    Encoding::for_label(trimmed.as_bytes()).or_else(|| {
        let normalized = trimmed.to_ascii_lowercase().replace([' ', '_'], "-");
        available_encodings().into_iter().find_map(|(label, encoding)| {
            let candidate = label.to_ascii_lowercase().replace([' ', '_'], "-");
            (candidate == normalized).then_some(encoding)
        })
    })
}

fn supported_encoding_names() -> Vec<String> {
    available_encodings()
        .into_iter()
        .map(|(name, _)| name.to_string())
        .collect()
}

fn encoding_display_name(encoding: &'static Encoding) -> String {
    available_encodings()
        .into_iter()
        .find_map(|(name, candidate)| std::ptr::eq(candidate, encoding).then_some(name.to_string()))
        .unwrap_or_else(|| encoding.name().to_string())
}

fn read_file_sample(path: &Path, max_len: usize) -> Result<Vec<u8>> {
    use std::io::Read;

    let mut file =
        std::fs::File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut sample = vec![0u8; max_len];
    let read_len = file
        .read(&mut sample)
        .with_context(|| format!("failed to read {}", path.display()))?;
    sample.truncate(read_len);
    Ok(sample)
}

fn count_search_matches(engine: &SearchEngine, reader: Arc<FileReader>) -> Result<usize> {
    let cancel_token = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::sync_channel(64);
    engine.count_matches(reader, tx, cancel_token.clone());

    let mut total = 0usize;
    loop {
        match rx.recv() {
            Ok(SearchMessage::CountResult(count)) => total = total.saturating_add(count),
            Ok(SearchMessage::Done(SearchType::Count)) => break,
            Ok(SearchMessage::Error(err)) => {
                cancel_token.store(true, Ordering::Relaxed);
                bail!("search count failed: {err}");
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    Ok(total)
}

fn fetch_search_batch(
    engine: &SearchEngine,
    reader: Arc<FileReader>,
    start_offset: usize,
    max_results: usize,
) -> Result<Vec<SearchResult>> {
    let cancel_token = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::sync_channel(16);
    engine.fetch_matches(reader, tx, start_offset, max_results, cancel_token.clone());

    let mut results = Vec::new();
    loop {
        match rx.recv() {
            Ok(SearchMessage::ChunkResult(chunk)) => {
                results.extend(chunk.matches);
            }
            Ok(SearchMessage::Done(SearchType::Fetch)) => break,
            Ok(SearchMessage::Error(err)) => {
                cancel_token.store(true, Ordering::Relaxed);
                bail!("search failed: {err}");
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    Ok(results)
}

fn collect_search_line_hits(
    reader: Arc<FileReader>,
    indexer: &LineIndexer,
    query: &str,
    use_regex: bool,
    case_sensitive: bool,
    start_offset: usize,
    max_matches: usize,
) -> Result<CollectedLineHits> {
    let mut engine = SearchEngine::new();
    engine.set_query(query.to_string(), use_regex, case_sensitive);

    let mut grouped = BTreeMap::<usize, SearchLineHit>::new();
    let mut seen_offsets = HashSet::<usize>::new();
    let mut current_offset = start_offset;
    let mut raw_matches_processed = 0usize;
    let mut next_start_offset = None;
    let batch_size = max_matches.saturating_mul(8).clamp(32, 512);

    while grouped.len() < max_matches && current_offset < reader.len() {
        let batch = fetch_search_batch(&engine, reader.clone(), current_offset, batch_size)?;
        if batch.is_empty() {
            break;
        }

        let mut batch_next_offset = current_offset;
        let mut advanced = false;

        for result in batch {
            let match_len = result.match_len.max(1);
            batch_next_offset = batch_next_offset.max(result.byte_offset.saturating_add(match_len));
            advanced = true;

            if !seen_offsets.insert(result.byte_offset) {
                continue;
            }

            raw_matches_processed += 1;
            let line_idx = indexer.find_line_at_offset(result.byte_offset, Some(reader.as_ref()));
            if let Some(hit) = grouped.get_mut(&line_idx) {
                hit.hit_count += 1;
                if result.byte_offset < hit.first_byte_offset {
                    hit.first_byte_offset = result.byte_offset;
                    hit.first_match_len = result.match_len;
                }
                continue;
            }

            grouped.insert(
                line_idx,
                SearchLineHit {
                    line_idx,
                    first_byte_offset: result.byte_offset,
                    first_match_len: result.match_len,
                    hit_count: 1,
                },
            );

            if grouped.len() >= max_matches {
                next_start_offset = (batch_next_offset < reader.len()).then_some(batch_next_offset);
                break;
            }
        }

        if grouped.len() >= max_matches {
            break;
        }
        if !advanced || batch_next_offset <= current_offset {
            break;
        }
        current_offset = batch_next_offset;
    }

    Ok(CollectedLineHits {
        hits: grouped.into_values().collect(),
        raw_matches_processed,
        next_start_offset,
    })
}

fn build_search_match_summary(
    indexed: &IndexedContent,
    result: &SearchResult,
    preview_chars: usize,
) -> Result<SearchMatchSummary> {
    let line_idx = indexed
        .indexer
        .find_line_at_offset(result.byte_offset, Some(indexed.opened.reader.as_ref()));
    Ok(SearchMatchSummary {
        line_no: line_idx + 1,
        byte_offset: result.byte_offset,
        match_len: result.match_len,
        hit_count_on_line: 1,
        preview: load_preview(
            &indexed.indexer,
            indexed.opened.reader.as_ref(),
            line_idx,
            preview_chars,
        )?,
    })
}

fn load_content_line(
    indexer: &LineIndexer,
    reader: &FileReader,
    line_idx: usize,
    clip_chars: usize,
) -> Result<ContentLine> {
    let (start, end) = indexer
        .get_line_with_reader(line_idx, reader)
        .with_context(|| format!("line {} not found", line_idx + 1))?;
    let text = decode_line_bytes(reader, reader.get_bytes(start, end.min(reader.len())));
    Ok(ContentLine {
        line_no: line_idx + 1,
        byte_start: start,
        byte_end: end.min(reader.len()),
        text: clip_text(&text, clip_chars),
    })
}

fn load_preview(
    indexer: &LineIndexer,
    reader: &FileReader,
    line_idx: usize,
    preview_chars: usize,
) -> Result<String> {
    let line = load_content_line(indexer, reader, line_idx, preview_chars)?;
    Ok(line.text)
}

fn decode_line_bytes(reader: &FileReader, bytes: &[u8]) -> String {
    let trimmed = bytes
        .strip_suffix(b"\r\n")
        .or_else(|| bytes.strip_suffix(b"\n"))
        .or_else(|| bytes.strip_suffix(b"\r"))
        .unwrap_or(bytes);

    match std::str::from_utf8(trimmed) {
        Ok(text) => text.to_string(),
        Err(_) => {
            let (cow, _, _) = reader.encoding().decode(trimmed);
            cow.into_owned()
        }
    }
}

fn clip_text(text: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }

    let mut chars = text.chars();
    let clipped: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        format!("{clipped}...")
    } else {
        clipped
    }
}

fn apply_line_offset(base_line_no: usize, offset: i32) -> Option<usize> {
    if offset >= 0 {
        base_line_no.checked_add(offset as usize)
    } else {
        base_line_no.checked_sub(offset.unsigned_abs() as usize)
    }
}

fn run_trace_backward_request(
    reader: &Arc<FileReader>,
    line_no: usize,
    target_kind: &McpTargetKind,
    target: &str,
    bit_lo: u8,
    bit_hi: u8,
    max_depth: usize,
    max_nodes: usize,
    per_branch_budget: usize,
    prune_equal_value_loads: bool,
) -> Result<BackwardTaintReport> {
    let streaming = StreamingTrace::new(reader.clone());
    let request = BackwardTaintRequest {
        target_kind: target_kind.as_target_kind(),
        line_no,
        reg: matches!(target_kind, McpTargetKind::Reg).then(|| target.to_string()),
        mem_expr: matches!(target_kind, McpTargetKind::Mem).then(|| target.to_string()),
        bit_lo,
        bit_hi,
        options: BackwardTaintOptions {
            max_depth,
            max_nodes,
            dedup: true,
            emit_linear_chains: true,
            per_branch_budget,
            prune_equal_value_loads,
        },
    };

    trace_backward_streaming(request, &streaming)
}

fn build_trace_hit_response(
    request: &SearchTraceRequest,
    reader: &FileReader,
    indexer: &LineIndexer,
    streaming: &StreamingTrace,
    hit: SearchLineHit,
) -> SearchTraceHit {
    let matched_line_no = hit.line_idx + 1;
    let analysis_line_no = apply_line_offset(matched_line_no, request.taint_line_offset);
    let preview = load_preview(indexer, reader, hit.line_idx, request.preview_chars)
        .unwrap_or_else(|err| format!("<preview unavailable: {err}>"));

    let Some(analysis_line_no) = analysis_line_no else {
        return SearchTraceHit {
            matched_line_no,
            analysis_line_no: 0,
            hit_count_on_line: hit.hit_count,
            preview,
            status: "error".to_string(),
            taint: None,
            root_sources: Vec::new(),
            error: Some("analysis line underflowed after applying taint_line_offset".to_string()),
        };
    };

    let taint_request = BackwardTaintRequest {
        target_kind: request.target_kind.as_target_kind(),
        line_no: analysis_line_no,
        reg: matches!(request.target_kind, McpTargetKind::Reg).then(|| request.target.clone()),
        mem_expr: matches!(request.target_kind, McpTargetKind::Mem).then(|| request.target.clone()),
        bit_lo: request.bit_lo,
        bit_hi: request.bit_hi,
        options: BackwardTaintOptions {
            max_depth: request.max_depth,
            max_nodes: request.max_nodes,
            dedup: true,
            emit_linear_chains: true,
            per_branch_budget: request.per_branch_budget,
            prune_equal_value_loads: request.prune_equal_value_loads,
        },
    };

    match trace_backward_streaming(taint_request, streaming) {
        Ok(report) => {
            let (taint, root_sources) =
                summarize_report(&report, request.max_root_sources_per_hit);
            SearchTraceHit {
                matched_line_no,
                analysis_line_no,
                hit_count_on_line: hit.hit_count,
                preview,
                status: "ok".to_string(),
                taint: Some(taint),
                root_sources,
                error: None,
            }
        }
        Err(err) => SearchTraceHit {
            matched_line_no,
            analysis_line_no,
            hit_count_on_line: hit.hit_count,
            preview,
            status: "error".to_string(),
            taint: None,
            root_sources: Vec::new(),
            error: Some(err.to_string()),
        },
    }
}

fn summarize_report(
    report: &BackwardTaintReport,
    max_root_sources: usize,
) -> (TaintSummary, Vec<RootSourceSummary>) {
    let summary = TaintSummary {
        target: report.summary.target.clone(),
        root_source_count: report.summary.root_source_count,
        exact_source_count: report.summary.exact_source_count,
        possible_source_count: report.summary.possible_source_count,
        unknown_source_count: report.summary.unknown_source_count,
        chain_count: report.summary.chain_count,
        truncated: report.summary.truncated,
        contains_unknown: report.summary.contains_unknown,
        contains_cycle: report.summary.contains_cycle,
    };
    let root_sources = report
        .graph
        .root_sources
        .iter()
        .take(max_root_sources)
        .map(to_root_source_summary)
        .collect();
    (summary, root_sources)
}

fn to_root_source_summary(root: &RootSource) -> RootSourceSummary {
    RootSourceSummary {
        label: root.label.clone(),
        explain: root.explain.clone(),
        confidence: format_confidence(&root.confidence).to_string(),
    }
}

fn count_matches_for_replace(
    input_path: &Path,
    encoding_override: Option<&str>,
    query: &str,
    use_regex: bool,
) -> Result<usize> {
    let metadata = fs::metadata(input_path)
        .with_context(|| format!("failed to inspect {}", input_path.display()))?;
    if metadata.len() == 0 {
        return Ok(0);
    }

    let opened = open_content_reader_with_encoding(input_path, encoding_override)?;
    let mut engine = SearchEngine::new();
    engine.set_query(query.to_string(), use_regex, use_regex);
    count_search_matches(&engine, opened.reader)
}

fn run_replace_all(
    input_path: &Path,
    output_path: &Path,
    query: &str,
    replacement: &str,
    use_regex: bool,
) -> Result<(usize, usize)> {
    let (tx, rx) = mpsc::channel();
    let cancel_token = Arc::new(AtomicBool::new(false));
    Replacer::replace_all(
        input_path,
        output_path,
        query,
        replacement,
        use_regex,
        tx,
        cancel_token,
    );

    let mut bytes_processed = 0usize;
    let mut total_bytes = fs::metadata(input_path)
        .with_context(|| format!("failed to inspect {}", input_path.display()))?
        .len() as usize;

    loop {
        match rx.recv() {
            Ok(ReplaceMessage::Progress(processed, total)) => {
                bytes_processed = processed;
                total_bytes = total;
            }
            Ok(ReplaceMessage::Done) => break,
            Ok(ReplaceMessage::Error(err)) => bail!("replace failed: {err}"),
            Err(_) => break,
        }
    }

    Ok((bytes_processed, total_bytes))
}

fn resolve_replace_output_path(
    input_path: &Path,
    output_file: Option<&str>,
    in_place: bool,
) -> Result<PathBuf> {
    if in_place {
        return Ok(input_path.to_path_buf());
    }

    if let Some(path) = output_file {
        return Ok(PathBuf::from(path));
    }

    let file_name = input_path
        .file_name()
        .and_then(|name| name.to_str())
        .context("input file must have a valid file name")?;
    Ok(input_path.with_file_name(format!("{file_name}.modified")))
}

fn temp_replace_output_path(input_path: &Path) -> PathBuf {
    let file_name = input_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("content-search");
    input_path.with_file_name(format!("{file_name}.mcp-replace.tmp"))
}

fn replace_path(temp_path: &Path, final_path: &Path) -> Result<()> {
    if fs::rename(temp_path, final_path).is_err() {
        if fs::remove_file(final_path).is_ok() {
            fs::rename(temp_path, final_path)?;
        } else {
            bail!(
                "failed to replace {} with {}",
                final_path.display(),
                temp_path.display()
            );
        }
    }
    Ok(())
}

impl IndexedContent {
    fn index_summary(&self) -> IndexSummary {
        IndexSummary {
            mode: format_index_mode(self.index_report.mode),
            cache_status: format_cache_status(self.index_report.cache_status),
            total_lines: self.index_report.total_lines,
        }
    }
}

fn format_index_mode(mode: IndexMode) -> String {
    match mode {
        IndexMode::Full => "full".to_string(),
        IndexMode::Sparse => "sparse".to_string(),
    }
}

fn format_cache_status(status: IndexCacheStatus) -> String {
    match status {
        IndexCacheStatus::Hit => "hit".to_string(),
        IndexCacheStatus::MissStored => "miss_stored".to_string(),
        IndexCacheStatus::MissSkipped => "miss_skipped".to_string(),
    }
}

fn format_confidence(confidence: &Confidence) -> &'static str {
    match confidence {
        Confidence::Exact => "exact",
        Confidence::Possible => "possible",
        Confidence::Unknown => "unknown",
    }
}

fn default_true() -> bool {
    true
}

fn default_max_matches() -> usize {
    DEFAULT_MAX_MATCHES
}

fn default_max_results() -> usize {
    DEFAULT_MAX_RESULTS
}

fn default_line_count() -> usize {
    DEFAULT_LINE_COUNT
}

fn default_bit_hi() -> u8 {
    63
}

fn default_max_depth() -> usize {
    DEFAULT_MAX_DEPTH
}

fn default_max_nodes() -> usize {
    DEFAULT_MAX_NODES
}

fn default_branch_budget() -> usize {
    DEFAULT_BRANCH_BUDGET
}

fn default_preview_chars() -> usize {
    DEFAULT_PREVIEW_CHARS
}

fn default_line_clip_chars() -> usize {
    DEFAULT_LINE_CLIP_CHARS
}

fn default_max_root_sources() -> usize {
    DEFAULT_MAX_ROOT_SOURCES
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn apply_line_offset_supports_positive_and_negative_offsets() {
        assert_eq!(apply_line_offset(10, 3), Some(13));
        assert_eq!(apply_line_offset(10, -3), Some(7));
        assert_eq!(apply_line_offset(2, -3), None);
    }

    #[test]
    fn clip_text_adds_ellipsis_when_truncated() {
        assert_eq!(clip_text("abcdef", 3), "abc...");
        assert_eq!(clip_text("abc", 3), "abc");
    }

    #[test]
    fn inspect_content_file_reports_index_summary() -> Result<()> {
        let mut file = NamedTempFile::new()?;
        write!(file, "alpha\nbeta\ngamma")?;

        let response = execute_inspect_content_file(InspectContentFileRequest {
            file_path: file.path().display().to_string(),
            encoding: None,
        })?;

        assert_eq!(response.total_lines, 3);
        assert_eq!(response.encoding, "UTF-8");
        assert_eq!(response.index.mode, "full");
        Ok(())
    }

    #[test]
    fn read_content_lines_returns_requested_window() -> Result<()> {
        let mut file = NamedTempFile::new()?;
        write!(file, "line-1\nline-2\nline-3\nline-4\n")?;

        let response = execute_read_content_lines(ReadContentLinesRequest {
            file_path: file.path().display().to_string(),
            encoding: None,
            start_line: 2,
            line_count: 2,
            clip_chars: 100,
        })?;

        assert_eq!(response.returned_lines, 2);
        assert_eq!(response.lines[0].line_no, 2);
        assert_eq!(response.lines[0].text, "line-2");
        assert_eq!(response.lines[1].line_no, 3);
        assert_eq!(response.lines[1].text, "line-3");
        Ok(())
    }

    #[test]
    fn search_content_counts_matches_and_reads_previews() -> Result<()> {
        let mut file = NamedTempFile::new()?;
        write!(file, "Error one\nok\nerror two\nERROR three\n")?;

        let response = execute_search_content(SearchContentRequest {
            file_path: file.path().display().to_string(),
            encoding: None,
            query: "error".to_string(),
            use_regex: false,
            case_sensitive: false,
            start_offset: 0,
            max_results: 10,
            include_total_count: true,
            collapse_by_line: false,
            preview_chars: 120,
        })?;

        assert_eq!(response.total_matches, Some(3));
        assert_eq!(response.returned_matches, 3);
        assert_eq!(response.matches[0].line_no, 1);
        assert!(response.matches[2].preview.contains("ERROR three"));
        Ok(())
    }

    #[test]
    fn replace_content_match_writes_modified_copy() -> Result<()> {
        let mut file = NamedTempFile::new()?;
        write!(file, "Hello trace")?;
        let output = file.path().with_file_name("hello-trace.modified.txt");

        let response = execute_replace_content_match(ReplaceContentMatchRequest {
            input_file: file.path().display().to_string(),
            output_file: Some(output.display().to_string()),
            in_place: false,
            byte_offset: 6,
            match_len: 5,
            replacement: "world".to_string(),
        })?;

        let content = fs::read_to_string(&output)?;
        assert_eq!(content, "Hello world");
        assert_eq!(response.output_file, output.display().to_string());
        let _ = fs::remove_file(output);
        Ok(())
    }

    #[test]
    fn replace_content_all_can_rewrite_in_place() -> Result<()> {
        let mut file = NamedTempFile::new()?;
        write!(file, "foo\nfoo\nbar\n")?;

        let response = execute_replace_content_all(ReplaceContentAllRequest {
            input_file: file.path().display().to_string(),
            encoding: None,
            output_file: None,
            in_place: true,
            query: "foo".to_string(),
            replacement: "baz".to_string(),
            use_regex: false,
        })?;

        let content = fs::read_to_string(file.path())?;
        assert_eq!(content, "baz\nbaz\nbar\n");
        assert_eq!(response.match_count_before_replace, 2);
        assert!(response.in_place);
        Ok(())
    }

    #[test]
    fn trace_backward_returns_summary_and_report_json() -> Result<()> {
        let mut file = NamedTempFile::new()?;
        write!(
            file,
            "1 | 0x1000 | movz w1, #0xAA | w1=0xAA\n\
2 | 0x1004 | movz w2, #0xBB | w2=0xBB\n\
3 | 0x1008 | strb w1, [x10] | x10=0x3000 w1=0xAA mw=0x3000:[AA]\n\
4 | 0x100c | strb w2, [x10, #0x1] | x10=0x3000 w2=0xBB mw=0x3001:[BB]\n\
5 | 0x1010 | ldrh w8, [x11] | x11=0x3000 mr=0x3000:[AABB] w8=0xBBAA"
        )?;

        let response = execute_trace_backward(TraceBackwardToolRequest {
            trace_file: file.path().display().to_string(),
            encoding: None,
            line_no: 5,
            target_kind: McpTargetKind::Reg,
            target: "w8".to_string(),
            bit_lo: 0,
            bit_hi: 15,
            max_depth: DEFAULT_MAX_DEPTH,
            max_nodes: DEFAULT_MAX_NODES,
            per_branch_budget: DEFAULT_BRANCH_BUDGET,
            prune_equal_value_loads: true,
            max_root_sources: 5,
        })?;

        assert_eq!(response.line_no, 5);
        assert!(response.summary.root_source_count >= 1);
        assert!(response.report_json.contains("\"summary\""));
        Ok(())
    }
}
