pub mod engine;
pub mod indexer;
pub mod normalizer;
pub mod parser;
pub mod report;
pub mod streaming;

use anyhow::Result;
use serde::Serialize;
use std::collections::BTreeMap;

pub use engine::{trace_backward, trace_backward_streaming};
pub use indexer::build_trace_index;
pub use normalizer::{parse_trace_from_reader, parse_trace_text};
pub use report::report_to_json;
pub use streaming::StreamingTrace;

#[derive(Debug, Clone, Serialize)]
pub struct TraceInstRaw {
    pub source_line: usize,
    pub line_no: usize,
    pub pc: Option<u64>,
    pub inst_text: String,
    pub annotation_text: String,
    pub raw_text: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum RegView {
    W,
    X,
    SP,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RegRef {
    pub name: String,
    pub base: String,
    pub view: RegView,
    pub bit_lo: u8,
    pub bit_hi: u8,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum MemAccessKind {
    Read,
    Write,
}

#[derive(Debug, Clone, Serialize)]
pub struct MemAccess {
    pub kind: MemAccessKind,
    pub expr: String,
    pub base_reg: Option<String>,
    pub offset_reg: Option<String>,
    pub offset_imm: Option<i64>,
    pub slot_name: String,
    pub match_key: String,
    pub abs_addr: Option<u64>,
    pub data_hex: Option<String>,
    pub size_bits: u16,
}

#[derive(Debug, Clone, Serialize)]
pub struct TraceInst {
    pub source_line: usize,
    pub line_no: usize,
    pub index: usize,
    pub pc: u64,
    pub mnemonic: String,
    pub operands_raw: String,
    pub operands: Vec<String>,
    pub inst_text: String,
    pub dst_regs: Vec<RegRef>,
    pub src_regs: Vec<RegRef>,
    pub mem_read: Option<MemAccess>,
    pub mem_write: Option<MemAccess>,
    pub imm_values: Vec<i64>,
    pub shift: Option<u8>,
    pub cond: Option<String>,
    pub sets_flags: bool,
    pub reg_value_map: BTreeMap<String, u64>,
    pub raw_annotation: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum TargetKind {
    RegSlice,
    MemSlice,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum Confidence {
    Exact,
    Possible,
    Unknown,
}

impl Default for Confidence {
    fn default() -> Self {
        Confidence::Exact
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct GuardContext {
    pub expr: String,
    pub value: Option<bool>,
    pub confidence: Confidence,
    pub source_line: Option<usize>,
    pub source_pc: Option<u64>,
    pub source_inst: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackwardTaintOptions {
    pub max_depth: usize,
    pub max_nodes: usize,
    pub dedup: bool,
    pub emit_linear_chains: bool,
    pub per_branch_budget: usize,
    pub prune_equal_value_loads: bool,
}

impl Default for BackwardTaintOptions {
    fn default() -> Self {
        Self {
            max_depth: 64,
            max_nodes: 2000,
            dedup: true,
            emit_linear_chains: true,
            per_branch_budget: 500,
            prune_equal_value_loads: true,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct BackwardTaintRequest {
    pub target_kind: TargetKind,
    pub line_no: usize,
    pub reg: Option<String>,
    pub mem_expr: Option<String>,
    pub bit_lo: u8,
    pub bit_hi: u8,
    pub options: BackwardTaintOptions,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum SliceNodeKind {
    Reg,
    Mem,
    Imm,
    Static,
    Arg,
    RetVal,
    MemLiveIn,
    Unknown,
    UnknownLiveIn,
    UnknownPreTrace,
    UnknownAlias,
    UnknownTruncated,
    UnknownUnsupported,
}

impl SliceNodeKind {
    pub fn is_unknown_variant(&self) -> bool {
        matches!(
            self,
            SliceNodeKind::Unknown
                | SliceNodeKind::UnknownLiveIn
                | SliceNodeKind::UnknownPreTrace
                | SliceNodeKind::UnknownAlias
                | SliceNodeKind::UnknownTruncated
                | SliceNodeKind::UnknownUnsupported
        )
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            SliceNodeKind::Imm
                | SliceNodeKind::Static
                | SliceNodeKind::Arg
                | SliceNodeKind::RetVal
                | SliceNodeKind::MemLiveIn
        ) || self.is_unknown_variant()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SliceNode {
    pub id: usize,
    pub kind: SliceNodeKind,
    pub name: String,
    pub line_no: usize,
    pub version: usize,
    pub bit_lo: u8,
    pub bit_hi: u8,
    pub value_hex: Option<String>,
    pub meta: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum EdgeReason {
    Read,
    Write,
    Calc,
    Imm,
    Call,
    Phi,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct TaintEdge {
    pub id: usize,
    pub src_node_id: usize,
    pub dst_node_id: usize,
    pub reason: EdgeReason,
    pub inst_line: usize,
    pub inst_pc: u64,
    pub inst_text: String,
    pub note: String,
    pub branch_group: Option<String>,
    pub confidence: Confidence,
    pub guard: Option<GuardContext>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RootSource {
    pub node_id: usize,
    pub root_kind: SliceNodeKind,
    pub label: String,
    pub explain: String,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, Serialize)]
pub struct GraphStats {
    pub total_nodes: usize,
    pub total_edges: usize,
    pub truncated: bool,
    pub cycle_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct GraphReport {
    pub target: SliceNode,
    pub nodes: Vec<SliceNode>,
    pub edges: Vec<TaintEdge>,
    pub root_sources: Vec<RootSource>,
    pub stats: GraphStats,
}

#[derive(Debug, Clone, Serialize)]
pub struct TraceStep {
    pub step_id: usize,
    pub order: usize,
    pub kind: EdgeReason,
    pub line_no: usize,
    pub pc: u64,
    pub inst_text: String,
    pub dst: String,
    pub srcs: Vec<String>,
    pub mem_addr: Option<String>,
    pub data_hex: Option<String>,
    pub note: String,
    pub parent_step_ids: Vec<usize>,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, Serialize)]
pub struct LinearChain {
    pub chain_id: usize,
    pub root_node_id: usize,
    pub node_ids: Vec<usize>,
    pub edge_ids: Vec<usize>,
    pub pretty: String,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, Serialize)]
pub struct SummaryReport {
    pub target: String,
    pub root_source_count: usize,
    pub exact_source_count: usize,
    pub possible_source_count: usize,
    pub unknown_source_count: usize,
    pub chain_count: usize,
    pub exact_chain_count: usize,
    pub contains_unknown: bool,
    pub contains_cycle: bool,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct DataFlowNode {
    pub value: String,
    pub name: String,
    pub kind: String,
    pub source_line: usize,
    pub pc: String,
    pub inst: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<DataFlowNode>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackwardTaintReport {
    pub request: BackwardTaintRequest,
    pub summary: SummaryReport,
    pub data_flow: DataFlowNode,
    #[serde(skip_serializing)]
    pub graph: GraphReport,
    #[serde(skip_serializing)]
    pub steps: Vec<TraceStep>,
    #[serde(skip_serializing)]
    pub chains: Vec<LinearChain>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MemoryWriteEvent {
    pub inst_index: usize,
    pub line_no: usize,
    pub abs_addr: u64,
    pub size_bytes: u16,
    pub match_key: String,
    pub slot_name: String,
    pub src_reg_base: Option<String>,
    pub data_hex: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ByteCoverageGroup {
    pub byte_offset: u16,
    pub byte_count: u16,
    pub write_event_idx: usize,
    pub bit_lo: u8,
    pub bit_hi: u8,
}

pub(crate) fn bit_label(bit_lo: u8, bit_hi: u8) -> String {
    format!("[{}:{}]", bit_hi, bit_lo)
}

pub(crate) fn node_label(node: &SliceNode) -> String {
    format!("{}{}", node.name, bit_label(node.bit_lo, node.bit_hi))
}

pub fn parse_trace_to_json(input: &str) -> Result<String> {
    let insts = parse_trace_text(input)?;
    Ok(serde_json::to_string_pretty(&insts)?)
}
