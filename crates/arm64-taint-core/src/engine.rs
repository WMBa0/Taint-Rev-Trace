use crate::indexer::TraceIndex;
use crate::normalizer::parse_reg;
use crate::report::build_report;
use crate::streaming::{PrecomputedSource, StreamingTrace, TraceSource};
use crate::{
    BackwardTaintReport, BackwardTaintRequest, Confidence, EdgeReason, GuardContext, MemAccess,
    RegRef, RegView, SliceNode, SliceNodeKind, TaintEdge, TraceInst,
};
use anyhow::Result;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BinaryHeap, HashMap, HashSet};

#[derive(Debug, Clone)]
struct PendingNode {
    node_id: usize,
    depth: usize,
    priority: u8,
}

impl PendingNode {
    fn new(node_id: usize, depth: usize, confidence: &Confidence) -> Self {
        let priority = match confidence {
            Confidence::Exact => 0,
            Confidence::Possible => 1,
            Confidence::Unknown => 2,
        };
        Self {
            node_id,
            depth,
            priority,
        }
    }
}

impl Eq for PendingNode {}

impl PartialEq for PendingNode {
    fn eq(&self, other: &Self) -> bool {
        self.priority == other.priority && self.depth == other.depth
    }
}

impl Ord for PendingNode {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .priority
            .cmp(&self.priority)
            .then_with(|| other.depth.cmp(&self.depth))
    }
}

impl PartialOrd for PendingNode {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

struct EngineState<'a> {
    req: &'a BackwardTaintRequest,
    source: &'a dyn TraceSource,
    nodes: Vec<SliceNode>,
    edges: Vec<TaintEdge>,
    node_keys: HashMap<String, usize>,
    expanded: HashSet<usize>,
    incoming: HashMap<usize, Vec<usize>>,
    branch_counts: HashMap<String, usize>,
    truncated: bool,
    cycle_count: usize,
}

#[derive(Clone)]
struct GuardResolution {
    taken_idx: Option<usize>,
    source_line: Option<usize>,
    source_pc: Option<u64>,
    source_inst: Option<String>,
}

struct PrunedLoadSource {
    reg: RegRef,
    search_line: usize,
    bit_lo: u8,
    bit_hi: u8,
    note: String,
}

struct FlagState {
    n: bool,
    z: bool,
    c: Option<bool>,
    v: Option<bool>,
}

pub fn trace_backward(
    req: BackwardTaintRequest,
    insts: &[TraceInst],
    index: &TraceIndex,
) -> Result<BackwardTaintReport> {
    let source = PrecomputedSource { insts, index };
    run_engine(req, &source)
}

pub fn trace_backward_streaming(
    req: BackwardTaintRequest,
    streaming: &StreamingTrace,
) -> Result<BackwardTaintReport> {
    run_engine(req, streaming)
}

fn run_engine(req: BackwardTaintRequest, source: &dyn TraceSource) -> Result<BackwardTaintReport> {
    let req_for_engine = req.clone();
    let mut state = EngineState::new(&req_for_engine, source);
    let target_id = state.make_target_node()?;
    let mut worklist =
        BinaryHeap::from([PendingNode::new(target_id, 0, &Confidence::Exact)]);

    while let Some(item) = worklist.pop() {
        if state.expanded.contains(&item.node_id) {
            continue;
        }
        state.expanded.insert(item.node_id);

        if item.depth >= req.options.max_depth {
            state.truncated = true;
            state.attach_typed_unknown(
                item.node_id,
                SliceNodeKind::UnknownTruncated,
                "max_depth reached",
                None,
                None,
            );
            continue;
        }

        if state.nodes.len() >= req.options.max_nodes {
            state.truncated = true;
            state.attach_typed_unknown(
                item.node_id,
                SliceNodeKind::UnknownTruncated,
                "max_nodes reached",
                None,
                None,
            );
            continue;
        }

        let next = state.expand_node(item.node_id)?;
        for (node_id, conf) in next {
            worklist.push(PendingNode::new(node_id, item.depth + 1, &conf));
        }
    }

    build_report(
        req,
        target_id,
        state.nodes,
        state.edges,
        state.truncated,
        state.cycle_count,
    )
}

impl<'a> EngineState<'a> {
    fn new(req: &'a BackwardTaintRequest, source: &'a dyn TraceSource) -> Self {
        Self {
            req,
            source,
            nodes: Vec::new(),
            edges: Vec::new(),
            node_keys: HashMap::new(),
            expanded: HashSet::new(),
            incoming: HashMap::new(),
            branch_counts: HashMap::new(),
            truncated: false,
            cycle_count: 0,
        }
    }

    fn make_target_node(&mut self) -> Result<usize> {
        match self.req.target_kind {
            crate::TargetKind::RegSlice => {
                let reg_name = self
                    .req
                    .reg
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("missing target reg"))?;
                let reg = parse_reg(reg_name)
                    .ok_or_else(|| anyhow::anyhow!("invalid target reg: {reg_name}"))?;
                Ok(self.add_node(SliceNode {
                    id: 0,
                    kind: SliceNodeKind::Reg,
                    name: reg.name.clone(),
                    line_no: self.req.line_no,
                    version: self.resolve_reg_version(&reg.base, self.req.line_no),
                    bit_lo: self.req.bit_lo,
                    bit_hi: self.req.bit_hi,
                    value_hex: self.resolve_reg_value_hex(&reg.base, self.req.line_no),
                    meta: reg_meta(&reg),
                }))
            }
            crate::TargetKind::MemSlice => {
                let expr = self
                    .req
                    .mem_expr
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("missing target mem_expr"))?;
                let mem = fake_mem_access(
                    &expr,
                    self.req.bit_hi.saturating_sub(self.req.bit_lo) as u16 + 1,
                );
                Ok(self.add_node(SliceNode {
                    id: 0,
                    kind: SliceNodeKind::Mem,
                    name: mem.slot_name.clone(),
                    line_no: self.req.line_no,
                    version: self.resolve_mem_version(&mem.match_key, self.req.line_no),
                    bit_lo: self.req.bit_lo,
                    bit_hi: self.req.bit_hi,
                    value_hex: mem.data_hex.clone(),
                    meta: mem_meta(&mem),
                }))
            }
        }
    }

    fn add_node(&mut self, mut node: SliceNode) -> usize {
        let key = format!(
            "{:?}|{}|{}|{}|{}|{}|{}",
            node.kind,
            node.name,
            node.line_no,
            node.version,
            node.bit_lo,
            node.bit_hi,
            node.value_hex.clone().unwrap_or_default()
        );

        if self.req.options.dedup {
            if let Some(existing) = self.node_keys.get(&key) {
                return *existing;
            }
        }

        node.id = self.nodes.len() + 1;
        let node_id = node.id;
        self.nodes.push(node);
        self.node_keys.insert(key, node_id);
        node_id
    }

    fn add_edge(
        &mut self,
        src_node_id: usize,
        dst_node_id: usize,
        reason: EdgeReason,
        inst: Option<&TraceInst>,
        note: String,
        branch_group: Option<String>,
        confidence: Confidence,
        guard: Option<GuardContext>,
    ) {
        if src_node_id == dst_node_id {
            self.cycle_count += 1;
            return;
        }

        if let Some(bg) = &branch_group {
            *self.branch_counts.entry(bg.clone()).or_default() += 1;
        }

        let edge = TaintEdge {
            id: self.edges.len() + 1,
            src_node_id,
            dst_node_id,
            reason,
            inst_line: inst.map(|i| i.line_no).unwrap_or(0),
            inst_pc: inst.map(|i| i.pc).unwrap_or(0),
            inst_text: inst
                .map(|i| i.inst_text.clone())
                .unwrap_or_else(|| "synthetic".to_string()),
            note,
            branch_group,
            confidence,
            guard,
        };
        self.incoming.entry(dst_node_id).or_default().push(edge.id);
        self.edges.push(edge);
    }

    fn expand_node(&mut self, node_id: usize) -> Result<Vec<(usize, Confidence)>> {
        let node = self.nodes[node_id - 1].clone();
        match node.kind {
            SliceNodeKind::Reg => self.expand_reg_node(&node),
            SliceNodeKind::Mem => self.expand_mem_node(&node),
            _ if node.kind.is_terminal() => Ok(Vec::new()),
            _ => Ok(Vec::new()),
        }
    }

    fn expand_reg_node(&mut self, node: &SliceNode) -> Result<Vec<(usize, Confidence)>> {
        let base = node
            .meta
            .get("base")
            .cloned()
            .unwrap_or_else(|| node.name.clone());
        if base == "xzr" {
            let source_id = self.make_imm_node(
                "0x0".to_string(),
                node.line_no,
                node.bit_lo,
                node.bit_hi,
                BTreeMap::from([("reason".to_string(), "zero register".to_string())]),
            );
            self.add_edge(
                source_id,
                node.id,
                EdgeReason::Imm,
                None,
                "zero register constant".to_string(),
                None,
                Confidence::Exact,
                None,
            );
            return Ok(vec![(source_id, Confidence::Exact)]);
        }
        let Some((def_line, inst)) = self.source.find_reg_def(&base, node.line_no) else {
            let kind = if is_arg_reg(&base) {
                SliceNodeKind::Arg
            } else {
                SliceNodeKind::UnknownLiveIn
            };
            let label = if kind == SliceNodeKind::Arg {
                format!("arg_{base}")
            } else {
                format!("unknown_{base}")
            };
            let source_id = self.add_node(SliceNode {
                id: 0,
                kind: kind.clone(),
                name: label,
                line_no: node.line_no,
                version: 0,
                bit_lo: node.bit_lo,
                bit_hi: node.bit_hi,
                value_hex: None,
                meta: BTreeMap::from([(
                    "reason".to_string(),
                    "no previous register definition".to_string(),
                )]),
            });
            let edge_conf = if kind == SliceNodeKind::Arg {
                Confidence::Exact
            } else {
                Confidence::Unknown
            };
            self.add_edge(
                source_id,
                node.id,
                EdgeReason::Unknown,
                None,
                "register source unavailable in trace".to_string(),
                None,
                edge_conf.clone(),
                None,
            );
            return Ok(vec![(source_id, edge_conf)]);
        };

        let dst_reg = inst
            .dst_regs
            .iter()
            .find(|r| r.base == base)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("def instruction for {base} has no matching dst"))?;
        let prev_line = self.source.nearest_prev_line(inst.line_no);
        let mut pending: Vec<(usize, Confidence)> = Vec::new();

        if dst_reg.view == RegView::W && node.bit_hi > 31 {
            if let Some((hi_lo, hi_hi)) = intersect_range(node.bit_lo, node.bit_hi, 32, 63) {
                let source_id = self.make_imm_node(
                    "0x0".to_string(),
                    inst.line_no,
                    hi_lo,
                    hi_hi,
                    BTreeMap::from([(
                        "reason".to_string(),
                        "w write clears upper 32 bits".to_string(),
                    )]),
                );
                self.add_edge(
                    source_id,
                    node.id,
                    EdgeReason::Imm,
                    Some(&inst),
                    "upper bits zeroed by W register write".to_string(),
                    None,
                    Confidence::Exact,
                    None,
                );
                pending.push((source_id, Confidence::Exact));
            }
        }

        let Some((use_lo, use_hi)) =
            intersect_range(node.bit_lo, node.bit_hi, 0, dst_reg.bit_hi)
        else {
            return Ok(pending);
        };

        match inst.mnemonic.as_str() {
            "mov" => {
                if let Some(src) = inst.src_regs.first() {
                    let id = self.link_reg_source(
                        src,
                        use_lo,
                        use_hi,
                        node.id,
                        &inst,
                        prev_line,
                        EdgeReason::Calc,
                        "register move".to_string(),
                        None,
                        Confidence::Exact,
                        None,
                    );
                    pending.push((id, Confidence::Exact));
                } else if let Some(imm) = inst.imm_values.first() {
                    let id = self.link_imm_source(
                        *imm,
                        use_lo,
                        use_hi,
                        node.id,
                        &inst,
                        "move immediate".to_string(),
                        Confidence::Exact,
                    );
                    pending.push((id, Confidence::Exact));
                }
            }
            "orr" if is_zero_register_operands(&inst.operands) => {
                if let Some(src) = inst.src_regs.first() {
                    let id = self.link_reg_source(
                        src,
                        use_lo,
                        use_hi,
                        node.id,
                        &inst,
                        prev_line,
                        EdgeReason::Calc,
                        "register alias move".to_string(),
                        None,
                        Confidence::Exact,
                        None,
                    );
                    pending.push((id, Confidence::Exact));
                }
            }
            "add" | "sub" | "and" | "eor" | "orr" | "lsl" | "lsr" | "asr"
            | "orn" | "bic" | "eon" | "neg" | "mvn"
            | "mul" | "madd" | "msub" | "umulh" | "smulh" | "mneg"
            | "ror" | "rev" | "rev16" | "rev32" | "rbit" | "clz" | "cls"
            | "extr" | "bfm" | "sxtb" | "sxth" | "sxtw" | "uxtb" | "uxth" => {
                if inst.mnemonic == "add" {
                    if let Some(static_id) =
                        self.try_expand_adrp_add(node, &inst, use_lo, use_hi)
                    {
                        self.add_edge(
                            static_id,
                            node.id,
                            EdgeReason::Calc,
                            Some(&inst),
                            "adrp+add static address construction".to_string(),
                            None,
                            Confidence::Exact,
                            None,
                        );
                        pending.push((static_id, Confidence::Exact));
                        return Ok(pending);
                    }
                }

                for (src_idx, src) in inst.src_regs.iter().enumerate() {
                    // For register-based shifts like `lsr x8, x8, x1`, the shift-count
                    // operand acts as an effective immediate once its concrete runtime
                    // value is known from the trace annotation.
                    if matches!(inst.mnemonic.as_str(), "lsl" | "lsr" | "asr") && src_idx == 1 {
                        if let Some(shift_value) = inst
                            .reg_value_map
                            .get(&src.base)
                            .or_else(|| inst.reg_value_map.get(&src.name))
                            .copied()
                        {
                            let id = self.link_imm_source(
                                shift_value as i64,
                                use_lo,
                                use_hi,
                                node.id,
                                &inst,
                                "register shift amount".to_string(),
                                Confidence::Exact,
                            );
                            pending.push((id, Confidence::Exact));
                            continue;
                        }
                    }

                    let search_line = if src.base == base {
                        prev_line
                    } else {
                        inst.line_no
                    };
                    let note = if inst.mnemonic == "add" || inst.mnemonic == "sub" {
                        if self.source.is_pointer_like_use(&dst_reg, def_line) {
                            "pointer_arithmetic".to_string()
                        } else {
                            "arithmetic input".to_string()
                        }
                    } else {
                        "calculation input".to_string()
                    };
                    let branch = Some(format!("{}:{src_idx}", inst.line_no));
                    let id = self.link_reg_source(
                        src,
                        use_lo,
                        use_hi.min(src.bit_hi),
                        node.id,
                        &inst,
                        search_line,
                        EdgeReason::Calc,
                        note,
                        branch,
                        Confidence::Exact,
                        None,
                    );
                    pending.push((id, Confidence::Exact));
                }
                for imm in &inst.imm_values {
                    let id = self.link_imm_source(
                        *imm,
                        use_lo,
                        use_hi,
                        node.id,
                        &inst,
                        if inst.mnemonic == "add" || inst.mnemonic == "sub" {
                            "arithmetic immediate".to_string()
                        } else {
                            "calculation immediate".to_string()
                        },
                        Confidence::Exact,
                    );
                    pending.push((id, Confidence::Exact));
                }
            }
            "ubfx" | "sbfx" | "ubfm" | "sbfm" => {
                if let Some(src) = inst.src_regs.first() {
                    let search_line = if src.base == base {
                        prev_line
                    } else {
                        inst.line_no
                    };
                    let id = self.link_reg_source(
                        src,
                        use_lo,
                        use_hi.min(src.bit_hi),
                        node.id,
                        &inst,
                        search_line,
                        EdgeReason::Calc,
                        "bitfield extract".to_string(),
                        None,
                        Confidence::Exact,
                        None,
                    );
                    pending.push((id, Confidence::Exact));
                }
            }
            "ldr" | "ldrb" | "ldrh" | "ldrsw" | "ldrsh" | "ldrsb"
            | "ldur" | "ldurb" | "ldurh" | "ldursw" | "ldursh" | "ldursb"
            | "ldar" | "ldarb" | "ldarh" => {
                if let Some(mem) = &inst.mem_read {
                    if let Some(pruned) =
                        self.try_prune_equal_value_load(node, &inst, mem, use_lo, use_hi)
                    {
                        let source_id = self.link_reg_source(
                            &pruned.reg,
                            pruned.bit_lo,
                            pruned.bit_hi,
                            node.id,
                            &inst,
                            pruned.search_line,
                            EdgeReason::Read,
                            pruned.note,
                            None,
                            Confidence::Exact,
                            None,
                        );
                        pending.push((source_id, Confidence::Exact));
                    } else {
                        let source_id = self.make_mem_node(mem, inst.line_no, use_lo, use_hi);
                        self.add_edge(
                            source_id,
                            node.id,
                            EdgeReason::Read,
                            Some(&inst),
                            format!("{} loaded from {}", node.name, mem.slot_name),
                            None,
                            Confidence::Exact,
                            None,
                        );
                        pending.push((source_id, Confidence::Exact));
                    }
                } else {
                    let id = self.attach_typed_unknown(
                        node.id,
                        SliceNodeKind::UnknownUnsupported,
                        "load missing memory metadata",
                        Some(&inst),
                        Some("read source could not be resolved".to_string()),
                    );
                    pending.push((id, Confidence::Unknown));
                }
            }
            "ldp" => {
                if let Some(mem) = &inst.mem_read {
                    let dst_idx = inst
                        .dst_regs
                        .iter()
                        .position(|r| r.base == base)
                        .unwrap_or(0);
                    let lane_offset = (dst_idx * 64) as u8;
                    let source_id = self.make_mem_node(
                        mem,
                        inst.line_no,
                        use_lo.saturating_add(lane_offset),
                        use_hi.saturating_add(lane_offset),
                    );
                    self.add_edge(
                        source_id,
                        node.id,
                        EdgeReason::Read,
                        Some(&inst),
                        format!(
                            "{} loaded from {} lane {}",
                            node.name, mem.slot_name, dst_idx
                        ),
                        Some(format!("{}:ldp:{dst_idx}", inst.line_no)),
                        Confidence::Exact,
                        None,
                    );
                    pending.push((source_id, Confidence::Exact));
                } else {
                    let id = self.attach_typed_unknown(
                        node.id,
                        SliceNodeKind::UnknownUnsupported,
                        "ldp missing memory metadata",
                        Some(&inst),
                        Some("paired read source could not be resolved".to_string()),
                    );
                    pending.push((id, Confidence::Unknown));
                }
            }
            "movz" | "movn" => {
                let shift = inst.shift.unwrap_or(0);
                let insert_lo = shift;
                let insert_hi = shift.saturating_add(15);
                if let Some((bit_lo, bit_hi)) =
                    intersect_range(use_lo, use_hi, insert_lo, insert_hi)
                {
                    let imm = inst.imm_values.first().copied().unwrap_or_default();
                    let id = self.link_imm_source(
                        imm,
                        bit_lo,
                        bit_hi,
                        node.id,
                        &inst,
                        if inst.mnemonic == "movn" {
                            "movn immediate complement".to_string()
                        } else {
                            "movz immediate".to_string()
                        },
                        Confidence::Exact,
                    );
                    pending.push((id, Confidence::Exact));
                }
            }
            "movk" => {
                let shift = inst.shift.unwrap_or(0);
                let insert_lo = shift;
                let insert_hi = shift.saturating_add(15);
                if let Some((bit_lo, bit_hi)) =
                    intersect_range(use_lo, use_hi, insert_lo, insert_hi)
                {
                    let imm = inst.imm_values.first().copied().unwrap_or_default();
                    let id = self.link_imm_source(
                        imm,
                        bit_lo,
                        bit_hi,
                        node.id,
                        &inst,
                        "movk immediate overwrite".to_string(),
                        Confidence::Exact,
                    );
                    pending.push((id, Confidence::Exact));
                }
                if let Some((bit_lo, bit_hi)) =
                    subtract_inserted_range(use_lo, use_hi, insert_lo, insert_hi)
                {
                    let old = RegRef {
                        name: node.name.clone(),
                        base: base.clone(),
                        view: dst_reg.view.clone(),
                        bit_lo,
                        bit_hi,
                    };
                    let id = self.link_reg_source(
                        &old,
                        bit_lo,
                        bit_hi,
                        node.id,
                        &inst,
                        prev_line,
                        EdgeReason::Calc,
                        "movk preserves old bits".to_string(),
                        Some(format!("{}:old", inst.line_no)),
                        Confidence::Exact,
                        None,
                    );
                    pending.push((id, Confidence::Exact));
                }
            }
            "csel" => {
                let cond_str = inst.cond.clone().unwrap_or_default();
                let guard_resolution = self.resolve_csel_guard(&inst);
                let taken_idx = guard_resolution
                    .as_ref()
                    .and_then(|guard| guard.taken_idx)
                    .or_else(|| {
                        let dst_val = inst
                            .reg_value_map
                            .get(&base)
                            .or_else(|| inst.reg_value_map.get(&dst_reg.name))
                            .copied();
                        let src_vals: Vec<Option<u64>> = inst
                            .src_regs
                            .iter()
                            .take(2)
                            .map(|src| inst.reg_value_map.get(&src.base).copied())
                            .collect();
                        dst_val.and_then(|dv| src_vals.iter().position(|sv| *sv == Some(dv)))
                    });

                for (src_idx, src) in inst.src_regs.iter().take(2).enumerate() {
                    let (conf, guard_value) = match taken_idx {
                        Some(ti) if src_idx == ti => (Confidence::Exact, Some(true)),
                        Some(_) => (Confidence::Possible, Some(false)),
                        None => (Confidence::Possible, None),
                    };

                    let guard = Some(GuardContext {
                        expr: cond_str.clone(),
                        value: guard_value,
                        confidence: conf.clone(),
                        source_line: guard_resolution.as_ref().and_then(|guard| guard.source_line),
                        source_pc: guard_resolution.as_ref().and_then(|guard| guard.source_pc),
                        source_inst: guard_resolution
                            .as_ref()
                            .and_then(|guard| guard.source_inst.clone()),
                    });

                    let id = self.link_reg_source(
                        src,
                        use_lo,
                        use_hi,
                        node.id,
                        &inst,
                        inst.line_no,
                        EdgeReason::Phi,
                        format!(
                            "conditional source {} ({})",
                            cond_str,
                            if guard_value == Some(true) {
                                "taken"
                            } else if guard_value == Some(false) {
                                "alt"
                            } else {
                                "undetermined"
                            }
                        ),
                        Some(format!("{}:{src_idx}", inst.line_no)),
                        conf.clone(),
                        guard,
                    );
                    pending.push((id, conf));
                }
            }
            "adrp" | "adr" => {
                let source_id = self.add_node(SliceNode {
                    id: 0,
                    kind: SliceNodeKind::Static,
                    name: format!(
                        "static_{}",
                        inst.operands.get(1).cloned().unwrap_or_default()
                    ),
                    line_no: inst.line_no,
                    version: 0,
                    bit_lo: use_lo,
                    bit_hi: use_hi,
                    value_hex: inst
                        .reg_value_map
                        .get(&node.name)
                        .copied()
                        .or_else(|| inst.reg_value_map.get(&base).copied())
                        .map(|v| format!("0x{v:x}")),
                    meta: BTreeMap::from([(
                        "reason".to_string(),
                        format!("{} static base", inst.mnemonic),
                    )]),
                });
                self.add_edge(
                    source_id,
                    node.id,
                    EdgeReason::Imm,
                    Some(&inst),
                    format!("{} static address", inst.mnemonic),
                    None,
                    Confidence::Exact,
                    None,
                );
                pending.push((source_id, Confidence::Exact));
            }
            "bl" => {
                if base == "x0" {
                    let source_id = self.add_node(SliceNode {
                        id: 0,
                        kind: SliceNodeKind::RetVal,
                        name: format!(
                            "retval_{}",
                            inst.operands
                                .first()
                                .cloned()
                                .unwrap_or_else(|| format!("pc_{:x}", inst.pc))
                        ),
                        line_no: inst.line_no,
                        version: 0,
                        bit_lo: use_lo,
                        bit_hi: use_hi,
                        value_hex: None,
                        meta: BTreeMap::from([(
                            "reason".to_string(),
                            "function return value".to_string(),
                        )]),
                    });
                    self.add_edge(
                        source_id,
                        node.id,
                        EdgeReason::Call,
                        Some(&inst),
                        "value returned by call".to_string(),
                        None,
                        Confidence::Exact,
                        None,
                    );
                    pending.push((source_id, Confidence::Exact));
                } else {
                    let id = self.attach_typed_unknown(
                        node.id,
                        SliceNodeKind::UnknownUnsupported,
                        "call output not modeled for this register",
                        Some(&inst),
                        None,
                    );
                    pending.push((id, Confidence::Unknown));
                }
            }
            _ => {
                let id = self.attach_typed_unknown(
                    node.id,
                    SliceNodeKind::UnknownUnsupported,
                    &format!("unhandled opcode {}", inst.mnemonic),
                    Some(&inst),
                    Some("instruction rule not implemented".to_string()),
                );
                pending.push((id, Confidence::Unknown));
            }
        }

        Ok(pending)
    }

    fn expand_mem_node(&mut self, node: &SliceNode) -> Result<Vec<(usize, Confidence)>> {
        let key = node
            .meta
            .get("match_key")
            .cloned()
            .unwrap_or_else(|| node.name.clone());
        let abs_addr = node.meta.get("abs_addr").and_then(|s| {
            u64::from_str_radix(s.trim_start_matches("0x"), 16).ok()
        });
        let reading_inst = self.source.get_inst_at_line(node.line_no);

        // P0-1: byte-level coverage when absolute address is available
        if let Some(addr) = abs_addr {
            let size_bytes =
                ((node.bit_hi as u16 - node.bit_lo as u16) / 8 + 1).max(1);
            let cw_results =
                self.source.find_covering_writes(addr, size_bytes, node.line_no);

            if cw_results.is_empty() {
                if let Some(data) = node.meta.get("data_hex").cloned() {
                    let value_hex = interpret_le_hex(&data);
                    let source_id = self.add_node(SliceNode {
                        id: 0,
                        kind: SliceNodeKind::MemLiveIn,
                        name: format!("mem_0x{addr:x}"),
                        line_no: node.line_no,
                        version: 0,
                        bit_lo: node.bit_lo,
                        bit_hi: node.bit_hi,
                        value_hex: Some(format!("0x{value_hex}")),
                        meta: BTreeMap::from([
                            ("reason".to_string(), "pre-trace memory value".to_string()),
                            ("abs_addr".to_string(), format!("0x{addr:x}")),
                            ("data_hex".to_string(), data),
                        ]),
                    });
                    self.add_edge(
                        source_id,
                        node.id,
                        EdgeReason::Read,
                        reading_inst.as_ref(),
                        format!("memory live-in at 0x{addr:x}"),
                        None,
                        Confidence::Exact,
                        None,
                    );
                    return Ok(vec![(source_id, Confidence::Exact)]);
                }
            }
            if !cw_results.is_empty() {
                let mut pending = Vec::new();
                let mut covered_bytes = 0u16;

                for cw in &cw_results {
                    let inst = &cw.inst;

                    let source_reg = if inst.mnemonic == "stp" {
                        let byte_in_store =
                            (addr + cw.byte_offset as u64).saturating_sub(cw.abs_addr);
                        if byte_in_store >= 8 {
                            inst.src_regs
                                .get(1)
                                .cloned()
                                .or_else(|| inst.src_regs.first().cloned())
                        } else {
                            inst.src_regs.first().cloned()
                        }
                    } else {
                        inst.src_regs.first().cloned()
                    };

                    if let Some(src_reg) = source_reg {
                        let store_byte_off = (addr + cw.byte_offset as u64)
                            .saturating_sub(cw.abs_addr);
                        let src_bit_lo = (store_byte_off * 8) as u8;
                        let src_bit_hi = (src_bit_lo as u16
                            + cw.byte_count as u16 * 8
                            - 1)
                            .min(src_reg.bit_hi as u16)
                            as u8;

                        let source_id = self.link_reg_source(
                            &src_reg,
                            src_bit_lo.min(src_bit_hi),
                            src_bit_hi,
                            node.id,
                            inst,
                            inst.line_no,
                            EdgeReason::Write,
                            format!(
                                "byte-exact store covers {}[{}:{}]",
                                node.name, cw.bit_hi, cw.bit_lo
                            ),
                            None,
                            Confidence::Exact,
                            None,
                        );
                        pending.push((source_id, Confidence::Exact));
                    }
                    covered_bytes += cw.byte_count;
                }

                if covered_bytes < size_bytes {
                    let id = self.attach_typed_unknown(
                        node.id,
                        SliceNodeKind::UnknownPreTrace,
                        "partial byte coverage - some bytes have no matching store",
                        None,
                        Some(format!(
                            "covered {}/{} bytes",
                            covered_bytes, size_bytes
                        )),
                    );
                    pending.push((id, Confidence::Unknown));
                }

                return Ok(pending);
            }
        }

        // Fallback: key-based single store lookup
        let Some((_store_line, inst)) = self.source.find_store(&key, node.line_no) else {
            if let Some(addr) = abs_addr {
                if let Some(data) = node.meta.get("data_hex").cloned() {
                    let value_hex = interpret_le_hex(&data);
                    let source_id = self.add_node(SliceNode {
                        id: 0,
                        kind: SliceNodeKind::MemLiveIn,
                        name: format!("mem_0x{addr:x}"),
                        line_no: node.line_no,
                        version: 0,
                        bit_lo: node.bit_lo,
                        bit_hi: node.bit_hi,
                        value_hex: Some(format!("0x{value_hex}")),
                        meta: BTreeMap::from([
                            ("reason".to_string(), "pre-trace memory value".to_string()),
                            ("abs_addr".to_string(), format!("0x{addr:x}")),
                            ("data_hex".to_string(), data),
                        ]),
                    });
                    self.add_edge(
                        source_id,
                        node.id,
                        EdgeReason::Read,
                        reading_inst.as_ref(),
                        format!("memory live-in at 0x{addr:x}"),
                        None,
                        Confidence::Exact,
                        None,
                    );
                    return Ok(vec![(source_id, Confidence::Exact)]);
                }
            }
            let unknown_kind = if abs_addr.is_some() {
                SliceNodeKind::UnknownAlias
            } else {
                SliceNodeKind::UnknownPreTrace
            };
            let id = self.attach_typed_unknown(
                node.id,
                unknown_kind,
                "no matching store before memory read",
                None,
                Some(format!("memory source unavailable for {}", node.name)),
            );
            return Ok(vec![(id, Confidence::Unknown)]);
        };

        let inst = inst;
        let confidence = if abs_addr.is_some() {
            Confidence::Exact
        } else {
            Confidence::Possible
        };
        let selected_source = if inst.mnemonic == "stp" {
            if node.bit_lo >= 64 {
                inst.src_regs
                    .get(1)
                    .cloned()
                    .or_else(|| inst.src_regs.first().cloned())
            } else {
                inst.src_regs.first().cloned()
            }
        } else {
            inst.src_regs.first().cloned()
        };
        let Some(source_reg) = selected_source else {
            let id = self.attach_typed_unknown(
                node.id,
                SliceNodeKind::UnknownUnsupported,
                "store missing source register",
                Some(&inst),
                None,
            );
            return Ok(vec![(id, Confidence::Unknown)]);
        };
        let source_bit_lo = if inst.mnemonic == "stp" && node.bit_lo >= 64 {
            node.bit_lo.saturating_sub(64)
        } else {
            node.bit_lo
        };
        let source_bit_hi = if inst.mnemonic == "stp" && node.bit_hi >= 64 {
            node.bit_hi.saturating_sub(64)
        } else {
            node.bit_hi
        };
        let use_hi = source_bit_hi.min(source_reg.bit_hi);
        let source_id = self.link_reg_source(
            &source_reg,
            source_bit_lo.min(use_hi),
            use_hi,
            node.id,
            &inst,
            inst.line_no,
            EdgeReason::Write,
            format!("matching store wrote {}", node.name),
            None,
            confidence.clone(),
            None,
        );
        Ok(vec![(source_id, confidence)])
    }

    fn try_prune_equal_value_load(
        &self,
        node: &SliceNode,
        inst: &TraceInst,
        mem: &MemAccess,
        use_lo: u8,
        use_hi: u8,
    ) -> Option<PrunedLoadSource> {
        if !self.req.options.prune_equal_value_loads {
            return None;
        }

        let read_hex = mem.data_hex.as_deref()?;
        let read_size_bytes = hex_byte_len(read_hex)?;
        if read_size_bytes == 0 {
            return None;
        }

        if let Some(target_addr) = mem.abs_addr {
            let covering_writes = self
                .source
                .find_covering_writes(target_addr, read_size_bytes as u16, inst.line_no);
            if covering_writes.len() == 1 {
                let cw = &covering_writes[0];
                if cw.byte_offset == 0 && usize::from(cw.byte_count) == read_size_bytes {
                    let store_data = cw
                        .data_hex
                        .as_deref()
                        .or_else(|| cw.inst.mem_write.as_ref()?.data_hex.as_deref())?;
                    let store_byte_off = target_addr.checked_sub(cw.abs_addr)? as usize;
                    if hex_slice_matches(store_data, store_byte_off, read_size_bytes, read_hex) {
                        let (reg, bit_lo, bit_hi) = select_store_source_for_addr_range(
                            &cw.inst,
                            target_addr,
                            read_size_bytes,
                            cw.abs_addr,
                        )?;
                        return Some(PrunedLoadSource {
                            reg,
                            search_line: cw.inst.line_no,
                            bit_lo,
                            bit_hi,
                            note: format!(
                                "equal-value load/store prune via {} (store @ line {})",
                                mem.slot_name, cw.inst.line_no
                            ),
                        });
                    }
                }
            }
        }

        let (_, store_inst) = self.source.find_store(&mem.match_key, inst.line_no)?;
        let store_data = store_inst.mem_write.as_ref()?.data_hex.as_deref()?;
        if !read_hex.eq_ignore_ascii_case(store_data) {
            return None;
        }

        let (reg, bit_lo, bit_hi) =
            select_store_source_for_target_bits(&store_inst, use_lo, use_hi)?;
        Some(PrunedLoadSource {
            reg,
            search_line: store_inst.line_no,
            bit_lo,
            bit_hi,
            note: format!(
                "equal-value load/store prune via {} (store @ line {})",
                node.name, store_inst.line_no
            ),
        })
    }

    fn try_expand_adrp_add(
        &mut self,
        node: &SliceNode,
        inst: &TraceInst,
        bit_lo: u8,
        bit_hi: u8,
    ) -> Option<usize> {
        let dst = inst.dst_regs.first()?;
        let src = inst.src_regs.first()?;
        if dst.base != src.base {
            return None;
        }
        let prev_line = self.source.nearest_prev_line(inst.line_no);
        let (_, adrp) = self.source.find_reg_def(&src.base, prev_line)?;
        if adrp.mnemonic != "adrp" {
            return None;
        }
        let page = adrp
            .operands
            .get(1)
            .cloned()
            .unwrap_or_else(|| "unknown_page".to_string());
        let off = inst.imm_values.first().copied().unwrap_or_default();
        let value_hex = self.resolve_reg_value_hex(&src.base, inst.line_no);
        Some(self.add_node(SliceNode {
            id: 0,
            kind: SliceNodeKind::Static,
            name: format!("static_{page}+0x{off:x}"),
            line_no: inst.line_no,
            version: 0,
            bit_lo,
            bit_hi,
            value_hex,
            meta: BTreeMap::from([
                ("reason".to_string(), "adrp+add".to_string()),
                ("page".to_string(), page),
                ("offset".to_string(), format!("0x{off:x}")),
                ("target".to_string(), node.name.clone()),
            ]),
        }))
    }

    fn link_reg_source(
        &mut self,
        reg: &RegRef,
        bit_lo: u8,
        bit_hi: u8,
        dst_node_id: usize,
        inst: &TraceInst,
        search_line: usize,
        reason: EdgeReason,
        note: String,
        branch_group: Option<String>,
        confidence: Confidence,
        guard: Option<GuardContext>,
    ) -> usize {
        let source_id = self.add_node(SliceNode {
            id: 0,
            kind: SliceNodeKind::Reg,
            name: reg.name.clone(),
            line_no: search_line,
            version: self.resolve_reg_version(&reg.base, search_line),
            bit_lo,
            bit_hi,
            value_hex: self.resolve_reg_value_hex(&reg.base, search_line),
            meta: reg_meta(reg),
        });
        self.add_edge(
            source_id,
            dst_node_id,
            reason,
            Some(inst),
            note,
            branch_group,
            confidence,
            guard,
        );
        source_id
    }

    fn link_imm_source(
        &mut self,
        imm: i64,
        bit_lo: u8,
        bit_hi: u8,
        dst_node_id: usize,
        inst: &TraceInst,
        note: String,
        confidence: Confidence,
    ) -> usize {
        let value_hex = if imm < 0 {
            format!("-0x{:x}", imm.unsigned_abs())
        } else {
            format!("0x{:x}", imm)
        };
        let source_id = self.make_imm_node(
            value_hex,
            inst.line_no,
            bit_lo,
            bit_hi,
            BTreeMap::from([("reason".to_string(), "instruction immediate".to_string())]),
        );
        self.add_edge(
            source_id,
            dst_node_id,
            EdgeReason::Imm,
            Some(inst),
            note,
            None,
            confidence,
            None,
        );
        source_id
    }

    fn make_imm_node(
        &mut self,
        value_hex: String,
        line_no: usize,
        bit_lo: u8,
        bit_hi: u8,
        meta: BTreeMap<String, String>,
    ) -> usize {
        self.add_node(SliceNode {
            id: 0,
            kind: SliceNodeKind::Imm,
            name: value_hex.clone(),
            line_no,
            version: 0,
            bit_lo,
            bit_hi,
            value_hex: Some(value_hex),
            meta,
        })
    }

    fn make_mem_node(
        &mut self,
        mem: &MemAccess,
        line_no: usize,
        bit_lo: u8,
        bit_hi: u8,
    ) -> usize {
        self.add_node(SliceNode {
            id: 0,
            kind: SliceNodeKind::Mem,
            name: mem.slot_name.clone(),
            line_no,
            version: self.resolve_mem_version(&mem.match_key, line_no),
            bit_lo,
            bit_hi,
            value_hex: mem.data_hex.clone(),
            meta: mem_meta(mem),
        })
    }

    fn attach_typed_unknown(
        &mut self,
        dst_node_id: usize,
        kind: SliceNodeKind,
        reason: &str,
        inst: Option<&TraceInst>,
        note: Option<String>,
    ) -> usize {
        let dst = self.nodes[dst_node_id - 1].clone();
        let source_id = self.add_node(SliceNode {
            id: 0,
            kind,
            name: format!("unknown_{}", dst.name),
            line_no: dst.line_no,
            version: 0,
            bit_lo: dst.bit_lo,
            bit_hi: dst.bit_hi,
            value_hex: None,
            meta: BTreeMap::from([("reason".to_string(), reason.to_string())]),
        });
        self.add_edge(
            source_id,
            dst_node_id,
            EdgeReason::Unknown,
            inst,
            note.unwrap_or_else(|| reason.to_string()),
            None,
            Confidence::Unknown,
            None,
        );
        source_id
    }

    fn resolve_reg_version(&self, base: &str, line_no: usize) -> usize {
        self.source.reg_version(base, line_no)
    }

    fn resolve_mem_version(&self, key: &str, line_no: usize) -> usize {
        self.source.mem_version(key, line_no)
    }

    fn resolve_reg_value_hex(&self, base: &str, line_no: usize) -> Option<String> {
        self.source.resolve_reg_value(base, line_no)
    }

    fn resolve_csel_guard(&self, inst: &TraceInst) -> Option<GuardResolution> {
        let cond = inst.cond.as_deref()?;
        let (line_no, flag_inst) = self
            .source
            .find_flag_def(self.source.nearest_prev_line(inst.line_no))?;
        let taken = evaluate_condition_from_inst(cond, &flag_inst)?;
        Some(GuardResolution {
            taken_idx: Some(if taken { 0 } else { 1 }),
            source_line: Some(line_no),
            source_pc: Some(flag_inst.pc),
            source_inst: Some(flag_inst.inst_text.clone()),
        })
    }
}

fn is_arg_reg(base: &str) -> bool {
    matches!(
        base,
        "x0" | "x1" | "x2" | "x3" | "x4" | "x5" | "x6" | "x7"
    )
}

fn reg_meta(reg: &RegRef) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("base".to_string(), reg.base.clone()),
        ("view".to_string(), format!("{:?}", reg.view)),
    ])
}

fn evaluate_condition_from_inst(cond: &str, inst: &TraceInst) -> Option<bool> {
    let flags = compute_flag_state(inst)?;
    match cond {
        "eq" => Some(flags.z),
        "ne" => Some(!flags.z),
        "cs" | "hs" => flags.c,
        "cc" | "lo" => flags.c.map(|c| !c),
        "mi" => Some(flags.n),
        "pl" => Some(!flags.n),
        "vs" => flags.v,
        "vc" => flags.v.map(|v| !v),
        "hi" => flags.c.map(|c| c && !flags.z),
        "ls" => flags.c.map(|c| !c || flags.z),
        "ge" => flags.v.map(|v| flags.n == v),
        "lt" => flags.v.map(|v| flags.n != v),
        "gt" => flags.v.map(|v| !flags.z && flags.n == v),
        "le" => flags.v.map(|v| flags.z || flags.n != v),
        "al" => Some(true),
        _ => None,
    }
}

fn compute_flag_state(inst: &TraceInst) -> Option<FlagState> {
    let (lhs, rhs, width) = first_two_input_values(inst)?;
    match inst.mnemonic.as_str() {
        "cmp" | "subs" => Some(compute_sub_flags(lhs, rhs, width)),
        "cmn" | "adds" => Some(compute_add_flags(lhs, rhs, width)),
        "tst" | "ands" => Some(compute_and_flags(lhs, rhs, width)),
        _ => None,
    }
}

fn first_two_input_values(inst: &TraceInst) -> Option<(u64, u64, u8)> {
    let width = inst
        .src_regs
        .first()
        .map(|reg| if reg.view == RegView::W { 32 } else { 64 })
        .or_else(|| {
            inst.dst_regs
                .first()
                .map(|reg| if reg.view == RegView::W { 32 } else { 64 })
        })
        .unwrap_or(64);

    let mut values = Vec::with_capacity(2);
    for reg in &inst.src_regs {
        if let Some(value) = inst
            .reg_value_map
            .get(&reg.base)
            .or_else(|| inst.reg_value_map.get(&reg.name))
            .copied()
        {
            values.push(value);
            if values.len() == 2 {
                break;
            }
        }
    }
    for imm in &inst.imm_values {
        values.push(*imm as u64);
        if values.len() == 2 {
            break;
        }
    }

    if values.len() == 2 {
        Some((values[0], values[1], width))
    } else {
        None
    }
}

fn width_mask(width: u8) -> u64 {
    match width {
        0 => 0,
        1..=63 => (1u64 << width) - 1,
        _ => u64::MAX,
    }
}

fn sign_bit(width: u8) -> u64 {
    1u64 << width.saturating_sub(1)
}

fn compute_sub_flags(lhs: u64, rhs: u64, width: u8) -> FlagState {
    let mask = width_mask(width);
    let sign = sign_bit(width);
    let lhs = lhs & mask;
    let rhs = rhs & mask;
    let result = lhs.wrapping_sub(rhs) & mask;
    FlagState {
        n: (result & sign) != 0,
        z: result == 0,
        c: Some(lhs >= rhs),
        v: Some(((lhs ^ rhs) & (lhs ^ result) & sign) != 0),
    }
}

fn compute_add_flags(lhs: u64, rhs: u64, width: u8) -> FlagState {
    let mask = width_mask(width);
    let sign = sign_bit(width);
    let lhs = lhs & mask;
    let rhs = rhs & mask;
    let wide = lhs as u128 + rhs as u128;
    let result = (wide as u64) & mask;
    FlagState {
        n: (result & sign) != 0,
        z: result == 0,
        c: Some(wide > mask as u128),
        v: Some(((!(lhs ^ rhs)) & (lhs ^ result) & sign) != 0),
    }
}

fn compute_and_flags(lhs: u64, rhs: u64, width: u8) -> FlagState {
    let mask = width_mask(width);
    let sign = sign_bit(width);
    let result = (lhs & rhs) & mask;
    FlagState {
        n: (result & sign) != 0,
        z: result == 0,
        c: None,
        v: None,
    }
}

fn mem_meta(mem: &MemAccess) -> BTreeMap<String, String> {
    let mut meta = BTreeMap::from([
        ("match_key".to_string(), mem.match_key.clone()),
        ("expr".to_string(), mem.expr.clone()),
        ("slot_name".to_string(), mem.slot_name.clone()),
    ]);
    if let Some(addr) = mem.abs_addr {
        meta.insert("abs_addr".to_string(), format!("0x{addr:x}"));
    }
    if let Some(data) = &mem.data_hex {
        meta.insert("data_hex".to_string(), data.clone());
    }
    meta
}

fn fake_mem_access(expr: &str, size_bits: u16) -> MemAccess {
    MemAccess {
        kind: crate::MemAccessKind::Read,
        expr: expr.to_string(),
        base_reg: None,
        offset_reg: None,
        offset_imm: None,
        slot_name: format!("UNKNOWN_MEM({expr})"),
        match_key: format!("UNKNOWN_MEM({expr})"),
        abs_addr: None,
        data_hex: None,
        size_bits,
    }
}

fn intersect_range(a_lo: u8, a_hi: u8, b_lo: u8, b_hi: u8) -> Option<(u8, u8)> {
    let lo = a_lo.max(b_lo);
    let hi = a_hi.min(b_hi);
    (lo <= hi).then_some((lo, hi))
}

fn hex_byte_len(hex: &str) -> Option<usize> {
    let hex = hex.trim();
    if hex.is_empty() || hex.len() % 2 != 0 {
        None
    } else {
        Some(hex.len() / 2)
    }
}

fn hex_slice_matches(source_hex: &str, byte_offset: usize, size_bytes: usize, expected_hex: &str) -> bool {
    let start = byte_offset.saturating_mul(2);
    let end = start.saturating_add(size_bytes.saturating_mul(2));
    source_hex
        .get(start..end)
        .map(|slice| slice.eq_ignore_ascii_case(expected_hex))
        .unwrap_or(false)
}

fn select_store_source_for_target_bits(
    inst: &TraceInst,
    target_bit_lo: u8,
    target_bit_hi: u8,
) -> Option<(RegRef, u8, u8)> {
    let source_reg = if inst.mnemonic == "stp" {
        if target_bit_lo >= 64 {
            inst.src_regs
                .get(1)
                .cloned()
                .or_else(|| inst.src_regs.first().cloned())
        } else {
            inst.src_regs.first().cloned()
        }
    } else {
        inst.src_regs.first().cloned()
    }?;

    let source_bit_lo = if inst.mnemonic == "stp" && target_bit_lo >= 64 {
        target_bit_lo.saturating_sub(64)
    } else {
        target_bit_lo
    };
    let source_bit_hi = if inst.mnemonic == "stp" && target_bit_hi >= 64 {
        target_bit_hi.saturating_sub(64)
    } else {
        target_bit_hi
    };
    let use_hi = source_bit_hi.min(source_reg.bit_hi);
    if source_bit_lo > use_hi {
        return None;
    }

    Some((source_reg, source_bit_lo, use_hi))
}

fn select_store_source_for_addr_range(
    inst: &TraceInst,
    target_addr: u64,
    size_bytes: usize,
    store_abs_addr: u64,
) -> Option<(RegRef, u8, u8)> {
    let store_byte_off = target_addr.checked_sub(store_abs_addr)? as usize;
    let lane_base = if inst.mnemonic == "stp" && store_byte_off >= 8 {
        8usize
    } else {
        0usize
    };
    let source_reg = if lane_base == 8 {
        inst.src_regs
            .get(1)
            .cloned()
            .or_else(|| inst.src_regs.first().cloned())
    } else {
        inst.src_regs.first().cloned()
    }?;

    let source_byte_off = store_byte_off.saturating_sub(lane_base);
    let source_bit_lo = (source_byte_off * 8) as u8;
    let source_bit_hi = (source_bit_lo as u16 + size_bytes as u16 * 8 - 1)
        .min(source_reg.bit_hi as u16) as u8;
    if source_bit_lo > source_bit_hi {
        return None;
    }

    Some((source_reg, source_bit_lo, source_bit_hi))
}

fn subtract_inserted_range(
    use_lo: u8,
    use_hi: u8,
    insert_lo: u8,
    insert_hi: u8,
) -> Option<(u8, u8)> {
    if use_hi < insert_lo || use_lo > insert_hi {
        return Some((use_lo, use_hi));
    }
    if use_lo < insert_lo {
        return Some((use_lo, insert_lo.saturating_sub(1)));
    }
    if use_hi > insert_hi {
        return Some((insert_hi.saturating_add(1), use_hi));
    }
    None
}

fn interpret_le_hex(hex: &str) -> String {
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .filter_map(|i| hex.get(i..i + 2).and_then(|s| u8::from_str_radix(s, 16).ok()))
        .collect();
    let mut value: u64 = 0;
    for (i, byte) in bytes.iter().enumerate().take(8) {
        value |= (*byte as u64) << (i * 8);
    }
    format!("{value:x}")
}

fn is_zero_register_operands(operands: &[String]) -> bool {
    operands
        .iter()
        .any(|op| op.trim().eq_ignore_ascii_case("xzr") || op.trim().eq_ignore_ascii_case("wzr"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::indexer::build_trace_index;
    use crate::normalizer::parse_trace_text;
    use crate::{BackwardTaintOptions, TargetKind};

    #[test]
    fn backward_trace_handles_ldrb_store_eor_chain() {
        let trace = "\
3124 | 0x4001b498 | movz w11, #0x3a | w11=0x3a\n\
3125 | 0x4001b49c | movk w11, #0x4a, lsl #8 | w11=0x4a3a\n\
3126 | 0x4001b4a0 | ldrb w13, [x13, x14] | x13=0x40020000 x14=0x79 mr=0x40020079:[10] w13=0x10\n\
3127 | 0x4001b4a4 | eor w11, w13, w11 | w13=0x10 w11=0x4a2a\n\
3128 | 0x4001b4b0 | strb w11, [x15, x14] | x15=0x40020700 x14=0x79 w11=0x2a mw=0x40020779:[2A]\n\
3562 | 0x40012558 | ldrb w8, [x8, x21] | x8=0x40020700 x21=0x79 mr=0x40020779:[2A] w8=0x2a";
        let insts = parse_trace_text(trace).expect("trace parses");
        let index = build_trace_index(&insts);
        let report = trace_backward(
            crate::BackwardTaintRequest {
                target_kind: TargetKind::RegSlice,
                line_no: 3562,
                reg: Some("w8".to_string()),
                mem_expr: None,
                bit_lo: 0,
                bit_hi: 7,
                options: BackwardTaintOptions::default(),
            },
            &insts,
            &index,
        )
        .expect("trace succeeds");

        assert!(report
            .graph
            .root_sources
            .iter()
            .any(|root| root.label.contains("0x3a")));
        assert!(report
            .graph
            .root_sources
            .iter()
            .any(|root| root.root_kind == SliceNodeKind::MemLiveIn
                || root.root_kind.is_unknown_variant()));
        assert!(!report.chains.is_empty());
    }

    #[test]
    fn backward_trace_handles_movk_old_and_new_sources() {
        let trace = "\
1 | 0x1000 | movz w11, #0x3a | w11=0x3a\n\
2 | 0x1004 | movk w11, #0x4a, lsl #8 | w11=0x4a3a";
        let insts = parse_trace_text(trace).expect("trace parses");
        let index = build_trace_index(&insts);
        let report = trace_backward(
            crate::BackwardTaintRequest {
                target_kind: TargetKind::RegSlice,
                line_no: 2,
                reg: Some("w11".to_string()),
                mem_expr: None,
                bit_lo: 0,
                bit_hi: 15,
                options: BackwardTaintOptions::default(),
            },
            &insts,
            &index,
        )
        .expect("trace succeeds");

        assert!(report
            .graph
            .root_sources
            .iter()
            .any(|root| root.label.contains("0x3a")));
        assert!(report
            .graph
            .root_sources
            .iter()
            .any(|root| root.label.contains("0x4a")));
    }

    #[test]
    fn backward_trace_handles_call_return() {
        let trace = "10 | 0x4010 | bl helper | x0=0x55";
        let insts = parse_trace_text(trace).expect("trace parses");
        let index = build_trace_index(&insts);
        let report = trace_backward(
            crate::BackwardTaintRequest {
                target_kind: TargetKind::RegSlice,
                line_no: 10,
                reg: Some("x0".to_string()),
                mem_expr: None,
                bit_lo: 0,
                bit_hi: 63,
                options: BackwardTaintOptions::default(),
            },
            &insts,
            &index,
        )
        .expect("trace succeeds");
        assert!(report
            .graph
            .root_sources
            .iter()
            .any(|root| root.root_kind == SliceNodeKind::RetVal));
    }

    #[test]
    fn backward_trace_handles_csel_with_guard() {
        let trace = "20 | 0x5000 | csel w8, w0, w1, eq | w0=0x11 w1=0x22 w8=0x11";
        let insts = parse_trace_text(trace).expect("trace parses");
        let index = build_trace_index(&insts);
        let report = trace_backward(
            crate::BackwardTaintRequest {
                target_kind: TargetKind::RegSlice,
                line_no: 20,
                reg: Some("w8".to_string()),
                mem_expr: None,
                bit_lo: 0,
                bit_hi: 7,
                options: BackwardTaintOptions::default(),
            },
            &insts,
            &index,
        )
        .expect("trace succeeds");

        let arg_roots = report
            .graph
            .root_sources
            .iter()
            .filter(|root| root.root_kind == SliceNodeKind::Arg)
            .count();
        assert_eq!(arg_roots, 2);

        let exact_roots = report
            .graph
            .root_sources
            .iter()
            .filter(|root| root.confidence == Confidence::Exact)
            .count();
        let possible_roots = report
            .graph
            .root_sources
            .iter()
            .filter(|root| root.confidence == Confidence::Possible)
            .count();
        assert_eq!(exact_roots, 1, "taken source should be Exact");
        assert_eq!(possible_roots, 1, "alt source should be Possible");

        let phi_edges: Vec<_> = report
            .graph
            .edges
            .iter()
            .filter(|e| e.reason == EdgeReason::Phi)
            .collect();
        assert_eq!(phi_edges.len(), 2);
        assert!(phi_edges.iter().any(|e| e.guard.is_some()
            && e.guard.as_ref().unwrap().value == Some(true)));
        assert!(phi_edges.iter().any(|e| e.guard.is_some()
            && e.guard.as_ref().unwrap().value == Some(false)));
    }

    #[test]
    fn backward_trace_csel_uses_prior_flag_def_when_dst_value_missing() {
        let trace = "\
1 | 0x1000 | mov x10, #0x111 | x10=0x111\n\
2 | 0x1004 | mov x11, #0x222 | x11=0x222\n\
3 | 0x1008 | cmp x1, #0x7 | x1=0x5\n\
4 | 0x100c | csel x0, x10, x11, lt | x10=0x111 x11=0x222";
        let insts = parse_trace_text(trace).expect("trace parses");
        let index = build_trace_index(&insts);
        let report = trace_backward(
            crate::BackwardTaintRequest {
                target_kind: TargetKind::RegSlice,
                line_no: 4,
                reg: Some("x0".to_string()),
                mem_expr: None,
                bit_lo: 0,
                bit_hi: 63,
                options: BackwardTaintOptions::default(),
            },
            &insts,
            &index,
        )
        .expect("trace succeeds");

        let phi_edges: Vec<_> = report
            .graph
            .edges
            .iter()
            .filter(|e| e.reason == EdgeReason::Phi)
            .collect();
        assert_eq!(phi_edges.len(), 2);

        let taken_edge = phi_edges
            .iter()
            .find(|edge| edge.guard.as_ref().and_then(|guard| guard.value) == Some(true))
            .expect("taken edge should exist");
        assert_eq!(taken_edge.confidence, Confidence::Exact);
        assert_eq!(
            taken_edge
                .guard
                .as_ref()
                .and_then(|guard| guard.source_line),
            Some(3)
        );
        assert!(
            taken_edge
                .guard
                .as_ref()
                .and_then(|guard| guard.source_inst.as_ref())
                .map(|inst| inst.contains("cmp"))
                .unwrap_or(false),
            "guard should point at the compare that produced NZCV"
        );
    }

    #[test]
    fn backward_trace_handles_adrp_add_static_root() {
        let trace = "\
30 | 0x6000 | adrp x1, #0x6fd3124000 | x1=0x6fd3124000\n\
31 | 0x6004 | add x1, x1, #0x56 | x1=0x6fd3124056";
        let insts = parse_trace_text(trace).expect("trace parses");
        let index = build_trace_index(&insts);
        let report = trace_backward(
            crate::BackwardTaintRequest {
                target_kind: TargetKind::RegSlice,
                line_no: 31,
                reg: Some("x1".to_string()),
                mem_expr: None,
                bit_lo: 0,
                bit_hi: 63,
                options: BackwardTaintOptions::default(),
            },
            &insts,
            &index,
        )
        .expect("trace succeeds");

        assert!(report.graph.root_sources.iter().any(
            |root| { root.root_kind == SliceNodeKind::Static && root.label.contains("0x56") }
        ));
    }

    #[test]
    fn backward_trace_marks_upper_x_bits_zero_after_w_write() {
        let trace = "40 | 0x7000 | movz w8, #0x12 | w8=0x12 x8=0x12";
        let insts = parse_trace_text(trace).expect("trace parses");
        let index = build_trace_index(&insts);
        let report = trace_backward(
            crate::BackwardTaintRequest {
                target_kind: TargetKind::RegSlice,
                line_no: 40,
                reg: Some("x8".to_string()),
                mem_expr: None,
                bit_lo: 32,
                bit_hi: 63,
                options: BackwardTaintOptions::default(),
            },
            &insts,
            &index,
        )
        .expect("trace succeeds");

        assert!(report
            .graph
            .root_sources
            .iter()
            .any(|root| root.label.contains("0x0")));
    }

    #[test]
    fn backward_trace_supports_sample_txt_style_chain() {
        let trace = "\
0x52c020\t4b028052\tmov     w11, #0x12                 \t//x11=0x0000000000000012,\n\
0x52c03c\tab0200b9\tstr     w11, [x21]                 \t//x11=0x0000000000000012,  mw=0x781a4ee290:[12000000]\n\
0x534260\t480080b9\tldrsw   x8, [x2]                   \t//x2=0x000000781a4ee290,x8=0x0000000000000012,  mw=0x781a4ee290:[12000000]";
        let insts = parse_trace_text(trace).expect("trace parses");
        let index = build_trace_index(&insts);
        let report = trace_backward(
            crate::BackwardTaintRequest {
                target_kind: TargetKind::RegSlice,
                line_no: 3,
                reg: Some("x8".to_string()),
                mem_expr: None,
                bit_lo: 0,
                bit_hi: 31,
                options: BackwardTaintOptions::default(),
            },
            &insts,
            &index,
        )
        .expect("trace succeeds");

        assert!(report
            .graph
            .root_sources
            .iter()
            .any(|root| root.label.contains("0x12")));
        assert!(report
            .chains
            .iter()
            .any(|chain| chain.pretty.contains("ldrsw")));
    }

    #[test]
    fn backward_trace_unknown_types_are_specific() {
        let trace = "50 | 0x8000 | udiv x5, x3, x4 | x5=0xff";
        let insts = parse_trace_text(trace).expect("trace parses");
        let index = build_trace_index(&insts);
        let report = trace_backward(
            crate::BackwardTaintRequest {
                target_kind: TargetKind::RegSlice,
                line_no: 50,
                reg: Some("x5".to_string()),
                mem_expr: None,
                bit_lo: 0,
                bit_hi: 63,
                options: BackwardTaintOptions::default(),
            },
            &insts,
            &index,
        )
        .expect("trace succeeds");

        assert!(report
            .graph
            .root_sources
            .iter()
            .any(|root| root.root_kind == SliceNodeKind::UnknownUnsupported));
    }

    #[test]
    fn backward_trace_byte_coverage_multi_store() {
        let trace = "\
1 | 0x1000 | movz w1, #0xAA | w1=0xAA\n\
2 | 0x1004 | movz w2, #0xBB | w2=0xBB\n\
3 | 0x1008 | strb w1, [x10] | x10=0x3000 w1=0xAA mw=0x3000:[AA]\n\
4 | 0x100c | strb w2, [x10, #0x1] | x10=0x3000 w2=0xBB mw=0x3001:[BB]\n\
5 | 0x1010 | ldrh w8, [x11] | x11=0x3000 mr=0x3000:[AABB] w8=0xBBAA";
        let insts = parse_trace_text(trace).expect("trace parses");
        let index = build_trace_index(&insts);
        let report = trace_backward(
            crate::BackwardTaintRequest {
                target_kind: TargetKind::RegSlice,
                line_no: 5,
                reg: Some("w8".to_string()),
                mem_expr: None,
                bit_lo: 0,
                bit_hi: 15,
                options: BackwardTaintOptions::default(),
            },
            &insts,
            &index,
        )
        .expect("trace succeeds");

        assert!(report
            .graph
            .root_sources
            .iter()
            .any(|root| root.label.contains("0xaa") || root.label.contains("0xAA")),
            "should trace to w1 source 0xAA");
        assert!(report
            .graph
            .root_sources
            .iter()
            .any(|root| root.label.contains("0xbb") || root.label.contains("0xBB")),
            "should trace to w2 source 0xBB");
    }

    #[test]
    fn backward_trace_prunes_equal_value_load_store_hop() {
        let trace = "\
1 | 0x1000 | movz w1, #0x12 | w1=0x12\n\
2 | 0x1004 | strb w1, [x10] | x10=0x3000 w1=0x12 mw=0x3000:[12]\n\
3 | 0x1008 | ldrb w8, [x11] | x11=0x3000 mr=0x3000:[12] w8=0x12";
        let insts = parse_trace_text(trace).expect("trace parses");
        let index = build_trace_index(&insts);
        let report = trace_backward(
            crate::BackwardTaintRequest {
                target_kind: TargetKind::RegSlice,
                line_no: 3,
                reg: Some("w8".to_string()),
                mem_expr: None,
                bit_lo: 0,
                bit_hi: 7,
                options: BackwardTaintOptions::default(),
            },
            &insts,
            &index,
        )
        .expect("trace succeeds");

        assert!(
            !report
                .graph
                .nodes
                .iter()
                .any(|node| node.kind == SliceNodeKind::Mem && node.line_no == 3),
            "equal-value pruning should skip the intermediate memory node"
        );
        assert!(
            report
                .graph
                .edges
                .iter()
                .any(|edge| edge.note.contains("equal-value load/store prune")),
            "report should record that pruning happened"
        );
    }

    #[test]
    fn backward_trace_can_disable_equal_value_load_store_prune() {
        let trace = "\
1 | 0x1000 | movz w1, #0x12 | w1=0x12\n\
2 | 0x1004 | strb w1, [x10] | x10=0x3000 w1=0x12 mw=0x3000:[12]\n\
3 | 0x1008 | ldrb w8, [x11] | x11=0x3000 mr=0x3000:[12] w8=0x12";
        let insts = parse_trace_text(trace).expect("trace parses");
        let index = build_trace_index(&insts);
        let report = trace_backward(
            crate::BackwardTaintRequest {
                target_kind: TargetKind::RegSlice,
                line_no: 3,
                reg: Some("w8".to_string()),
                mem_expr: None,
                bit_lo: 0,
                bit_hi: 7,
                options: BackwardTaintOptions {
                    prune_equal_value_loads: false,
                    ..BackwardTaintOptions::default()
                },
            },
            &insts,
            &index,
        )
        .expect("trace succeeds");

        assert!(
            report
                .graph
                .nodes
                .iter()
                .any(|node| node.kind == SliceNodeKind::Mem && node.line_no == 3),
            "disabling pruning should keep the intermediate memory node"
        );
        assert!(
            report
                .graph
                .edges
                .iter()
                .all(|edge| !edge.note.contains("equal-value load/store prune")),
            "prune note should disappear when the option is off"
        );
    }

    #[test]
    fn backward_trace_truncated_uses_specific_unknown_type() {
        let trace = "\
1 | 0x1000 | mov x0, x1 | x0=0x1 x1=0x1\n\
2 | 0x1004 | mov x1, x0 | x0=0x1 x1=0x1";
        let insts = parse_trace_text(trace).expect("trace parses");
        let index = build_trace_index(&insts);
        let report = trace_backward(
            crate::BackwardTaintRequest {
                target_kind: TargetKind::RegSlice,
                line_no: 2,
                reg: Some("x1".to_string()),
                mem_expr: None,
                bit_lo: 0,
                bit_hi: 63,
                options: BackwardTaintOptions {
                    max_depth: 2,
                    max_nodes: 2000,
                    dedup: false,
                    emit_linear_chains: true,
                    per_branch_budget: 500,
                    prune_equal_value_loads: true,
                },
            },
            &insts,
            &index,
        )
        .expect("trace succeeds");

        assert!(report
            .graph
            .root_sources
            .iter()
            .any(|root| root.root_kind == SliceNodeKind::UnknownTruncated));
    }

    #[test]
    fn backward_trace_treats_register_shift_count_as_immediate_when_known() {
        let trace = "\
1 | 0x547b68 | mov w1, #6 | x1=0x6\n\
2 | 0x53a490 | mov x8, #0x14118103110102 | x8=0x14118103110102\n\
3 | 0x53a498 | lsr x8, x8, x1 | x8=0x5046040c440408 x1=0x6";
        let insts = parse_trace_text(trace).expect("trace parses");
        let index = build_trace_index(&insts);
        let report = trace_backward(
            crate::BackwardTaintRequest {
                target_kind: TargetKind::RegSlice,
                line_no: 3,
                reg: Some("x8".to_string()),
                mem_expr: None,
                bit_lo: 0,
                bit_hi: 63,
                options: BackwardTaintOptions::default(),
            },
            &insts,
            &index,
        )
        .expect("trace succeeds");

        assert!(
            report
                .graph
                .root_sources
                .iter()
                .any(|root| root.root_kind == SliceNodeKind::Imm && root.label.contains("0x6")),
            "shift count should fold into an immediate root"
        );
        assert!(
            !report
                .graph
                .root_sources
                .iter()
                .any(|root| root.label.contains("unknown_x1")),
            "known shift count should not fall back to unknown_x1"
        );
    }
}
