use crate::{
    node_label, BackwardTaintReport, BackwardTaintRequest, Confidence, DataFlowNode, GraphReport,
    GraphStats, LinearChain, RootSource, SliceNode, SliceNodeKind, SummaryReport, TaintEdge,
    TraceStep,
};
use anyhow::Result;
use std::collections::{BTreeMap, HashMap, HashSet};

pub fn report_to_json(report: &BackwardTaintReport) -> Result<String> {
    Ok(serde_json::to_string_pretty(report)?)
}

pub(crate) fn build_report(
    request: BackwardTaintRequest,
    target_id: usize,
    nodes: Vec<SliceNode>,
    edges: Vec<TaintEdge>,
    truncated: bool,
    cycle_count: usize,
) -> Result<BackwardTaintReport> {
    let target = nodes
        .iter()
        .find(|node| node.id == target_id)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("missing target node"))?;
    let incoming = build_incoming_map(&edges);
    let path_conf = propagate_confidence_to_roots(target_id, &edges);
    let root_sources = collect_roots(&nodes, &incoming, &path_conf);
    let chains = collect_chains(&target, &incoming, &nodes, &edges);
    let steps = collect_steps(&target, &nodes, &edges, &incoming);
    let graph = GraphReport {
        target: target.clone(),
        nodes: nodes.clone(),
        edges: edges.clone(),
        root_sources: root_sources.clone(),
        stats: GraphStats {
            total_nodes: nodes.len(),
            total_edges: edges.len(),
            truncated,
            cycle_count,
        },
    };

    let exact_source_count = root_sources
        .iter()
        .filter(|r| r.confidence == Confidence::Exact)
        .count();
    let possible_source_count = root_sources
        .iter()
        .filter(|r| r.confidence == Confidence::Possible)
        .count();
    let unknown_source_count = root_sources
        .iter()
        .filter(|r| r.confidence == Confidence::Unknown)
        .count();
    let exact_chain_count = chains
        .iter()
        .filter(|c| c.confidence == Confidence::Exact)
        .count();

    let summary = SummaryReport {
        target: node_label(&target),
        root_source_count: root_sources.len(),
        exact_source_count,
        possible_source_count,
        unknown_source_count,
        chain_count: chains.len(),
        exact_chain_count,
        contains_unknown: root_sources
            .iter()
            .any(|root| root.root_kind.is_unknown_variant()),
        contains_cycle: cycle_count > 0,
        truncated,
    };

    let data_flow = build_data_flow_tree(target_id, &nodes, &edges);

    Ok(BackwardTaintReport {
        request,
        summary,
        data_flow,
        graph,
        steps,
        chains,
    })
}

fn build_incoming_map(edges: &[TaintEdge]) -> HashMap<usize, Vec<&TaintEdge>> {
    let mut map: HashMap<usize, Vec<&TaintEdge>> = HashMap::new();
    for edge in edges {
        map.entry(edge.dst_node_id).or_default().push(edge);
    }
    for list in map.values_mut() {
        list.sort_by(|left, right| {
            left.inst_line
                .cmp(&right.inst_line)
                .then_with(|| left.inst_pc.cmp(&right.inst_pc))
                .then_with(|| left.id.cmp(&right.id))
        });
    }
    map
}



fn collect_roots(
    nodes: &[SliceNode],
    incoming: &HashMap<usize, Vec<&TaintEdge>>,
    path_conf: &HashMap<usize, Confidence>,
) -> Vec<RootSource> {
    let nodes_with_incoming: HashSet<usize> = incoming
        .iter()
        .flat_map(|(_, edges)| edges.iter().map(|e| e.src_node_id))
        .collect();
    let nodes_that_are_dst: HashSet<usize> = incoming.keys().cloned().collect();

    let mut roots: Vec<RootSource> = nodes
        .iter()
        .filter(|node| {
            !nodes_that_are_dst.contains(&node.id)
                || incoming
                    .get(&node.id)
                    .map(|e| e.is_empty())
                    .unwrap_or(true)
        })
        .filter(|node| node.kind.is_terminal() || !nodes_with_incoming.contains(&node.id))
        .map(|node| {
            let conf = path_conf
                .get(&node.id)
                .cloned()
                .unwrap_or(Confidence::Exact);
            RootSource {
                node_id: node.id,
                root_kind: node.kind.clone(),
                label: node_label(node),
                explain: explain_root(node),
                confidence: conf,
            }
        })
        .collect();

    roots.sort_by(|left, right| {
        confidence_ord(&left.confidence)
            .cmp(&confidence_ord(&right.confidence))
            .then_with(|| left.label.cmp(&right.label))
            .then_with(|| left.node_id.cmp(&right.node_id))
    });
    roots
}

fn propagate_confidence_to_roots(
    target_id: usize,
    edges: &[TaintEdge],
) -> HashMap<usize, Confidence> {
    let mut incoming: HashMap<usize, Vec<&TaintEdge>> = HashMap::new();
    for e in edges {
        incoming.entry(e.dst_node_id).or_default().push(e);
    }

    let mut best_conf: HashMap<usize, Confidence> = HashMap::new();
    best_conf.insert(target_id, Confidence::Exact);

    let mut queue = std::collections::VecDeque::from([target_id]);

    while let Some(node_id) = queue.pop_front() {
        let current_ord = confidence_ord(best_conf.get(&node_id).unwrap_or(&Confidence::Exact));

        for edge in incoming.get(&node_id).unwrap_or(&Vec::new()) {
            let edge_ord = confidence_ord(&edge.confidence);
            let reaching_ord = edge_ord.max(current_ord);

            let existing_ord =
                confidence_ord(best_conf.get(&edge.src_node_id).unwrap_or(&Confidence::Unknown));
            if reaching_ord < existing_ord {
                let reaching_conf = match reaching_ord {
                    0 => Confidence::Exact,
                    1 => Confidence::Possible,
                    _ => Confidence::Unknown,
                };
                best_conf.insert(edge.src_node_id, reaching_conf);
                queue.push_back(edge.src_node_id);
            }
        }
    }

    best_conf
}

fn confidence_ord(c: &Confidence) -> u8 {
    match c {
        Confidence::Exact => 0,
        Confidence::Possible => 1,
        Confidence::Unknown => 2,
    }
}

fn explain_root(node: &SliceNode) -> String {
    match node.kind {
        SliceNodeKind::Imm => {
            format!(
                "immediate source {}",
                node.value_hex.clone().unwrap_or_default()
            )
        }
        SliceNodeKind::Static => "static address construction root".to_string(),
        SliceNodeKind::Arg => "function argument origin".to_string(),
        SliceNodeKind::RetVal => "function return origin".to_string(),
        SliceNodeKind::UnknownLiveIn => node
            .meta
            .get("reason")
            .cloned()
            .unwrap_or_else(|| "register live-in before trace".to_string()),
        SliceNodeKind::UnknownPreTrace => node
            .meta
            .get("reason")
            .cloned()
            .unwrap_or_else(|| "data predates trace capture".to_string()),
        SliceNodeKind::UnknownAlias => node
            .meta
            .get("reason")
            .cloned()
            .unwrap_or_else(|| "memory alias unresolved".to_string()),
        SliceNodeKind::UnknownTruncated => node
            .meta
            .get("reason")
            .cloned()
            .unwrap_or_else(|| "analysis truncated by budget".to_string()),
        SliceNodeKind::UnknownUnsupported => node
            .meta
            .get("reason")
            .cloned()
            .unwrap_or_else(|| "instruction not yet modeled".to_string()),
        SliceNodeKind::MemLiveIn => {
            let addr_str = node
                .meta
                .get("abs_addr")
                .cloned()
                .unwrap_or_default();
            let val_str = node.value_hex.clone().unwrap_or_default();
            format!("pre-trace memory at {addr_str} = {val_str}")
        }
        SliceNodeKind::Unknown => node
            .meta
            .get("reason")
            .cloned()
            .unwrap_or_else(|| "unknown origin".to_string()),
        SliceNodeKind::Mem | SliceNodeKind::Reg => "trace root".to_string(),
    }
}

fn build_data_flow_tree(
    target_id: usize,
    nodes: &[SliceNode],
    edges: &[TaintEdge],
) -> DataFlowNode {
    let node_map: HashMap<usize, &SliceNode> = nodes.iter().map(|n| (n.id, n)).collect();
    let mut incoming: HashMap<usize, Vec<&TaintEdge>> = HashMap::new();
    for edge in edges {
        incoming.entry(edge.dst_node_id).or_default().push(edge);
    }
    let mut path = HashSet::new();
    build_tree_recursive(target_id, None, &node_map, &incoming, &mut path, 0)
}

fn build_tree_recursive(
    node_id: usize,
    parent_edge: Option<&TaintEdge>,
    node_map: &HashMap<usize, &SliceNode>,
    incoming: &HashMap<usize, Vec<&TaintEdge>>,
    path: &mut HashSet<usize>,
    depth: usize,
) -> DataFlowNode {
    let node = match node_map.get(&node_id) {
        Some(n) => *n,
        None => {
            return DataFlowNode {
                value: String::new(),
                name: format!("missing_{node_id}"),
                kind: "Unknown".to_string(),
                source_line: 0,
                pc: String::new(),
                inst: String::new(),
                sources: Vec::new(),
            };
        }
    };

    let edges_in = incoming.get(&node_id).map(|v| v.as_slice()).unwrap_or(&[]);

    let (def_line, def_pc, def_inst) = if let Some(edge) = edges_in.first() {
        let line = if edge.inst_line > 0 {
            edge.inst_line
        } else {
            node.line_no
        };
        (line, edge.inst_pc, edge.inst_text.clone())
    } else if let Some(pe) = parent_edge {
        let line = if pe.inst_line > 0 { pe.inst_line } else { node.line_no };
        (line, pe.inst_pc, pe.inst_text.clone())
    } else {
        (node.line_no, 0, String::new())
    };

    let mut sources = Vec::new();
    if depth < 256 && path.insert(node_id) {
        for edge in edges_in {
            let src_node = node_map.get(&edge.src_node_id).copied();
            let should_flatten = src_node
                .map(|sn| {
                    sn.kind == SliceNodeKind::Mem
                        && incoming
                            .get(&sn.id)
                            .map(|e| {
                                e.len() == 1
                                    && node_map
                                        .get(&e[0].src_node_id)
                                        .map(|leaf| leaf.kind.is_terminal())
                                        .unwrap_or(false)
                            })
                            .unwrap_or(false)
                })
                .unwrap_or(false);

            if should_flatten {
                let mem_node = src_node.unwrap();
                let mem_edges = incoming.get(&mem_node.id).unwrap();
                for sub_edge in mem_edges {
                    sources.push(build_tree_recursive(
                        sub_edge.src_node_id,
                        Some(sub_edge),
                        node_map,
                        incoming,
                        path,
                        depth + 1,
                    ));
                }
            } else {
                sources.push(build_tree_recursive(
                    edge.src_node_id,
                    Some(edge),
                    node_map,
                    incoming,
                    path,
                    depth + 1,
                ));
            }
        }
        path.remove(&node_id);
    }

    DataFlowNode {
        value: node.value_hex.clone().unwrap_or_default(),
        name: node.name.clone(),
        kind: format!("{:?}", node.kind),
        source_line: def_line,
        pc: format!("0x{:x}", def_pc),
        inst: def_inst,
        sources,
    }
}

fn collect_chains(
    target: &SliceNode,
    incoming: &HashMap<usize, Vec<&TaintEdge>>,
    nodes: &[SliceNode],
    edges: &[TaintEdge],
) -> Vec<LinearChain> {
    let edge_map: HashMap<usize, &TaintEdge> = edges.iter().map(|edge| (edge.id, edge)).collect();
    let node_map: HashMap<usize, &SliceNode> = nodes.iter().map(|node| (node.id, node)).collect();
    let mut chains = Vec::new();
    let mut current_nodes = vec![target.id];
    let mut current_edges = Vec::new();
    let mut visiting = HashSet::new();
    dfs_chain(
        target.id,
        incoming,
        &node_map,
        &edge_map,
        &mut visiting,
        &mut current_nodes,
        &mut current_edges,
        &mut chains,
    );

    for (idx, chain) in chains.iter_mut().enumerate() {
        chain.chain_id = idx + 1;
    }

    chains
}

fn dfs_chain(
    node_id: usize,
    incoming: &HashMap<usize, Vec<&TaintEdge>>,
    node_map: &HashMap<usize, &SliceNode>,
    edge_map: &HashMap<usize, &TaintEdge>,
    visiting: &mut HashSet<usize>,
    current_nodes: &mut Vec<usize>,
    current_edges: &mut Vec<usize>,
    chains: &mut Vec<LinearChain>,
) {
    if !visiting.insert(node_id) {
        return;
    }

    let next_edges = incoming.get(&node_id).cloned().unwrap_or_default();
    if next_edges.is_empty() {
        let pretty = build_pretty_chain(current_nodes, current_edges, node_map, edge_map);
        let chain_confidence = compute_chain_confidence(current_edges, edge_map);
        chains.push(LinearChain {
            chain_id: 0,
            root_node_id: node_id,
            node_ids: current_nodes.clone(),
            edge_ids: current_edges.clone(),
            pretty,
            confidence: chain_confidence,
        });
        visiting.remove(&node_id);
        return;
    }

    for edge in next_edges {
        current_edges.push(edge.id);
        current_nodes.push(edge.src_node_id);
        dfs_chain(
            edge.src_node_id,
            incoming,
            node_map,
            edge_map,
            visiting,
            current_nodes,
            current_edges,
            chains,
        );
        current_nodes.pop();
        current_edges.pop();
    }

    visiting.remove(&node_id);
}

fn compute_chain_confidence(
    edge_ids: &[usize],
    edge_map: &HashMap<usize, &TaintEdge>,
) -> Confidence {
    let mut worst = Confidence::Exact;
    for eid in edge_ids {
        if let Some(edge) = edge_map.get(eid) {
            let ord = confidence_ord(&edge.confidence);
            if ord > confidence_ord(&worst) {
                worst = edge.confidence.clone();
            }
        }
    }
    worst
}

fn build_pretty_chain(
    node_ids: &[usize],
    edge_ids: &[usize],
    node_map: &HashMap<usize, &SliceNode>,
    edge_map: &HashMap<usize, &TaintEdge>,
) -> String {
    let mut parts = Vec::new();
    for (index, edge_id) in edge_ids.iter().enumerate() {
        if let (Some(dst), Some(src), Some(edge)) = (
            node_map.get(&node_ids[index]),
            node_map.get(&node_ids[index + 1]),
            edge_map.get(edge_id),
        ) {
            let conf_tag = match &edge.confidence {
                Confidence::Exact => "",
                Confidence::Possible => " [possible]",
                Confidence::Unknown => " [unknown]",
            };
            parts.push(format!(
                "L{}: `{}` {} {} from {}{}",
                edge.inst_line,
                edge.inst_text,
                node_label(dst),
                describe_reason(&edge.reason),
                node_label(src),
                conf_tag,
            ));
        }
    }
    parts.join(" -> ")
}

fn collect_steps(
    target: &SliceNode,
    nodes: &[SliceNode],
    edges: &[TaintEdge],
    incoming: &HashMap<usize, Vec<&TaintEdge>>,
) -> Vec<TraceStep> {
    let node_map: HashMap<usize, &SliceNode> = nodes.iter().map(|node| (node.id, node)).collect();
    let distances = distance_from_target(target.id, incoming);

    #[derive(Clone)]
    struct StepGroup {
        key: (usize, u64, String, usize, String),
        edge_ids: Vec<usize>,
        node_id: usize,
    }

    let mut groups: BTreeMap<(usize, u64, String, usize, String), StepGroup> = BTreeMap::new();
    for edge in edges {
        let key = (
            edge.inst_line,
            edge.inst_pc,
            edge.inst_text.clone(),
            edge.dst_node_id,
            format!("{:?}", edge.reason),
        );
        groups
            .entry(key.clone())
            .and_modify(|group| group.edge_ids.push(edge.id))
            .or_insert(StepGroup {
                key,
                edge_ids: vec![edge.id],
                node_id: edge.dst_node_id,
            });
    }

    let edge_map: HashMap<usize, &TaintEdge> = edges.iter().map(|edge| (edge.id, edge)).collect();
    let mut grouped: Vec<StepGroup> = groups.into_values().collect();
    grouped.sort_by(|left, right| {
        let left_distance = distances.get(&left.node_id).copied().unwrap_or(usize::MAX);
        let right_distance = distances.get(&right.node_id).copied().unwrap_or(usize::MAX);
        left_distance
            .cmp(&right_distance)
            .then_with(|| right.key.0.cmp(&left.key.0))
            .then_with(|| left.key.1.cmp(&right.key.1))
            .then_with(|| left.key.2.cmp(&right.key.2))
    });

    let mut edge_to_step = HashMap::new();
    let mut steps = Vec::new();
    for (order, group) in grouped.iter().enumerate() {
        let first = edge_map[&group.edge_ids[0]];
        let dst = node_map[&first.dst_node_id];
        let mut srcs: Vec<String> = group
            .edge_ids
            .iter()
            .filter_map(|edge_id| edge_map.get(edge_id))
            .map(|edge| node_label(node_map[&edge.src_node_id]))
            .collect();
        srcs.sort();
        srcs.dedup();

        let mut parent_step_ids = Vec::new();
        for edge_id in &group.edge_ids {
            if let Some(edge) = edge_map.get(edge_id) {
                if let Some(parent_edges) = incoming.get(&edge.src_node_id) {
                    for parent in parent_edges {
                        if let Some(step_id) = edge_to_step.get(&parent.id) {
                            parent_step_ids.push(*step_id);
                        }
                    }
                }
            }
        }
        parent_step_ids.sort_unstable();
        parent_step_ids.dedup();

        let step_id = steps.len() + 1;
        for edge_id in &group.edge_ids {
            edge_to_step.insert(*edge_id, step_id);
        }

        let data_hex = group
            .edge_ids
            .iter()
            .filter_map(|edge_id| edge_map.get(edge_id))
            .find_map(|edge| {
                node_map
                    .get(&edge.src_node_id)
                    .and_then(|node| node.value_hex.clone())
            });
        let mem_addr = node_map
            .get(&first.src_node_id)
            .and_then(|node| node.meta.get("abs_addr").cloned());
        let mut note_parts: Vec<String> = group
            .edge_ids
            .iter()
            .filter_map(|edge_id| edge_map.get(edge_id))
            .map(|edge| edge.note.clone())
            .collect();
        note_parts.sort();
        note_parts.dedup();

        let step_confidence = group
            .edge_ids
            .iter()
            .filter_map(|eid| edge_map.get(eid))
            .map(|e| confidence_ord(&e.confidence))
            .max()
            .map(|ord| match ord {
                0 => Confidence::Exact,
                1 => Confidence::Possible,
                _ => Confidence::Unknown,
            })
            .unwrap_or(Confidence::Exact);

        steps.push(TraceStep {
            step_id,
            order,
            kind: first.reason.clone(),
            line_no: first.inst_line,
            pc: first.inst_pc,
            inst_text: first.inst_text.clone(),
            dst: node_label(dst),
            srcs,
            mem_addr,
            data_hex,
            note: note_parts.join("; "),
            parent_step_ids,
            confidence: step_confidence,
        });
    }

    steps
}

fn distance_from_target(
    target_id: usize,
    incoming: &HashMap<usize, Vec<&TaintEdge>>,
) -> HashMap<usize, usize> {
    let mut distance = HashMap::new();
    let mut queue = std::collections::VecDeque::from([(target_id, 0usize)]);

    while let Some((node_id, depth)) = queue.pop_front() {
        if distance.contains_key(&node_id) {
            continue;
        }
        distance.insert(node_id, depth);
        for edge in incoming.get(&node_id).cloned().unwrap_or_default() {
            queue.push_back((edge.src_node_id, depth + 1));
        }
    }

    distance
}

fn describe_reason(reason: &crate::EdgeReason) -> &'static str {
    match reason {
        crate::EdgeReason::Read => "reads",
        crate::EdgeReason::Write => "writes",
        crate::EdgeReason::Calc => "calculates",
        crate::EdgeReason::Imm => "builds from immediate",
        crate::EdgeReason::Call => "returns from call",
        crate::EdgeReason::Phi => "selects from branch",
        crate::EdgeReason::Unknown => "comes from unknown source",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::indexer::build_trace_index;
    use crate::normalizer::parse_trace_text;
    use crate::{trace_backward, BackwardTaintOptions, BackwardTaintRequest, TargetKind};

    #[test]
    fn report_json_contains_expected_sections() {
        let trace = "\
1 | 0x1000 | movz w8, #0x12 | w8=0x12\n\
2 | 0x1004 | strb w8, [x1] | x1=0x2000 w8=0x12 mw=0x2000:[12]\n\
3 | 0x1008 | ldrb w9, [x2] | x2=0x2000 mr=0x2000:[12] w9=0x12";
        let insts = parse_trace_text(trace).expect("trace parses");
        let index = build_trace_index(&insts);
        let report = trace_backward(
            BackwardTaintRequest {
                target_kind: TargetKind::RegSlice,
                line_no: 3,
                reg: Some("w9".to_string()),
                mem_expr: None,
                bit_lo: 0,
                bit_hi: 7,
                options: BackwardTaintOptions::default(),
            },
            &insts,
            &index,
        )
        .expect("trace succeeds");

        let json = report_to_json(&report).expect("json renders");
        assert!(json.contains("\"data_flow\""));
        assert!(json.contains("\"summary\""));
        assert!(json.contains("\"exact_source_count\""));
        assert!(!json.contains("\"steps\""), "steps should be hidden");
        assert!(!json.contains("\"chains\""), "chains should be hidden");
    }

    #[test]
    fn report_confidence_stats_are_correct() {
        let trace = "20 | 0x5000 | csel w8, w0, w1, eq | w0=0x11 w1=0x22 w8=0x11";
        let insts = parse_trace_text(trace).expect("trace parses");
        let index = build_trace_index(&insts);
        let report = trace_backward(
            BackwardTaintRequest {
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

        assert!(report.summary.exact_source_count >= 1);
        assert!(report.summary.possible_source_count >= 1);
    }
}
