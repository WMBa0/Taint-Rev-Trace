use crate::parser::{parse_trace_line, parse_trace_text_raw};
use crate::{MemAccess, MemAccessKind, RegRef, RegView, TraceInst};
use anyhow::Result;
use content_search_core::file_reader::FileReader;
use content_search_core::line_indexer::LineIndexer;
use regex::Regex;
use std::collections::BTreeMap;
use std::sync::OnceLock;

fn reg_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^(?i)(x\d+|w\d+|q\d+|v\d+(?:\.\w+)?|sp|fp|lr|xzr|wzr)$")
            .expect("valid register regex")
    })
}

fn reg_value_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\b(?P<name>x\d+|w\d+|q\d+|v\d+(?:\.\w+)?|sp|fp|lr)\s*=\s*(?P<value>0x[0-9a-fA-F]+|\d+)",
        )
        .expect("valid reg value regex")
    })
}

fn mem_read_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\bmr\s*=\s*(?P<addr>0x[0-9a-fA-F]+)\s*:\s*\[(?P<data>[0-9a-fA-F\s]*)\]")
            .expect("valid mem read regex")
    })
}

fn mem_write_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\bmw\s*=\s*(?P<addr>0x[0-9a-fA-F]+)\s*:\s*\[(?P<data>[0-9a-fA-F\s]*)\]")
            .expect("valid mem write regex")
    })
}

pub fn parse_trace_text(input: &str) -> Result<Vec<TraceInst>> {
    let raw = parse_trace_text_raw(input);
    Ok(raw
        .into_iter()
        .enumerate()
        .map(|(index, raw_inst)| normalize_inst(index, raw_inst))
        .collect())
}

/// Parse trace instructions from a FileReader + LineIndexer, only reading up to
/// `max_line` (1-indexed). Uses mmap for zero-copy byte access and avoids
/// parsing lines beyond the target, significantly improving performance on
/// large files.
pub fn parse_trace_from_reader(
    reader: &FileReader,
    indexer: &LineIndexer,
    max_line: usize,
) -> Result<Vec<TraceInst>> {
    let total = indexer.total_lines();
    let limit = max_line.min(total);
    let file_len = reader.len();

    let mut raw_insts = Vec::new();
    for line_idx in 0..limit {
        let source_line = line_idx + 1;
        if let Some((start, end)) = indexer.get_line_with_reader(line_idx, reader) {
            let end = end.min(file_len);
            if start >= end {
                continue;
            }
            let bytes = reader.get_bytes(start, end);
            let trimmed = bytes
                .strip_suffix(b"\r\n")
                .or_else(|| bytes.strip_suffix(b"\n"))
                .or_else(|| bytes.strip_suffix(b"\r"))
                .unwrap_or(bytes);
            let line_text = std::str::from_utf8(trimmed).unwrap_or("");
            if let Some(raw) = parse_trace_line(source_line, line_text) {
                raw_insts.push(raw);
            }
        }
    }

    Ok(raw_insts
        .into_iter()
        .enumerate()
        .map(|(index, raw)| normalize_inst(index, raw))
        .collect())
}

pub(crate) fn normalize_inst(index: usize, raw: crate::TraceInstRaw) -> TraceInst {
    let mut pieces = raw.inst_text.splitn(2, char::is_whitespace);
    let mnemonic = pieces
        .next()
        .unwrap_or("unknown")
        .trim()
        .to_ascii_lowercase();
    let operands_raw = pieces.next().unwrap_or("").trim().to_string();
    let operands = split_operands(&operands_raw);
    let reg_value_map = parse_reg_values(&raw.annotation_text);
    let mem_read_meta = parse_mem_meta(&raw.annotation_text, "mr");
    let mem_write_meta = parse_mem_meta(&raw.annotation_text, "mw");
    let shift = parse_shift(&operands);
    let cond = parse_cond(&mnemonic, &operands);
    let sets_flags = mnemonic_sets_flags(&mnemonic);

    let (dst_regs, src_regs, mem_read, mem_write, imm_values) = classify_operands(
        &mnemonic,
        &operands,
        &reg_value_map,
        mem_read_meta,
        mem_write_meta,
    );

    TraceInst {
        source_line: raw.source_line,
        line_no: raw.line_no,
        index,
        pc: raw.pc.unwrap_or(0),
        mnemonic,
        operands_raw,
        operands,
        inst_text: raw.inst_text,
        dst_regs,
        src_regs,
        mem_read,
        mem_write,
        imm_values,
        shift,
        cond,
        sets_flags,
        reg_value_map,
        raw_annotation: raw.annotation_text,
    }
}

fn mnemonic_sets_flags(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "cmp"
            | "cmn"
            | "tst"
            | "adds"
            | "adcs"
            | "subs"
            | "sbcs"
            | "ands"
            | "bics"
    )
}

fn parse_reg_values(annotation: &str) -> BTreeMap<String, u64> {
    let mut values = BTreeMap::new();
    for caps in reg_value_regex().captures_iter(annotation) {
        let name = normalize_reg_value_name(&caps["name"].to_ascii_lowercase());
        let raw = caps["value"].trim();
        let value = if let Some(hex) = raw.strip_prefix("0x") {
            u64::from_str_radix(hex, 16).ok()
        } else {
            raw.parse::<u64>().ok()
        };
        if let Some(value) = value {
            values.entry(name).or_insert(value);
        }
    }
    values
}

fn parse_mem_meta(annotation: &str, kind: &str) -> Option<(u64, String)> {
    let regex = match kind {
        "mr" => mem_read_regex(),
        "mw" => mem_write_regex(),
        _ => return None,
    };
    let caps = regex.captures(annotation)?;
    let addr = u64::from_str_radix(caps.name("addr")?.as_str().trim_start_matches("0x"), 16).ok()?;
    let data = caps
        .name("data")
        .map(|m| m.as_str().split_whitespace().collect::<String>())
        .unwrap_or_default();
    Some((addr, data))
}

fn classify_operands(
    mnemonic: &str,
    operands: &[String],
    reg_value_map: &BTreeMap<String, u64>,
    mem_read_meta: Option<(u64, String)>,
    mem_write_meta: Option<(u64, String)>,
) -> (Vec<RegRef>, Vec<RegRef>, Option<MemAccess>, Option<MemAccess>, Vec<i64>) {
    let mut dst_regs = Vec::new();
    let mut src_regs = Vec::new();
    let mut mem_read = None;
    let mut mem_write = None;
    let mut imm_values = Vec::new();

    match mnemonic {
        "mov" | "movz" | "movk" | "movn" | "adrp" | "adr" | "movi" | "mrs" => {
            if let Some(dst) = operands.first().and_then(|op| parse_reg(op)) {
                dst_regs.push(dst);
            }
            for operand in operands.iter().skip(1) {
                collect_operand(operand, &mut src_regs, &mut imm_values);
            }
        }
        "orr" | "and" | "eor" | "add" | "sub" | "lsl" | "lsr" | "asr" | "csel" => {
            if let Some(dst) = operands.first().and_then(|op| parse_reg(op)) {
                dst_regs.push(dst);
            }
            for operand in operands.iter().skip(1) {
                collect_operand(operand, &mut src_regs, &mut imm_values);
            }
        }
        "ldr" | "ldrb" | "ldrh" | "ldrsw" | "ldrsh" | "ldrsb"
        | "ldur" | "ldurb" | "ldurh" | "ldursw" | "ldursh" | "ldursb"
        | "ldar" | "ldarb" | "ldarh" => {
            if let Some(dst) = operands.first().and_then(|op| parse_reg(op)) {
                dst_regs.push(dst.clone());
            }
            if let Some(mem_operand) = operands.get(1) {
                let size_bits = load_size_bits(mnemonic, operands.first());
                mem_read = Some(parse_mem_access(
                    mem_operand,
                    MemAccessKind::Read,
                    size_bits,
                    reg_value_map,
                    mem_read_meta.or(mem_write_meta.clone()),
                ));
                collect_mem_src_regs(mem_operand, &mut src_regs);
            }
        }
        "ldp" => {
            if let Some(dst) = operands.first().and_then(|op| parse_reg(op)) {
                dst_regs.push(dst);
            }
            if let Some(dst) = operands.get(1).and_then(|op| parse_reg(op)) {
                dst_regs.push(dst);
            }
            if let Some(mem_operand) = operands.get(2) {
                mem_read = Some(parse_mem_access(
                    mem_operand,
                    MemAccessKind::Read,
                    128,
                    reg_value_map,
                    mem_read_meta.or(mem_write_meta.clone()),
                ));
                collect_mem_src_regs(mem_operand, &mut src_regs);
            }
        }
        "str" | "strb" | "strh" | "stur" | "sturb" | "sturh"
        | "stlr" | "stlrb" | "stlrh" => {
            if let Some(src) = operands.first().and_then(|op| parse_reg(op)) {
                src_regs.push(src);
            }
            if let Some(mem_operand) = operands.get(1) {
                let size_bits = store_size_bits(mnemonic, operands.first());
                mem_write = Some(parse_mem_access(
                    mem_operand,
                    MemAccessKind::Write,
                    size_bits,
                    reg_value_map,
                    mem_write_meta,
                ));
                collect_mem_src_regs(mem_operand, &mut src_regs);
            }
        }
        "stp" => {
            if let Some(src) = operands.first().and_then(|op| parse_reg(op)) {
                src_regs.push(src);
            }
            if let Some(src) = operands.get(1).and_then(|op| parse_reg(op)) {
                src_regs.push(src);
            }
            if let Some(mem_operand) = operands.get(2) {
                mem_write = Some(parse_mem_access(
                    mem_operand,
                    MemAccessKind::Write,
                    128,
                    reg_value_map,
                    mem_write_meta,
                ));
                collect_mem_src_regs(mem_operand, &mut src_regs);
            }
        }
        "bl" => {
            if let Some(ret) = parse_reg("x0") {
                dst_regs.push(ret);
            }
        }
        "cmp" | "cmn" | "tst" | "br" | "b" | "ret"
        | "tbnz" | "tbz" | "cbz" | "cbnz"
        | "b.eq" | "b.ne" | "b.lt" | "b.gt" | "b.le" | "b.ge"
        | "b.hi" | "b.lo" | "b.hs" | "b.ls" | "b.mi" | "b.pl"
        | "b.vs" | "b.vc" | "b.al" | "nop" | "dmb" | "dsb" | "isb" => {
            for operand in operands {
                collect_operand(operand, &mut src_regs, &mut imm_values);
            }
        }
        _ => {
            if let Some(dst) = operands.first().and_then(|op| parse_reg(op)) {
                dst_regs.push(dst);
            }
            for operand in operands.iter().skip(1) {
                collect_operand(operand, &mut src_regs, &mut imm_values);
            }
        }
    }

    (dst_regs, src_regs, mem_read, mem_write, imm_values)
}

fn parse_mem_access(
    operand: &str,
    kind: MemAccessKind,
    size_bits: u16,
    reg_value_map: &BTreeMap<String, u64>,
    meta: Option<(u64, String)>,
) -> MemAccess {
    let expr = operand.trim().to_string();
    let inner = expr.trim().trim_start_matches('[').trim_end_matches(']');
    let parts = split_operands(inner);
    let base_reg = parts.first().and_then(|part| parse_reg(part)).map(|r| r.base);
    let mut offset_reg = None;
    let mut offset_imm = None;

    if let Some(second) = parts.get(1) {
        if let Some(reg) = parse_reg(second) {
            offset_reg = Some(reg.base);
        } else if let Some(value) = parse_immediate(second) {
            offset_imm = Some(value);
        }
    }

    let abs_addr = meta.as_ref().map(|(addr, _)| *addr).or_else(|| {
        infer_abs_addr(base_reg.as_deref(), offset_reg.as_deref(), offset_imm, reg_value_map)
    });
    let slot_name = mem_slot_name(base_reg.as_deref(), offset_reg.as_deref(), offset_imm, &expr);
    let match_key = abs_addr
        .map(|addr| format!("abs_0x{addr:x}"))
        .unwrap_or_else(|| slot_name.clone());

    MemAccess {
        kind,
        expr,
        base_reg,
        offset_reg,
        offset_imm,
        slot_name,
        match_key,
        abs_addr,
        data_hex: meta
            .as_ref()
            .map(|(_, data)| data.to_ascii_uppercase())
            .filter(|data| !data.is_empty()),
        size_bits,
    }
}

fn collect_mem_src_regs(operand: &str, out: &mut Vec<RegRef>) {
    let inner = operand.trim().trim_start_matches('[').trim_end_matches(']');
    for part in split_operands(inner) {
        if let Some(reg) = parse_reg(&part) {
            out.push(reg);
        }
    }
}

fn collect_operand(operand: &str, regs: &mut Vec<RegRef>, imms: &mut Vec<i64>) {
    if let Some(reg) = parse_reg(operand) {
        regs.push(reg);
    } else if let Some(value) = parse_immediate(operand) {
        imms.push(value);
    }
}

pub(crate) fn parse_reg(text: &str) -> Option<RegRef> {
    let reg = text.trim().trim_end_matches('!').to_ascii_lowercase();
    if !reg_regex().is_match(&reg) {
        return None;
    }

    let (base, view, bit_hi) = if reg == "sp" {
        ("sp".to_string(), RegView::SP, 63)
    } else if reg == "fp" {
        ("x29".to_string(), RegView::X, 63)
    } else if reg == "lr" {
        ("x30".to_string(), RegView::X, 63)
    } else if reg == "xzr" {
        ("xzr".to_string(), RegView::X, 63)
    } else if reg == "wzr" {
        ("xzr".to_string(), RegView::W, 31)
    } else if let Some(idx) = reg.strip_prefix('x') {
        (format!("x{idx}"), RegView::X, 63)
    } else if let Some(idx) = reg.strip_prefix('w') {
        (format!("x{idx}"), RegView::W, 31)
    } else if let Some(idx) = reg.strip_prefix('q') {
        (format!("q{idx}"), RegView::X, 127)
    } else if let Some((head, _)) = reg.split_once('.') {
        if let Some(idx) = head.strip_prefix('v') {
            (format!("q{idx}"), RegView::X, 127)
        } else {
            return None;
        }
    } else {
        return None;
    };

    Some(RegRef {
        name: reg,
        base,
        view,
        bit_lo: 0,
        bit_hi,
    })
}

pub(crate) fn parse_immediate(text: &str) -> Option<i64> {
    let cleaned = text
        .trim()
        .trim_start_matches('#')
        .trim_end_matches('!')
        .trim();
    if cleaned.is_empty() {
        return None;
    }
    if let Some(hex) = cleaned.strip_prefix("-0x") {
        i64::from_str_radix(hex, 16).ok().map(|value| -value)
    } else if let Some(hex) = cleaned.strip_prefix("0x") {
        i64::from_str_radix(hex, 16).ok()
    } else {
        cleaned.parse::<i64>().ok()
    }
}

pub(crate) fn split_operands(text: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut depth = 0usize;

    for ch in text.chars() {
        match ch {
            '[' => {
                depth += 1;
                current.push(ch);
            }
            ']' => {
                depth = depth.saturating_sub(1);
                current.push(ch);
            }
            ',' if depth == 0 => {
                let trimmed = current.trim();
                if !trimmed.is_empty() {
                    parts.push(trimmed.to_string());
                }
                current.clear();
            }
            _ => current.push(ch),
        }
    }

    let trimmed = current.trim();
    if !trimmed.is_empty() {
        parts.push(trimmed.to_string());
    }
    parts
}

pub(crate) fn parse_shift(operands: &[String]) -> Option<u8> {
    operands
        .iter()
        .find_map(|operand| operand.trim().strip_prefix("lsl #"))
        .and_then(|value| value.parse::<u8>().ok())
}

fn parse_cond(mnemonic: &str, operands: &[String]) -> Option<String> {
    if mnemonic == "csel" {
        return operands.get(3).map(|value| value.trim().to_ascii_lowercase());
    }
    None
}

fn normalize_reg_value_name(raw_name: &str) -> String {
    parse_reg(raw_name)
        .map(|reg| reg.base)
        .unwrap_or_else(|| raw_name.to_ascii_lowercase())
}

fn infer_abs_addr(
    base_reg: Option<&str>,
    offset_reg: Option<&str>,
    offset_imm: Option<i64>,
    reg_value_map: &BTreeMap<String, u64>,
) -> Option<u64> {
    let base = base_reg
        .and_then(|name| reg_value_map.get(name))
        .copied()?;
    let reg_delta = offset_reg
        .and_then(|name| reg_value_map.get(name))
        .copied()
        .unwrap_or(0);
    let imm_delta = offset_imm.unwrap_or(0);
    Some(base.wrapping_add(reg_delta).wrapping_add_signed(imm_delta))
}

fn mem_slot_name(
    base_reg: Option<&str>,
    offset_reg: Option<&str>,
    offset_imm: Option<i64>,
    expr: &str,
) -> String {
    match (base_reg, offset_reg, offset_imm) {
        (Some("sp"), None, Some(offset)) => format!("stack_sp_{}", offset),
        (Some("x29"), None, Some(offset)) => format!("fp_{}", offset),
        (Some("x19"), None, Some(offset)) => format!("obj_x19_{offset:x}"),
        (Some(base), None, Some(offset)) => format!("{base}_{}", offset),
        (Some(base), Some(offset_reg), None) => format!("UNKNOWN_MEM([{base},{offset_reg}])"),
        _ => format!("UNKNOWN_MEM({})", expr),
    }
}

fn load_size_bits(mnemonic: &str, dst: Option<&String>) -> u16 {
    match mnemonic {
        "ldrb" | "ldurb" | "ldarb" | "ldrsb" | "ldursb" => 8,
        "ldrh" | "ldurh" | "ldarh" | "ldrsh" | "ldursh" => 16,
        "ldrsw" | "ldursw" => 32,
        _ => dst
            .and_then(|reg| parse_reg(reg))
            .map(|reg| if reg.view == RegView::W { 32 } else { 64 })
            .unwrap_or(64),
    }
}

fn store_size_bits(mnemonic: &str, src: Option<&String>) -> u16 {
    match mnemonic {
        "strb" | "sturb" | "stlrb" => 8,
        "strh" | "sturh" | "stlrh" => 16,
        _ => src
            .and_then(|reg| parse_reg(reg))
            .map(|reg| if reg.view == RegView::W { 32 } else { 64 })
            .unwrap_or(64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_operands_keeps_memory_expr() {
        let operands = split_operands("w8, [x1, x2], lsl #1");
        assert_eq!(operands, vec!["w8", "[x1, x2]", "lsl #1"]);
    }

    #[test]
    fn parse_trace_normalizes_memory() {
        let insts = parse_trace_text("12 | 0x4000 | ldrb w8, [x19, #0x10] | x19=0x5000 mr=0x5010:[4A]")
            .expect("trace parses");
        let inst = &insts[0];
        assert_eq!(inst.mnemonic, "ldrb");
        assert_eq!(inst.mem_read.as_ref().unwrap().match_key, "abs_0x5010");
        assert_eq!(inst.mem_read.as_ref().unwrap().slot_name, "obj_x19_10");
    }

    #[test]
    fn parse_sample_trace_style_line() {
        let insts = parse_trace_text(
            "0x534260\t480080b9\tldrsw   x8, [x2]                    \t//x8=0x0000000000000012,  mw=0x781a4ee290:[12000000]",
        )
        .expect("trace parses");
        let inst = &insts[0];
        assert_eq!(inst.line_no, 1);
        assert_eq!(inst.pc, 0x534260);
        assert_eq!(inst.mnemonic, "ldrsw");
        assert_eq!(inst.mem_read.as_ref().unwrap().match_key, "abs_0x781a4ee290");
    }

    #[test]
    fn reg_values_keep_first_occurrence_as_new_value() {
        let insts = parse_trace_text(
            "0x52c048\t29050051\tsub     w9, w9, #1                  \t//x9=0x0000000000000001,x9=0x0000000000000002,",
        )
        .expect("trace parses");
        assert_eq!(insts[0].reg_value_map.get("x9").copied(), Some(1));
    }
}
