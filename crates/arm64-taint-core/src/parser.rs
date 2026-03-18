use crate::TraceInstRaw;
use regex::Regex;
use std::sync::OnceLock;

fn pc_style_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"^\s*(?P<pc>0x[0-9a-fA-F]+)\s+:?(?P<opcode>[0-9a-fA-F]{4,16})\s+(?P<inst>.+?)(?:\s*//(?P<ann>.*))?$",
        )
        .expect("valid pc style regex")
    })
}

fn line_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"^\s*(?P<line>\d+)\s*(?:\||:)?\s*(?P<pc>0x[0-9a-fA-F]+)?\s*(?:\||:)?\s*(?P<body>.*)$",
        )
        .expect("valid line regex")
    })
}

fn annotation_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b(?:mr|mw|x\d+|w\d+|sp|fp)\s*=").expect("valid annotation regex")
    })
}

fn looks_like_instruction_start(text: &str) -> bool {
    text.chars()
        .next()
        .map(|ch| ch.is_ascii_alphabetic())
        .unwrap_or(false)
}

pub(crate) fn parse_trace_text_raw(input: &str) -> Vec<TraceInstRaw> {
    input
        .lines()
        .enumerate()
        .filter_map(|(idx, line)| parse_trace_line(idx + 1, line))
        .collect()
}

pub(crate) fn parse_trace_line(source_line: usize, line: &str) -> Option<TraceInstRaw> {
    let raw = line.trim();
    if raw.is_empty()
        || raw.starts_with('#')
        || raw.starts_with("sym_")
        || raw.starts_with("sym:")
        || raw.contains(": ")
            && !raw.starts_with("0x")
            && raw.chars().next().map(|c| c.is_ascii_hexdigit()).unwrap_or(false)
    {
        return None;
    }

    if let Some(caps) = pc_style_regex().captures(raw) {
        let pc = u64::from_str_radix(caps.name("pc")?.as_str().trim_start_matches("0x"), 16).ok();
        let inst_text = caps.name("inst")?.as_str().trim().to_string();
        let annotation_text = caps
            .name("ann")
            .map(|m| m.as_str().trim().to_string())
            .unwrap_or_default();

        return Some(TraceInstRaw {
            source_line,
            line_no: source_line,
            pc,
            inst_text,
            annotation_text,
            raw_text: raw.to_string(),
        });
    }

    let caps = line_regex().captures(raw)?;
    let line_no = caps
        .name("line")
        .and_then(|m| m.as_str().parse::<usize>().ok())
        .unwrap_or(source_line);
    let pc = caps
        .name("pc")
        .and_then(|m| u64::from_str_radix(m.as_str().trim_start_matches("0x"), 16).ok());
    let body = caps.name("body").map(|m| m.as_str()).unwrap_or("");
    let (inst_text, annotation_text) = split_instruction_and_annotation(body);

    let inst_text = if inst_text.is_empty() {
        raw.to_string()
    } else {
        inst_text
    };

    Some(TraceInstRaw {
        source_line,
        line_no,
        pc,
        inst_text,
        annotation_text,
        raw_text: raw.to_string(),
    })
}

fn split_instruction_and_annotation(body: &str) -> (String, String) {
    let parts: Vec<&str> = body
        .split('|')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect();

    if parts.len() >= 2 && looks_like_instruction_start(parts[0]) {
        return (parts[0].to_string(), parts[1..].join(" "));
    }

    if let Some(mat) = annotation_regex().find(body) {
        let inst = body[..mat.start()].trim();
        let ann = body[mat.start()..].trim();
        return (inst.to_string(), ann.to_string());
    }

    (body.trim().to_string(), String::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pipe_style_line() {
        let raw = parse_trace_text_raw("12 | 0x4000 | ldrb w8, [x1] | mr=0x4010:[4A]");
        assert_eq!(raw.len(), 1);
        assert_eq!(raw[0].line_no, 12);
        assert_eq!(raw[0].pc, Some(0x4000));
        assert_eq!(raw[0].inst_text, "ldrb w8, [x1]");
        assert_eq!(raw[0].annotation_text, "mr=0x4010:[4A]");
    }

    #[test]
    fn parse_annotation_split_without_pipes() {
        let raw = parse_trace_text_raw("12 0x4000 mov w8, w9 w8=0x1 w9=0x1");
        assert_eq!(raw[0].inst_text, "mov w8, w9");
        assert!(raw[0].annotation_text.contains("w8=0x1"));
    }

    #[test]
    fn parse_pc_opcode_trace_style() {
        let raw = parse_trace_text_raw(
            "0x52c020\t4b028052\tmov     w11, #0x12                 \t//x11=0x0000000000000012,",
        );
        assert_eq!(raw.len(), 1);
        assert_eq!(raw[0].line_no, 1);
        assert_eq!(raw[0].pc, Some(0x52c020));
        assert_eq!(raw[0].inst_text, "mov     w11, #0x12");
        assert!(raw[0].annotation_text.contains("x11=0x0000000000000012"));
    }

    #[test]
    fn parse_colon_prefixed_opcode_format() {
        let raw = parse_trace_text_raw(
            "0x523718\t:4a0701ce  eor     w14, w14, w7               \t//x14=0x000000006568cf43,x14=0x00000000021d9b42,x7=0x0000000067755401,",
        );
        assert_eq!(raw.len(), 1);
        assert_eq!(raw[0].pc, Some(0x523718));
        assert_eq!(raw[0].inst_text, "eor     w14, w14, w7");
        assert!(raw[0].annotation_text.contains("x14=0x000000006568cf43"));
    }

    #[test]
    fn skip_memdump_and_symbol_lines() {
        let raw = parse_trace_text_raw(
            "sym_libc:memcpy=797cdf75c0 dst=781a4ee2a0 src=786ef35da8 0x48(72)\n786ef35da8: 29 1a 00 00",
        );
        assert!(raw.is_empty());
    }
}
