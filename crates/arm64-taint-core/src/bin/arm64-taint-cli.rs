use anyhow::{anyhow, bail, Context, Result};
use arm64_taint_core::{
    report_to_json, trace_backward_streaming, BackwardTaintOptions, BackwardTaintRequest,
    StreamingTrace, TargetKind,
};
use content_search_core::file_reader::FileReader;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug)]
struct CliArgs {
    trace_file: PathBuf,
    target_kind: TargetKind,
    line_no: usize,
    reg: Option<String>,
    mem_expr: Option<String>,
    bit_lo: u8,
    bit_hi: u8,
    max_depth: usize,
    max_nodes: usize,
    per_branch_budget: usize,
    emit_linear_chains: bool,
    prune_equal_value_loads: bool,
    out_file: Option<PathBuf>,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = parse_args(env::args().skip(1).collect())?;
    let reader = FileReader::new(args.trace_file.clone(), encoding_rs::UTF_8)
        .with_context(|| format!("failed to open trace file {}", args.trace_file.display()))?;
    let streaming = StreamingTrace::new(Arc::new(reader));
    let report = trace_backward_streaming(
        BackwardTaintRequest {
            target_kind: args.target_kind,
            line_no: args.line_no,
            reg: args.reg,
            mem_expr: args.mem_expr,
            bit_lo: args.bit_lo,
            bit_hi: args.bit_hi,
            options: BackwardTaintOptions {
                max_depth: args.max_depth,
                max_nodes: args.max_nodes,
                dedup: true,
                emit_linear_chains: args.emit_linear_chains,
                per_branch_budget: args.per_branch_budget,
                prune_equal_value_loads: args.prune_equal_value_loads,
            },
        },
        &streaming,
    )?;
    let json = report_to_json(&report)?;

    if let Some(out_file) = args.out_file {
        fs::write(&out_file, json)
            .with_context(|| format!("failed to write report {}", out_file.display()))?;
        println!("{}", out_file.display());
    } else {
        println!("{json}");
    }

    Ok(())
}

fn parse_args(args: Vec<String>) -> Result<CliArgs> {
    if args.is_empty() || args.iter().any(|arg| arg == "-h" || arg == "--help") {
        print_usage();
        std::process::exit(0);
    }

    let trace_file = PathBuf::from(args[0].clone());
    let mut target_kind = None;
    let mut line_no = None;
    let mut reg = None;
    let mut mem_expr = None;
    let mut bit_lo = 0u8;
    let mut bit_hi = 63u8;
    let mut max_depth = 64usize;
    let mut max_nodes = 2000usize;
    let mut per_branch_budget = 500usize;
    let mut emit_linear_chains = true;
    let mut prune_equal_value_loads = true;
    let mut out_file = None;

    let mut idx = 1usize;
    while idx < args.len() {
        match args[idx].as_str() {
            "--line" => {
                idx += 1;
                line_no = Some(parse_usize_arg(&args, idx, "--line")?);
            }
            "--reg" => {
                idx += 1;
                let value = args.get(idx).ok_or_else(|| anyhow!("missing value for --reg"))?;
                reg = Some(value.clone());
                target_kind = Some(TargetKind::RegSlice);
            }
            "--mem" => {
                idx += 1;
                let value = args.get(idx).ok_or_else(|| anyhow!("missing value for --mem"))?;
                mem_expr = Some(value.clone());
                target_kind = Some(TargetKind::MemSlice);
            }
            "--bits" => {
                idx += 1;
                let value = args.get(idx).ok_or_else(|| anyhow!("missing value for --bits"))?;
                (bit_lo, bit_hi) = parse_bits(value)?;
            }
            "--max-depth" => {
                idx += 1;
                max_depth = parse_usize_arg(&args, idx, "--max-depth")?;
            }
            "--max-nodes" => {
                idx += 1;
                max_nodes = parse_usize_arg(&args, idx, "--max-nodes")?;
            }
            "--branch-budget" => {
                idx += 1;
                per_branch_budget = parse_usize_arg(&args, idx, "--branch-budget")?;
            }
            "--out" => {
                idx += 1;
                let value = args.get(idx).ok_or_else(|| anyhow!("missing value for --out"))?;
                out_file = Some(PathBuf::from(value));
            }
            "--no-chains" => {
                emit_linear_chains = false;
            }
            "--no-prune" => {
                prune_equal_value_loads = false;
            }
            other => bail!("unknown argument: {other}"),
        }
        idx += 1;
    }

    let target_kind = target_kind.ok_or_else(|| anyhow!("either --reg or --mem is required"))?;
    let line_no = line_no.ok_or_else(|| anyhow!("--line is required"))?;

    Ok(CliArgs {
        trace_file,
        target_kind,
        line_no,
        reg,
        mem_expr,
        bit_lo,
        bit_hi,
        max_depth,
        max_nodes,
        per_branch_budget,
        emit_linear_chains,
        prune_equal_value_loads,
        out_file,
    })
}

fn parse_usize_arg(args: &[String], idx: usize, flag: &str) -> Result<usize> {
    let value = args
        .get(idx)
        .ok_or_else(|| anyhow!("missing value for {flag}"))?;
    value
        .parse::<usize>()
        .with_context(|| format!("invalid integer for {flag}: {value}"))
}

fn parse_bits(value: &str) -> Result<(u8, u8)> {
    let (lo, hi) = value
        .split_once(':')
        .ok_or_else(|| anyhow!("--bits must be formatted as lo:hi"))?;
    let bit_lo = lo
        .parse::<u8>()
        .with_context(|| format!("invalid bit lo: {lo}"))?;
    let bit_hi = hi
        .parse::<u8>()
        .with_context(|| format!("invalid bit hi: {hi}"))?;
    if bit_lo > bit_hi {
        bail!("invalid bit range: {value}");
    }
    Ok((bit_lo, bit_hi))
}

fn print_usage() {
    println!(
        "\
Usage:
  arm64-taint-cli <trace-file> --line <line_no> --reg <reg>
  arm64-taint-cli <trace-file> --line <line_no> --mem <mem_expr>

Options:
  --bits <lo:hi>        Bit range, default 0:63
  --max-depth <n>       Max trace depth, default 64
  --max-nodes <n>       Max expanded nodes, default 2000
  --branch-budget <n>   Per-branch node budget, default 500
  --out <file>          Write JSON report to file
  --no-chains           Disable linear chain generation
  --no-prune            Disable equal-value load/store pruning

Examples:
  arm64-taint-cli sample.txt --line 72 --reg x8 --bits 0:31 --out report.json
  arm64-taint-cli sample.txt --line 10 --mem \"[x21]\" --bits 0:31
"
    );
}
