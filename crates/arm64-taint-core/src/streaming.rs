use crate::normalizer::normalize_inst;
use crate::parser::parse_trace_line;
use crate::{RegRef, TraceInst};
use content_search_core::file_reader::FileReader;
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Combined result for covering-write queries
// ---------------------------------------------------------------------------
#[derive(Clone)]
#[allow(dead_code)]
pub(crate) struct CoveringWrite {
    pub byte_offset: u16,
    pub byte_count: u16,
    pub bit_lo: u8,
    pub bit_hi: u8,
    pub inst: TraceInst,
    pub abs_addr: u64,
    pub src_reg_base: Option<String>,
    pub data_hex: Option<String>,
}

// ---------------------------------------------------------------------------
// Trait: abstract data access for the engine
// ---------------------------------------------------------------------------
pub(crate) trait TraceSource {
    fn get_inst_at_line(&self, line_no: usize) -> Option<TraceInst>;
    fn find_reg_def(&self, reg_base: &str, at_line: usize) -> Option<(usize, TraceInst)>;
    fn find_store(&self, match_key: &str, at_line: usize) -> Option<(usize, TraceInst)>;
    fn find_flag_def(&self, at_line: usize) -> Option<(usize, TraceInst)>;
    fn find_covering_writes(
        &self,
        target_addr: u64,
        target_size: u16,
        at_line: usize,
    ) -> Vec<CoveringWrite>;
    fn nearest_prev_line(&self, line_no: usize) -> usize;
    fn resolve_reg_value(&self, reg_base: &str, at_line: usize) -> Option<String>;
    fn reg_version(&self, reg_base: &str, at_line: usize) -> usize;
    fn mem_version(&self, match_key: &str, at_line: usize) -> usize;
    fn is_pointer_like_use(&self, reg: &RegRef, def_line: usize) -> bool;
}

// ===========================================================================
// PrecomputedSource — wraps the old (&[TraceInst], &TraceIndex) pair
// ===========================================================================
use crate::indexer::TraceIndex;

pub(crate) struct PrecomputedSource<'a> {
    pub insts: &'a [TraceInst],
    pub index: &'a TraceIndex,
}

impl<'a> TraceSource for PrecomputedSource<'a> {
    fn get_inst_at_line(&self, line_no: usize) -> Option<TraceInst> {
        let idx = self.index.inst_index_for_line(line_no)?;
        self.insts.get(idx).cloned()
    }

    fn find_reg_def(&self, reg_base: &str, at_line: usize) -> Option<(usize, TraceInst)> {
        let lookup = self.index.inst_index_for_line(at_line)?;
        let def_idx = self.index.last_def_for_reg(reg_base, lookup)?;
        let inst = self.insts.get(def_idx)?.clone();
        Some((inst.line_no, inst))
    }

    fn find_store(&self, match_key: &str, at_line: usize) -> Option<(usize, TraceInst)> {
        let lookup = self.index.inst_index_for_line(at_line)?;
        let store_idx = self.index.last_store_for_key(match_key, lookup)?;
        let inst = self.insts.get(store_idx)?.clone();
        Some((inst.line_no, inst))
    }

    fn find_flag_def(&self, at_line: usize) -> Option<(usize, TraceInst)> {
        let lookup = self.index.inst_index_for_line(at_line)?;
        let flag_idx = self.index.last_flag_def(lookup)?;
        let inst = self.insts.get(flag_idx)?.clone();
        Some((inst.line_no, inst))
    }

    fn find_covering_writes(
        &self,
        target_addr: u64,
        target_size: u16,
        at_line: usize,
    ) -> Vec<CoveringWrite> {
        let Some(lookup) = self.index.inst_index_for_line(at_line) else {
            return Vec::new();
        };
        let groups = self.index.find_covering_writes(target_addr, target_size, lookup);
        groups
            .into_iter()
            .filter_map(|g| {
                let evt = self.index.mem_write_events.get(g.write_event_idx)?;
                let inst = self.insts.get(evt.inst_index)?.clone();
                Some(CoveringWrite {
                    byte_offset: g.byte_offset,
                    byte_count: g.byte_count,
                    bit_lo: g.bit_lo,
                    bit_hi: g.bit_hi,
                    inst,
                    abs_addr: evt.abs_addr,
                    src_reg_base: evt.src_reg_base.clone(),
                    data_hex: evt.data_hex.clone(),
                })
            })
            .collect()
    }

    fn nearest_prev_line(&self, line_no: usize) -> usize {
        self.index.nearest_prev_line(line_no)
    }

    fn resolve_reg_value(&self, reg_base: &str, at_line: usize) -> Option<String> {
        let idx = self.index.inst_index_for_line(at_line)?;
        let def_idx = self.index.last_def_for_reg(reg_base, idx)?;
        let inst = self.insts.get(def_idx)?;
        inst.reg_value_map
            .get(reg_base)
            .map(|v| format!("0x{v:x}"))
    }

    fn reg_version(&self, reg_base: &str, at_line: usize) -> usize {
        let idx = self.index.inst_index_for_line(at_line);
        self.index
            .reg_version_at(reg_base, idx.and_then(|i| self.index.last_def_for_reg(reg_base, i)))
    }

    fn mem_version(&self, match_key: &str, at_line: usize) -> usize {
        let idx = self.index.inst_index_for_line(at_line);
        self.index
            .mem_version_at(match_key, idx.and_then(|i| self.index.last_store_for_key(match_key, i)))
    }

    fn is_pointer_like_use(&self, reg: &RegRef, def_line: usize) -> bool {
        if let Some(idx) = self.index.inst_index_for_line(def_line) {
            self.index.is_pointer_like_use(self.insts, reg, idx)
        } else {
            false
        }
    }
}

// ===========================================================================
// StreamingTrace — chunk-based backward scanning via FileReader
// ===========================================================================

const CHUNK_SIZE: usize = 2 * 1024 * 1024; // 2MB per chunk
const MAX_SCAN_LINES: usize = 50_000;

pub struct StreamingTrace {
    reader: Arc<FileReader>,
    file_size: usize,
    io_file: RefCell<Option<std::fs::File>>,
    inst_cache: RefCell<HashMap<usize, Option<TraceInst>>>,
    line_offsets: RefCell<BTreeMap<usize, usize>>,
    reg_def_cache: RefCell<HashMap<String, Vec<(usize, TraceInst)>>>,
    store_cache: RefCell<HashMap<String, Vec<(usize, TraceInst)>>>,
    reg_query_cache: RefCell<HashMap<(String, usize), Option<(usize, TraceInst)>>>,
    store_query_cache: RefCell<HashMap<(String, usize), Option<(usize, TraceInst)>>>,
    flag_def_query_cache: RefCell<HashMap<usize, Option<(usize, TraceInst)>>>,
}

impl StreamingTrace {
    pub fn new(reader: Arc<FileReader>) -> Self {
        let file_size = reader.len();
        let io_file = std::fs::File::open(reader.path()).ok();
        let mut initial = BTreeMap::new();
        initial.insert(1usize, 0usize);
        Self {
            reader,
            file_size,
            io_file: RefCell::new(io_file),
            inst_cache: RefCell::new(HashMap::new()),
            line_offsets: RefCell::new(initial),
            reg_def_cache: RefCell::new(HashMap::new()),
            store_cache: RefCell::new(HashMap::new()),
            reg_query_cache: RefCell::new(HashMap::new()),
            store_query_cache: RefCell::new(HashMap::new()),
            flag_def_query_cache: RefCell::new(HashMap::new()),
        }
    }

    fn line_byte_offset(&self, line_no: usize) -> Option<usize> {
        if line_no == 0 {
            return None;
        }
        {
            let map = self.line_offsets.borrow();
            if let Some(&off) = map.get(&line_no) {
                return Some(off);
            }
            if let Some((&cl, &cb)) = map.range(..=line_no).next_back() {
                if cl == line_no {
                    return Some(cb);
                }
                drop(map);
                return self.scan_forward_to_line(line_no, cl, cb);
            }
        }
        self.scan_forward_to_line(line_no, 1, 0)
    }

    fn scan_forward_to_line(
        &self,
        target_line: usize,
        start_line: usize,
        start_byte: usize,
    ) -> Option<usize> {
        let file = std::fs::File::open(self.reader.path()).ok()?;
        let mut br = BufReader::with_capacity(1024 * 1024, file);
        br.seek(SeekFrom::Start(start_byte as u64)).ok()?;

        let mut current_line = start_line;
        let mut byte_pos = start_byte;

        loop {
            let buf = br.fill_buf().ok()?;
            if buf.is_empty() {
                break;
            }
            let buf_len = buf.len();
            {
                let mut map = self.line_offsets.borrow_mut();
                for pos in memchr::memchr_iter(b'\n', buf) {
                    current_line += 1;
                    let new_byte = byte_pos + pos + 1;
                    map.insert(current_line, new_byte);
                    if current_line == target_line {
                        return Some(new_byte);
                    }
                }
            }
            byte_pos += buf_len;
            br.consume(buf_len);
        }
        None
    }

    fn parse_line_from_bytes(&self, line_no: usize, line_bytes: &[u8]) -> Option<TraceInst> {
        {
            let cache = self.inst_cache.borrow();
            if let Some(entry) = cache.get(&line_no) {
                return entry.clone();
            }
        }
        let trimmed = line_bytes.strip_suffix(b"\r").unwrap_or(line_bytes);
        let text = std::str::from_utf8(trimmed).ok()?;
        let raw = parse_trace_line(line_no, text)?;
        let inst = normalize_inst(0, raw);
        self.inst_cache
            .borrow_mut()
            .insert(line_no, Some(inst.clone()));
        Some(inst)
    }

    fn parse_at_line(&self, source_line: usize) -> Option<TraceInst> {
        {
            let cache = self.inst_cache.borrow();
            if let Some(entry) = cache.get(&source_line) {
                return entry.clone();
            }
        }
        if source_line == 0 {
            return None;
        }
        let start = self.line_byte_offset(source_line)?;
        let buf = self.read_via_io(start, 4096);
        let line_len = memchr::memchr(b'\n', &buf).unwrap_or(buf.len());
        let line_bytes = &buf[..line_len];
        let trimmed = line_bytes.strip_suffix(b"\r").unwrap_or(line_bytes);
        let text = std::str::from_utf8(trimmed).ok()?;
        let raw = parse_trace_line(source_line, text)?;
        let inst = normalize_inst(0, raw);
        self.inst_cache
            .borrow_mut()
            .insert(source_line, Some(inst.clone()));
        Some(inst)
    }

    fn read_via_io(&self, start: usize, max_len: usize) -> Vec<u8> {
        let end = (start + max_len).min(self.file_size);
        let len = end.saturating_sub(start);
        if len == 0 {
            return Vec::new();
        }
        let mut io = self.io_file.borrow_mut();
        if let Some(ref mut file) = *io {
            if file.seek(SeekFrom::Start(start as u64)).is_ok() {
                let mut buf = vec![0u8; len];
                if file.read_exact(&mut buf).is_ok() {
                    return buf;
                }
            }
        }
        self.reader.get_bytes(start, end).to_vec()
    }

    fn reg_num(base: &str) -> Option<u32> {
        let s = base
            .strip_prefix('x')
            .or_else(|| base.strip_prefix('w'))?;
        s.parse::<u32>().ok()
    }

    fn line_might_def_reg(inst_before_ann: &[u8], reg_num: u32) -> bool {
        let w_pat = format!(" w{},", reg_num);
        let x_pat = format!(" x{},", reg_num);
        if memmem(inst_before_ann, w_pat.as_bytes())
            || memmem(inst_before_ann, x_pat.as_bytes())
        {
            let mnemonic = extract_mnemonic(inst_before_ann);
            return !is_non_writing(mnemonic);
        }
        false
    }

    fn line_has_mem_write(raw: &[u8]) -> bool {
        memmem(raw, b"mw=")
    }

    fn inst_part(raw: &[u8]) -> &[u8] {
        match memchr::memmem::find(raw, b"//") {
            Some(pos) => &raw[..pos],
            None => raw,
        }
    }

    // -----------------------------------------------------------------------
    // Chunk-based backward iteration
    // -----------------------------------------------------------------------
    fn scan_chunk_backward<F>(
        &self,
        end_byte: usize,
        end_line_no: usize,
        visitor: &mut F,
    ) -> Option<(usize, usize)>
    where
        F: FnMut(usize, &[u8]) -> ScanAction,
    {
        if end_byte == 0 || end_line_no <= 1 {
            return None;
        }
        let start_byte = end_byte.saturating_sub(CHUNK_SIZE);
        let raw = self.read_via_io(start_byte, end_byte - start_byte);
        if raw.is_empty() {
            return None;
        }

        let data_start = if start_byte > 0 {
            match memchr::memchr(b'\n', &raw) {
                Some(p) => p + 1,
                None => return None,
            }
        } else {
            0
        };
        let data = &raw[data_start..];

        let nl_positions: Vec<usize> = memchr::memchr_iter(b'\n', data).collect();
        if nl_positions.is_empty() {
            return None;
        }

        let nl_count = nl_positions.len();
        let first_line_no = end_line_no - nl_count;

        for i in (0..nl_count).rev() {
            let line_no = first_line_no + i;
            let line_start = if i == 0 { 0 } else { nl_positions[i - 1] + 1 };
            let line_end = nl_positions[i];
            let line_bytes = &data[line_start..line_end];
            let line_bytes = line_bytes.strip_suffix(b"\r").unwrap_or(line_bytes);
            match visitor(line_no, line_bytes) {
                ScanAction::Continue => {}
                ScanAction::Found => return Some((0, 0)),
            }
        }

        Some((start_byte + data_start, first_line_no))
    }

    fn resolve_end_byte(&self, at_line: usize) -> Option<usize> {
        self.line_byte_offset(at_line)
    }

    // -----------------------------------------------------------------------
    // Core backward scan with distance limit
    // -----------------------------------------------------------------------

    fn find_reg_def_scan(&self, reg_base: &str, at_line: usize) -> Option<(usize, TraceInst)> {
        {
            let cache = self.reg_def_cache.borrow();
            if let Some(defs) = cache.get(reg_base) {
                let pos = defs.partition_point(|&(l, _)| l <= at_line);
                if pos > 0 {
                    let (line, ref inst) = defs[pos - 1];
                    return Some((line, inst.clone()));
                }
            }
        }

        let reg_num = Self::reg_num(reg_base)?;
        let end_byte = self.resolve_end_byte(at_line.saturating_add(1))?;
        let min_line = at_line.saturating_sub(MAX_SCAN_LINES);
        let mut cur_end_byte = end_byte;
        let mut cur_end_line = at_line + 1;

        loop {
            if cur_end_line <= min_line.saturating_add(1) {
                return None;
            }

            let next = self.scan_chunk_backward(cur_end_byte, cur_end_line, &mut |line_no, bytes| {
                if line_no < min_line {
                    return ScanAction::Continue;
                }
                let inst_area = Self::inst_part(bytes);
                if Self::line_might_def_reg(inst_area, reg_num) {
                    if let Some(inst) = self.parse_line_from_bytes(line_no, bytes) {
                        if inst.dst_regs.iter().any(|r| r.base == reg_base) {
                            let mut cache = self.reg_def_cache.borrow_mut();
                            let entry = cache.entry(reg_base.to_string()).or_default();
                            let insert_pos = entry.partition_point(|&(l, _)| l < line_no);
                            if insert_pos >= entry.len() || entry[insert_pos].0 != line_no {
                                entry.insert(insert_pos, (line_no, inst));
                            }
                        }
                    }
                }
                ScanAction::Continue
            });

            {
                let cache = self.reg_def_cache.borrow();
                if let Some(defs) = cache.get(reg_base) {
                    let pos = defs.partition_point(|&(l, _)| l <= at_line);
                    if pos > 0 {
                        let (line, ref inst) = defs[pos - 1];
                        return Some((line, inst.clone()));
                    }
                }
            }

            match next {
                Some((0, 0)) => return None,
                Some((new_end_byte, new_end_line)) if new_end_byte > 0 => {
                    if new_end_line <= min_line {
                        return None;
                    }
                    cur_end_byte = new_end_byte;
                    cur_end_line = new_end_line;
                }
                _ => return None,
            }
        }
    }

    fn find_store_scan(&self, match_key: &str, at_line: usize) -> Option<(usize, TraceInst)> {
        {
            let cache = self.store_cache.borrow();
            if let Some(stores) = cache.get(match_key) {
                let pos = stores.partition_point(|&(l, _)| l <= at_line);
                if pos > 0 {
                    let (line, ref inst) = stores[pos - 1];
                    return Some((line, inst.clone()));
                }
            }
        }

        let end_byte = self.resolve_end_byte(at_line.saturating_add(1))?;
        let min_line = at_line.saturating_sub(MAX_SCAN_LINES);
        let mut cur_end_byte = end_byte;
        let mut cur_end_line = at_line + 1;

        loop {
            if cur_end_line <= min_line.saturating_add(1) {
                return None;
            }

            let next = self.scan_chunk_backward(cur_end_byte, cur_end_line, &mut |line_no, bytes| {
                if line_no < min_line {
                    return ScanAction::Continue;
                }
                if Self::line_has_mem_write(bytes) {
                    if let Some(inst) = self.parse_line_from_bytes(line_no, bytes) {
                        if let Some(mw) = &inst.mem_write {
                            let mut cache = self.store_cache.borrow_mut();
                            let entry = cache.entry(mw.match_key.clone()).or_default();
                            let insert_pos = entry.partition_point(|&(l, _)| l < line_no);
                            if insert_pos >= entry.len() || entry[insert_pos].0 != line_no {
                                entry.insert(insert_pos, (line_no, inst));
                            }
                        }
                    }
                }
                ScanAction::Continue
            });

            {
                let cache = self.store_cache.borrow();
                if let Some(stores) = cache.get(match_key) {
                    let pos = stores.partition_point(|&(l, _)| l <= at_line);
                    if pos > 0 {
                        let (line, ref inst) = stores[pos - 1];
                        return Some((line, inst.clone()));
                    }
                }
            }

            match next {
                Some((0, 0)) => return None,
                Some((new_end_byte, new_end_line)) if new_end_byte > 0 => {
                    if new_end_line <= min_line {
                        return None;
                    }
                    cur_end_byte = new_end_byte;
                    cur_end_line = new_end_line;
                }
                _ => return None,
            }
        }
    }

    fn find_flag_def_scan(&self, at_line: usize) -> Option<(usize, TraceInst)> {
        let end_byte = self.resolve_end_byte(at_line.saturating_add(1))?;
        let min_line = at_line.saturating_sub(MAX_SCAN_LINES);
        let mut cur_end_byte = end_byte;
        let mut cur_end_line = at_line + 1;

        loop {
            if cur_end_line <= min_line.saturating_add(1) {
                return None;
            }

            let mut found: Option<(usize, TraceInst)> = None;
            let next = self.scan_chunk_backward(cur_end_byte, cur_end_line, &mut |line_no, bytes| {
                if line_no < min_line {
                    return ScanAction::Continue;
                }
                let inst_area = Self::inst_part(bytes);
                if line_might_set_flags(inst_area) {
                    if let Some(inst) = self.parse_line_from_bytes(line_no, bytes) {
                        if inst.sets_flags {
                            found = Some((line_no, inst));
                            return ScanAction::Found;
                        }
                    }
                }
                ScanAction::Continue
            });

            if found.is_some() {
                return found;
            }

            match next {
                Some((0, 0)) => return None,
                Some((new_end_byte, new_end_line)) if new_end_byte > 0 => {
                    if new_end_line <= min_line {
                        return None;
                    }
                    cur_end_byte = new_end_byte;
                    cur_end_line = new_end_line;
                }
                _ => return None,
            }
        }
    }
}

enum ScanAction {
    Continue,
    Found,
}

impl TraceSource for StreamingTrace {
    fn get_inst_at_line(&self, line_no: usize) -> Option<TraceInst> {
        self.parse_at_line(line_no)
    }

    fn find_reg_def(&self, reg_base: &str, at_line: usize) -> Option<(usize, TraceInst)> {
        {
            let qc = self.reg_query_cache.borrow();
            if let Some(result) = qc.get(&(reg_base.to_string(), at_line)) {
                return result.clone();
            }
        }
        let result = self.find_reg_def_scan(reg_base, at_line);
        self.reg_query_cache
            .borrow_mut()
            .insert((reg_base.to_string(), at_line), result.clone());
        result
    }

    fn find_store(&self, match_key: &str, at_line: usize) -> Option<(usize, TraceInst)> {
        {
            let qc = self.store_query_cache.borrow();
            if let Some(result) = qc.get(&(match_key.to_string(), at_line)) {
                return result.clone();
            }
        }
        let result = self.find_store_scan(match_key, at_line);
        self.store_query_cache
            .borrow_mut()
            .insert((match_key.to_string(), at_line), result.clone());
        result
    }

    fn find_flag_def(&self, at_line: usize) -> Option<(usize, TraceInst)> {
        {
            let qc = self.flag_def_query_cache.borrow();
            if let Some(result) = qc.get(&at_line) {
                return result.clone();
            }
        }
        let result = self.find_flag_def_scan(at_line);
        self.flag_def_query_cache
            .borrow_mut()
            .insert(at_line, result.clone());
        result
    }

    fn find_covering_writes(
        &self,
        target_addr: u64,
        target_size: u16,
        at_line: usize,
    ) -> Vec<CoveringWrite> {
        let target_end = target_addr + target_size as u64;
        let mut byte_sources: Vec<Option<(usize, TraceInst)>> = vec![None; target_size as usize];

        let Some(end_byte) = self.resolve_end_byte(at_line.saturating_add(1)) else {
            return Vec::new();
        };
        let min_line = at_line.saturating_sub(MAX_SCAN_LINES);
        let mut cur_end_byte = end_byte;
        let mut cur_end_line = at_line + 1;

        loop {
            let all_covered = byte_sources.iter().all(|s| s.is_some());
            if all_covered {
                break;
            }
            if cur_end_line <= min_line.saturating_add(1) {
                break;
            }

            let next = self.scan_chunk_backward(cur_end_byte, cur_end_line, &mut |line_no, bytes| {
                if line_no < min_line {
                    return ScanAction::Continue;
                }
                if Self::line_has_mem_write(bytes) {
                    if let Some(inst) = self.parse_line_from_bytes(line_no, bytes) {
                        if let Some(mw) = &inst.mem_write {
                            if let Some(wa) = mw.abs_addr {
                                let write_end = wa + (mw.size_bits / 8).max(1) as u64;
                                if wa < target_end && write_end > target_addr {
                                    let overlap_start = wa.max(target_addr);
                                    let overlap_end = write_end.min(target_end);
                                    for addr in overlap_start..overlap_end {
                                        let off = (addr - target_addr) as usize;
                                        if byte_sources[off].is_none() {
                                            byte_sources[off] = Some((line_no, inst.clone()));
                                        }
                                    }
                                    if byte_sources.iter().all(|s| s.is_some()) {
                                        return ScanAction::Found;
                                    }
                                }
                            }
                        }
                    }
                }
                ScanAction::Continue
            });

            match next {
                Some((0, 0)) => break,
                Some((new_end_byte, new_end_line)) => {
                    if new_end_line <= min_line {
                        break;
                    }
                    cur_end_byte = new_end_byte;
                    cur_end_line = new_end_line;
                }
                None => break,
            }
        }

        coalesce_streaming(&byte_sources, target_addr)
    }

    fn nearest_prev_line(&self, line_no: usize) -> usize {
        line_no.saturating_sub(1)
    }

    fn resolve_reg_value(&self, reg_base: &str, at_line: usize) -> Option<String> {
        let (_, inst) = self.find_reg_def(reg_base, at_line)?;
        inst.reg_value_map
            .get(reg_base)
            .map(|v| format!("0x{v:x}"))
    }

    fn reg_version(&self, reg_base: &str, at_line: usize) -> usize {
        self.find_reg_def(reg_base, at_line)
            .map(|(l, _)| l)
            .unwrap_or(0)
    }

    fn mem_version(&self, match_key: &str, at_line: usize) -> usize {
        self.find_store(match_key, at_line)
            .map(|(l, _)| l)
            .unwrap_or(0)
    }

    fn is_pointer_like_use(&self, _reg: &RegRef, _def_line: usize) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn memmem(haystack: &[u8], needle: &[u8]) -> bool {
    memchr::memmem::find(haystack, needle).is_some()
}

fn extract_mnemonic(inst_bytes: &[u8]) -> &[u8] {
    let text = match inst_bytes.iter().position(|&b| b.is_ascii_alphabetic()) {
        Some(pos) => &inst_bytes[pos..],
        None => return b"",
    };
    let end = text
        .iter()
        .position(|&b| b == b' ' || b == b'\t')
        .unwrap_or(text.len());
    &text[..end]
}

fn is_non_writing(mnemonic: &[u8]) -> bool {
    let m = mnemonic.to_ascii_lowercase();
    matches!(
        m.as_slice(),
        b"str" | b"strb" | b"strh"
            | b"stp" | b"stur" | b"sturb" | b"sturh"
            | b"stlr" | b"stlrb" | b"stlrh"
            | b"cmp" | b"cmn" | b"tst"
            | b"nop"
            | b"ret" | b"br" | b"blr" | b"bl"
            | b"dmb" | b"dsb" | b"isb"
    ) || m.starts_with(b"b.")
}

fn line_might_set_flags(inst_bytes: &[u8]) -> bool {
    let mnemonic = extract_mnemonic(inst_bytes);
    let m = mnemonic.to_ascii_lowercase();
    matches!(
        m.as_slice(),
        b"cmp" | b"cmn" | b"tst" | b"adds" | b"adcs" | b"subs" | b"sbcs" | b"ands" | b"bics"
    )
}

fn coalesce_streaming(
    byte_sources: &[Option<(usize, TraceInst)>],
    target_addr: u64,
) -> Vec<CoveringWrite> {
    let mut groups = Vec::new();
    let mut i = 0;
    while i < byte_sources.len() {
        let Some((line, inst)) = &byte_sources[i] else {
            i += 1;
            continue;
        };
        let start = i;
        let cur_line = *line;
        while i < byte_sources.len() {
            match &byte_sources[i] {
                Some((l, _)) if *l == cur_line => i += 1,
                _ => break,
            }
        }
        let count = (i - start) as u16;
        let bit_lo = (start * 8) as u8;
        let bit_hi = ((start + count as usize) * 8 - 1) as u8;
        let mw = inst.mem_write.as_ref();
        groups.push(CoveringWrite {
            byte_offset: start as u16,
            byte_count: count,
            bit_lo,
            bit_hi,
            inst: inst.clone(),
            abs_addr: mw.and_then(|m| m.abs_addr).unwrap_or(target_addr),
            src_reg_base: inst.src_regs.first().map(|r| r.base.clone()),
            data_hex: mw.and_then(|m| m.data_hex.clone()),
        });
    }
    groups
}
