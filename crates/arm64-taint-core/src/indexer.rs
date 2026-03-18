use crate::{ByteCoverageGroup, MemoryWriteEvent, RegRef, TraceInst};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Clone, Serialize)]
pub struct TraceIndex {
    pub line_to_index: BTreeMap<usize, usize>,
    pub reg_defs: HashMap<String, Vec<usize>>,
    pub mem_stores: HashMap<String, Vec<usize>>,
    pub flag_defs: Vec<usize>,
    pub reg_versions: HashMap<(String, usize), usize>,
    pub mem_versions: HashMap<(String, usize), usize>,
    pub mem_write_events: Vec<MemoryWriteEvent>,
}

pub fn build_trace_index(insts: &[TraceInst]) -> TraceIndex {
    let mut line_to_index = BTreeMap::new();
    let mut reg_defs: HashMap<String, Vec<usize>> = HashMap::new();
    let mut mem_stores: HashMap<String, Vec<usize>> = HashMap::new();
    let mut flag_defs = Vec::new();
    let mut reg_versions = HashMap::new();
    let mut mem_versions = HashMap::new();
    let mut reg_counters: HashMap<String, usize> = HashMap::new();
    let mut mem_counters: HashMap<String, usize> = HashMap::new();
    let mut mem_write_events = Vec::new();

    for (index, inst) in insts.iter().enumerate() {
        line_to_index.insert(inst.line_no, index);

        if inst.sets_flags {
            flag_defs.push(index);
        }

        for reg in &inst.dst_regs {
            let entry = reg_defs.entry(reg.base.clone()).or_default();
            entry.push(index);
            let version = reg_counters.entry(reg.base.clone()).or_default();
            *version += 1;
            reg_versions.insert((reg.base.clone(), index), *version);
        }

        if let Some(mem) = &inst.mem_write {
            let entry = mem_stores.entry(mem.match_key.clone()).or_default();
            entry.push(index);
            let version = mem_counters.entry(mem.match_key.clone()).or_default();
            *version += 1;
            mem_versions.insert((mem.match_key.clone(), index), *version);

            if let Some(abs_addr) = mem.abs_addr {
                let size_bytes = (mem.size_bits / 8).max(1);
                mem_write_events.push(MemoryWriteEvent {
                    inst_index: index,
                    line_no: inst.line_no,
                    abs_addr,
                    size_bytes,
                    match_key: mem.match_key.clone(),
                    slot_name: mem.slot_name.clone(),
                    src_reg_base: inst.src_regs.first().map(|r| r.base.clone()),
                    data_hex: mem.data_hex.clone(),
                });
            }
        }
    }

    TraceIndex {
        line_to_index,
        reg_defs,
        mem_stores,
        flag_defs,
        reg_versions,
        mem_versions,
        mem_write_events,
    }
}

impl TraceIndex {
    pub fn inst_index_for_line(&self, line_no: usize) -> Option<usize> {
        self.line_to_index
            .range(..=line_no)
            .next_back()
            .map(|(_, idx)| *idx)
    }

    pub fn last_def_for_reg(&self, reg: &str, before_or_at_index: usize) -> Option<usize> {
        let defs = self.reg_defs.get(reg)?;
        let pos = defs.partition_point(|&idx| idx <= before_or_at_index);
        if pos > 0 { Some(defs[pos - 1]) } else { None }
    }

    pub fn last_store_for_key(&self, key: &str, before_or_at_index: usize) -> Option<usize> {
        let stores = self.mem_stores.get(key)?;
        let pos = stores.partition_point(|&idx| idx <= before_or_at_index);
        if pos > 0 { Some(stores[pos - 1]) } else { None }
    }

    pub fn last_flag_def(&self, before_or_at_index: usize) -> Option<usize> {
        let pos = self.flag_defs.partition_point(|&idx| idx <= before_or_at_index);
        if pos > 0 {
            Some(self.flag_defs[pos - 1])
        } else {
            None
        }
    }

    pub fn reg_version_at(&self, reg: &str, inst_index: Option<usize>) -> usize {
        inst_index
            .and_then(|idx| self.reg_versions.get(&(reg.to_string(), idx)).copied())
            .unwrap_or(0)
    }

    pub fn mem_version_at(&self, key: &str, inst_index: Option<usize>) -> usize {
        inst_index
            .and_then(|idx| self.mem_versions.get(&(key.to_string(), idx)).copied())
            .unwrap_or(0)
    }

    pub fn nearest_prev_line(&self, line_no: usize) -> usize {
        self.line_to_index
            .range(..line_no)
            .next_back()
            .map(|(line, _)| *line)
            .unwrap_or_else(|| line_no.saturating_sub(1))
    }

    pub fn find_covering_writes(
        &self,
        target_addr: u64,
        target_size_bytes: u16,
        before_index: usize,
    ) -> Vec<ByteCoverageGroup> {
        let target_end = target_addr + target_size_bytes as u64;
        let mut byte_sources: Vec<Option<usize>> = vec![None; target_size_bytes as usize];

        let cutoff = self
            .mem_write_events
            .partition_point(|evt| evt.inst_index < before_index);

        for evt_idx in 0..cutoff {
            let evt = &self.mem_write_events[evt_idx];
            let write_end = evt.abs_addr + evt.size_bytes as u64;
            if evt.abs_addr >= target_end || write_end <= target_addr {
                continue;
            }
            let overlap_start = evt.abs_addr.max(target_addr);
            let overlap_end = write_end.min(target_end);

            for addr in overlap_start..overlap_end {
                let offset = (addr - target_addr) as usize;
                match byte_sources[offset] {
                    None => byte_sources[offset] = Some(evt_idx),
                    Some(prev) => {
                        if self.mem_write_events[prev].inst_index < evt.inst_index {
                            byte_sources[offset] = Some(evt_idx);
                        }
                    }
                }
            }
        }

        coalesce_byte_coverage(&byte_sources)
    }

    pub fn is_pointer_like_use(&self, insts: &[TraceInst], reg: &RegRef, def_index: usize) -> bool {
        insts.iter().skip(def_index + 1).take(8).any(|inst| {
            inst.mem_read
                .as_ref()
                .map(|mem| mem.base_reg.as_deref() == Some(&reg.base) || mem.offset_reg.as_deref() == Some(&reg.base))
                .unwrap_or(false)
                || inst
                    .mem_write
                    .as_ref()
                    .map(|mem| mem.base_reg.as_deref() == Some(&reg.base) || mem.offset_reg.as_deref() == Some(&reg.base))
                    .unwrap_or(false)
        })
    }
}

fn coalesce_byte_coverage(byte_sources: &[Option<usize>]) -> Vec<ByteCoverageGroup> {
    let mut groups = Vec::new();
    let mut i = 0;
    while i < byte_sources.len() {
        let Some(evt_idx) = byte_sources[i] else {
            i += 1;
            continue;
        };
        let start = i;
        while i < byte_sources.len() && byte_sources[i] == Some(evt_idx) {
            i += 1;
        }
        let count = (i - start) as u16;
        let bit_lo = (start * 8) as u8;
        let bit_hi = ((start + count as usize) * 8 - 1) as u8;
        groups.push(ByteCoverageGroup {
            byte_offset: start as u16,
            byte_count: count,
            write_event_idx: evt_idx,
            bit_lo,
            bit_hi,
        });
    }
    groups
}
