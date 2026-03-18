use crate::cache::cache_file_for_path;
use crate::file_reader::FileReader;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;

const LINE_INDEX_CACHE_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IndexMode {
    Full,
    Sparse,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IndexCacheStatus {
    Hit,
    MissStored,
    MissSkipped,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexBuildReport {
    pub mode: IndexMode,
    pub cache_status: IndexCacheStatus,
    pub total_lines: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LineIndexCache {
    version: u32,
    file_size: usize,
    line_offsets: Vec<usize>,
    sparse_checkpoint_offsets: Vec<usize>,
    sparse_checkpoint_lines: Vec<usize>,
    total_lines: usize,
    sample_interval: usize,
    avg_line_length: f64,
}

pub struct LineIndexer {
    line_offsets: Vec<usize>,
    sparse_checkpoint_offsets: Vec<usize>,
    sparse_checkpoint_lines: Vec<usize>,
    total_lines: usize,
    indexed: bool,
    // Sparse sampling for large files
    sample_interval: usize,
    file_size: usize,
    avg_line_length: f64,
}

impl Default for LineIndexer {
    fn default() -> Self {
        Self::new()
    }
}

impl LineIndexer {
    pub fn new() -> Self {
        Self {
            line_offsets: vec![0],
            sparse_checkpoint_offsets: Vec::new(),
            sparse_checkpoint_lines: Vec::new(),
            total_lines: 0,
            indexed: false,
            sample_interval: 0,
            file_size: 0,
            avg_line_length: 80.0,
        }
    }

    pub fn index_file(&mut self, reader: &FileReader) {
        self.reset_for_file(reader.len());

        // For small files (< 10MB), do full indexing
        // For large files, use sparse sampling only
        const FULL_INDEX_THRESHOLD: usize = 10_000_000; // 10 MB

        if self.file_size <= FULL_INDEX_THRESHOLD {
            // Full indexing for smaller files
            let data = reader.all_data();
            self.full_index(data);
            self.sample_interval = 0;
            self.total_lines = self.line_offsets.len();
        } else {
            // Sparse sampling for large files - only sample at intervals
            self.sparse_sample_index(reader);
            self.total_lines = self
                .sparse_checkpoint_lines
                .last()
                .copied()
                .unwrap_or(0)
                .saturating_add(1);
        }

        self.indexed = true;
    }

    pub fn index_file_cached(&mut self, reader: &FileReader) -> IndexBuildReport {
        let cache_path = reader
            .path()
            .metadata()
            .ok()
            .map(|metadata| cache_file_for_path("line-index", reader.path(), &metadata));

        if let Some(path) = &cache_path {
            if let Ok(bytes) = fs::read(path) {
                if let Ok(cache) = bincode::deserialize::<LineIndexCache>(&bytes) {
                    if cache.version == LINE_INDEX_CACHE_VERSION && cache.file_size == reader.len() {
                        self.apply_cache(cache);
                        return IndexBuildReport {
                            mode: self.index_mode(),
                            cache_status: IndexCacheStatus::Hit,
                            total_lines: self.total_lines,
                        };
                    }
                }
            }
        }

        self.index_file(reader);
        let cache_status = match cache_path {
            Some(path) => {
                let snapshot = self.snapshot();
                let write_result: Result<()> = (|| {
                    if let Some(parent) = path.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    fs::write(path, bincode::serialize(&snapshot)?)?;
                    Ok(())
                })();
                if write_result.is_ok() {
                    IndexCacheStatus::MissStored
                } else {
                    IndexCacheStatus::MissSkipped
                }
            }
            None => IndexCacheStatus::MissSkipped,
        };

        IndexBuildReport {
            mode: self.index_mode(),
            cache_status,
            total_lines: self.total_lines,
        }
    }

    fn reset_for_file(&mut self, file_size: usize) {
        self.line_offsets.clear();
        self.line_offsets.push(0);
        self.sparse_checkpoint_offsets.clear();
        self.sparse_checkpoint_lines.clear();
        self.total_lines = 0;
        self.indexed = false;
        self.sample_interval = 0;
        self.file_size = file_size;
        self.avg_line_length = 80.0;
    }

    fn snapshot(&self) -> LineIndexCache {
        LineIndexCache {
            version: LINE_INDEX_CACHE_VERSION,
            file_size: self.file_size,
            line_offsets: self.line_offsets.clone(),
            sparse_checkpoint_offsets: self.sparse_checkpoint_offsets.clone(),
            sparse_checkpoint_lines: self.sparse_checkpoint_lines.clone(),
            total_lines: self.total_lines,
            sample_interval: self.sample_interval,
            avg_line_length: self.avg_line_length,
        }
    }

    fn apply_cache(&mut self, cache: LineIndexCache) {
        self.file_size = cache.file_size;
        self.line_offsets = cache.line_offsets;
        self.sparse_checkpoint_offsets = cache.sparse_checkpoint_offsets;
        self.sparse_checkpoint_lines = cache.sparse_checkpoint_lines;
        self.total_lines = cache.total_lines;
        self.sample_interval = cache.sample_interval;
        self.avg_line_length = cache.avg_line_length;
        self.indexed = true;
    }

    pub fn index_mode(&self) -> IndexMode {
        if self.sample_interval == 0 {
            IndexMode::Full
        } else {
            IndexMode::Sparse
        }
    }

    fn full_index(&mut self, data: &[u8]) {
        for (i, &byte) in data.iter().enumerate() {
            if byte == b'\n' {
                self.line_offsets.push(i + 1);
            }
        }
    }

    fn sparse_sample_index(&mut self, reader: &FileReader) {
        // Only sample every 10MB for large files - creates sparse checkpoint index
        const SPARSE_SAMPLE_SIZE: usize = 10_000_000; // 10MB
        self.sample_interval = SPARSE_SAMPLE_SIZE;

        let mut pos = 0;
        let mut cumulative_lines = 0usize;

        let mut total_bytes_sampled = 0;
        let mut total_newlines_found = 0;

        while pos < self.file_size {
            self.sparse_checkpoint_offsets.push(pos);
            self.sparse_checkpoint_lines.push(cumulative_lines);

            let chunk_end = (pos + SPARSE_SAMPLE_SIZE).min(self.file_size);
            let chunk = reader.get_bytes(pos, chunk_end);
            let newline_count = chunk.iter().filter(|&&b| b == b'\n').count();

            total_bytes_sampled += chunk.len();
            total_newlines_found += newline_count;
            cumulative_lines += newline_count;

            pos = chunk_end;
        }

        self.sparse_checkpoint_offsets.push(self.file_size);
        self.sparse_checkpoint_lines.push(cumulative_lines);

        if total_newlines_found > 0 {
            self.avg_line_length = total_bytes_sampled as f64 / total_newlines_found as f64;
        }
    }

    pub fn get_line_range(&self, line_num: usize) -> Option<(usize, usize)> {
        if self.sample_interval == 0 {
            // Full index available
            if line_num >= self.line_offsets.len() {
                return None;
            }

            let start = self.line_offsets[line_num];
            let end = if line_num + 1 < self.line_offsets.len() {
                self.line_offsets[line_num + 1]
            } else {
                usize::MAX
            };

            Some((start, end))
        } else {
            // Sparse index - estimate line position
            // This will be resolved on-demand in get_line_with_reader
            let estimated_pos = (line_num as f64 * self.avg_line_length) as usize;
            Some((estimated_pos, usize::MAX))
        }
    }

    // Helper method to get actual line content by scanning from estimated position
    pub fn get_line_with_reader(
        &self,
        line_num: usize,
        reader: &FileReader,
    ) -> Option<(usize, usize)> {
        if self.sample_interval == 0 {
            // Use full index
            return self.get_line_range(line_num);
        }

        if self.sparse_checkpoint_offsets.is_empty() || line_num >= self.total_lines {
            return None;
        }

        let checkpoint_index = self
            .sparse_checkpoint_lines
            .partition_point(|&checkpoint_line| checkpoint_line <= line_num)
            .saturating_sub(1);
        let mut current_line = self.sparse_checkpoint_lines[checkpoint_index];
        let mut line_start = self.sparse_checkpoint_offsets[checkpoint_index];

        if current_line < line_num {
            while current_line < line_num && line_start < self.file_size {
                let chunk_end = (line_start + 65536).min(self.file_size);
                let chunk_start = line_start;
                let chunk = reader.get_bytes(chunk_start, chunk_end);
                if chunk.is_empty() {
                    break;
                }

                let mut advanced = false;
                for (idx, &byte) in chunk.iter().enumerate() {
                    if byte == b'\n' {
                        current_line += 1;
                        line_start = chunk_start + idx + 1;
                        advanced = true;
                        if current_line == line_num {
                            break;
                        }
                    }
                }

                if current_line >= line_num {
                    break;
                }

                if !advanced {
                    line_start = chunk_end;
                } else if line_start < chunk_end {
                    line_start = chunk_end;
                }
            }
        }

        let mut line_end = line_start;
        while line_end < self.file_size {
            let chunk_end = (line_end + 65536).min(self.file_size);
            let chunk = reader.get_bytes(line_end, chunk_end);
            if chunk.is_empty() {
                break;
            }

            if let Some(idx) = chunk.iter().position(|&byte| byte == b'\n') {
                line_end += idx;
                return Some((line_start, line_end));
            }

            line_end = chunk_end;
        }

        Some((line_start, line_end))
    }

    pub fn find_line_at_offset(&self, offset: usize, reader: Option<&FileReader>) -> usize {
        if self.sample_interval == 0 {
            // Full index
            match self.line_offsets.binary_search(&offset) {
                Ok(line) => line,
                Err(line) => line.saturating_sub(1),
            }
        } else if let Some(reader) = reader {
            self.find_line_at_offset_sparse(offset, reader)
        } else {
            // Sparse index - estimate
            if self.avg_line_length > 0.0 {
                (offset as f64 / self.avg_line_length) as usize
            } else {
                offset / 80
            }
        }
    }

    fn find_line_at_offset_sparse(&self, offset: usize, reader: &FileReader) -> usize {
        if self.sparse_checkpoint_offsets.is_empty() {
            return if self.avg_line_length > 0.0 {
                (offset as f64 / self.avg_line_length) as usize
            } else {
                offset / 80
            };
        }

        let clamped_offset = offset.min(self.file_size);
        let checkpoint_index = self
            .sparse_checkpoint_offsets
            .partition_point(|&checkpoint_offset| checkpoint_offset <= clamped_offset)
            .saturating_sub(1);
        let checkpoint_offset = self.sparse_checkpoint_offsets[checkpoint_index];
        let checkpoint_line = self.sparse_checkpoint_lines[checkpoint_index];

        let chunk = reader.get_bytes(checkpoint_offset, clamped_offset);
        checkpoint_line + chunk.iter().filter(|&&byte| byte == b'\n').count()
    }

    pub fn total_lines(&self) -> usize {
        self.total_lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file_reader::detect_encoding;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_line_indexer_small_file() -> anyhow::Result<()> {
        let mut file = NamedTempFile::new()?;
        write!(file, "Line 1\nLine 2\nLine 3")?;
        let path = file.path().to_path_buf();

        let reader = FileReader::new(path, detect_encoding(b""))?;
        let mut indexer = LineIndexer::new();
        indexer.index_file(&reader);

        assert_eq!(indexer.total_lines, 3);
        assert_eq!(indexer.line_offsets, vec![0, 7, 14]);
        Ok(())
    }

    #[test]
    fn test_line_indexer_empty_lines() -> anyhow::Result<()> {
        let mut file = NamedTempFile::new()?;
        write!(file, "\n\n\n")?;
        let path = file.path().to_path_buf();

        let reader = FileReader::new(path, detect_encoding(b""))?;
        let mut indexer = LineIndexer::new();
        indexer.index_file(&reader);

        assert_eq!(indexer.total_lines, 4);
        assert_eq!(indexer.line_offsets, vec![0, 1, 2, 3]);
        Ok(())
    }

    #[test]
    fn test_sparse_index_exact_offset_lookup() -> anyhow::Result<()> {
        let mut file = NamedTempFile::new()?;
        let line = "0123456789abcdef\n";
        for _ in 0..700_000 {
            file.write_all(line.as_bytes())?;
        }
        let path = file.path().to_path_buf();

        let reader = FileReader::new(path, detect_encoding(b""))?;
        let mut indexer = LineIndexer::new();
        indexer.index_file(&reader);

        let target_line = 543_210usize;
        let target_offset = target_line * line.len();
        assert_eq!(
            indexer.find_line_at_offset(target_offset, Some(&reader)),
            target_line
        );

        let (start, end) = indexer
            .get_line_with_reader(target_line, &reader)
            .expect("line should resolve");
        assert_eq!(start, target_offset);
        assert_eq!(reader.get_chunk(start, end), "0123456789abcdef");
        Ok(())
    }

    #[test]
    fn test_index_file_cached_reuses_saved_index() -> anyhow::Result<()> {
        let mut file = NamedTempFile::new()?;
        write!(file, "alpha\nbeta\ngamma\ndelta\n")?;
        let path = file.path().to_path_buf();

        let reader = FileReader::new(path.clone(), detect_encoding(b""))?;
        let mut first = LineIndexer::new();
        let first_report = first.index_file_cached(&reader);
        assert_eq!(first_report.cache_status, IndexCacheStatus::MissStored);
        assert_eq!(first_report.mode, IndexMode::Full);

        let second_reader = FileReader::new(path, detect_encoding(b""))?;
        let mut second = LineIndexer::new();
        let second_report = second.index_file_cached(&second_reader);
        assert_eq!(second_report.cache_status, IndexCacheStatus::Hit);
        assert_eq!(second.total_lines(), first.total_lines());
        assert_eq!(second.get_line_range(2), first.get_line_range(2));
        Ok(())
    }
}
