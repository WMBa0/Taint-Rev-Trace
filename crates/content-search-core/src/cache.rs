use std::env;
use std::fs::Metadata;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

const APP_CACHE_DIR_NAME: &str = "content-search";

pub fn cache_root_dir() -> PathBuf {
    if let Some(override_dir) = env::var_os("CONTENT_SEARCH_CACHE_DIR") {
        return PathBuf::from(override_dir);
    }

    #[cfg(test)]
    {
        return env::temp_dir().join(APP_CACHE_DIR_NAME);
    }

    #[cfg(not(test))]
    {
        if let Some(local_app_data) = env::var_os("LOCALAPPDATA") {
            return PathBuf::from(local_app_data).join(APP_CACHE_DIR_NAME);
        }
        if let Some(xdg_cache_home) = env::var_os("XDG_CACHE_HOME") {
            return PathBuf::from(xdg_cache_home).join(APP_CACHE_DIR_NAME);
        }
        if let Some(home) = env::var_os("HOME") {
            return PathBuf::from(home).join(".cache").join(APP_CACHE_DIR_NAME);
        }
        env::temp_dir().join(APP_CACHE_DIR_NAME)
    }
}

pub fn cache_file_for_path(namespace: &str, path: &Path, metadata: &Metadata) -> PathBuf {
    let modified = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .unwrap_or_default();
    let path_hash = fnv1a_64(path.to_string_lossy().as_bytes());
    let file_name = format!(
        "{path_hash:016x}-{}-{}-{}.bin",
        metadata.len(),
        modified.as_secs(),
        modified.subsec_nanos()
    );

    cache_root_dir().join(namespace).join(file_name)
}

fn fnv1a_64(bytes: &[u8]) -> u64 {
    const OFFSET_BASIS: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x100000001b3;

    let mut hash = OFFSET_BASIS;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}
