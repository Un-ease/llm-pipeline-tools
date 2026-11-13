use llm_pipeline_tools::{Options, Result, main_result, report};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, Metadata};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

const DEFAULT_MAX_FILE_BYTES: usize = 16 * 1024 * 1024;

struct Entry {
    path: PathBuf,
    name: String,
    bytes: u64,
}

#[derive(Default)]
struct Extension {
    files: u64,
    bytes: u64,
}

#[derive(Default)]
struct Inventory {
    sizes: BTreeMap<u64, Vec<Entry>>,
    extensions: BTreeMap<String, Extension>,
    total_files: u64,
    input_bytes: u64,
    oversized_files: u64,
    oversized_bytes: u64,
    excluded_dirs: u64,
    symlinks: u64,
    other_entries: u64,
}

fn add(total: &mut u64, amount: u64) -> Result<()> {
    *total = total.checked_add(amount).ok_or("inventory counter overflow")?;
    Ok(())
}

fn excluded(path: &Path) -> bool {
    matches!(path.file_name().and_then(|s| s.to_str()), Some(".git" | "node_modules" | "target" | "__pycache__"))
}

fn metadata(path: &Path) -> Result<Metadata> {
    fs::symlink_metadata(path).map_err(|e| format!("{}: {e}", path.display()))
}

// Inspect ancestors before resolving '..': even an explicitly supplied root must
// not traverse a symlink, or enter a normally excluded directory.
fn prepare_root(input: &str, cwd: &Path) -> Result<PathBuf> {
    if input == "-" {
        return Err("bbp-evidence accepts filesystem roots, not stdin".into());
    }
    let absolute = cwd.join(input);
    let mut path = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::ParentDir => { path.pop(); }
            Component::CurDir => {}
            _ => path.push(component.as_os_str()),
        }
        let meta = metadata(&path)?;
        if meta.file_type().is_symlink() || (meta.is_dir() && excluded(&path)) {
            return Ok(path);
        }
    }
    Ok(path)
}

fn text(path: &Path) -> Result<String> {
    path.to_str().map(str::to_owned)
        .ok_or_else(|| format!("non-UTF-8 path cannot be represented without loss: {}", path.display()))
}

fn relative(path: &Path, base: &Path) -> Result<String> {
    let left: Vec<_> = base.components().collect();
    let right: Vec<_> = path.components().collect();
    let common = left.iter().zip(&right).take_while(|(a, b)| a == b).count();
    let mut result = PathBuf::new();
    for _ in common..left.len() { result.push(".."); }
    for component in &right[common..] { result.push(component.as_os_str()); }
    if result.as_os_str().is_empty() { Ok(".".into()) } else { text(&result) }
}

fn inventory(roots: &[PathBuf], base: &Path, maximum: u64) -> Result<Inventory> {
    let mut result = Inventory::default();
    let mut pending: Vec<PathBuf> = roots.to_vec();
    while let Some(path) = pending.pop() {
        let meta = metadata(&path)?;
        if meta.file_type().is_symlink() {
            add(&mut result.symlinks, 1)?;
        } else if meta.is_dir() {
            if excluded(&path) {
                add(&mut result.excluded_dirs, 1)?;
                continue;
            }
            let entries = fs::read_dir(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            for entry in entries {
                let entry = entry.map_err(|e| format!("{}: {e}", path.display()))?;
                pending.push(entry.path());
            }
        } else if meta.is_file() {
            let name = relative(&path, base)?;
            // Check readability even when no hash is needed. Permission failures
            // must not turn into a successful, apparently complete inventory.
            File::open(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            let extension = match path.extension() {
                Some(value) => value.to_str().ok_or_else(|| format!("non-UTF-8 extension: {name}"))?.to_lowercase(),
                None => String::new(),
            };
            let bytes = meta.len();
            let ext = result.extensions.entry(extension).or_default();
            add(&mut ext.files, 1)?;
            add(&mut ext.bytes, bytes)?;
            add(&mut result.total_files, 1)?;
            add(&mut result.input_bytes, bytes)?;
            if bytes > maximum {
                add(&mut result.oversized_files, 1)?;
                add(&mut result.oversized_bytes, bytes)?;
            } else {
                result.sizes.entry(bytes).or_default().push(Entry { path, name, bytes });
            }
        } else {
            add(&mut result.other_entries, 1)?;
        }
    }
    Ok(result)
}

fn hash(entry: &Entry) -> Result<(String, u64)> {
    let before = metadata(&entry.path)?;
    if !before.is_file() || before.len() != entry.bytes {
        return Err(format!("{}: file changed during inventory", entry.path.display()));
    }
    let mut file = File::open(&entry.path).map_err(|e| format!("{}: {e}", entry.path.display()))?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 65536];
    let mut bytes = 0u64;
    loop {
        let n = file.read(&mut buffer).map_err(|e| format!("{}: {e}", entry.path.display()))?;
        if n == 0 { break; }
        add(&mut bytes, n as u64)?;
        if bytes > entry.bytes {
            return Err(format!("{}: file grew during hashing", entry.path.display()));
        }
        digest.update(&buffer[..n]);
    }
    let after = file.metadata().map_err(|e| format!("{}: {e}", entry.path.display()))?;
    if bytes != entry.bytes || after.len() != entry.bytes || before.modified().ok() != after.modified().ok() {
        return Err(format!("{}: file changed during hashing", entry.path.display()));
    }
    Ok((format!("{:x}", digest.finalize()), bytes))
}

fn run() -> Result<()> {
    let options = Options::parse(&["--all"], &["--max-file-bytes", "--limit"])?;
    if options.help() {
        println!("bbp-evidence [--max-file-bytes N] [--limit N|--all] ROOT...\nOffline, read-only inventory; no stdin or symlink traversal. Default hash maximum: 16777216 bytes.\nRows: SHA-256 duplicate groups, sorted by first relative path; duplicate_paths contains every extra copy in each shown group.\nStats always cover all files. Extension names are lowercase (empty means no extension). Oversized files are unclassified, never unique.\nExcluded directories: .git, node_modules, target, __pycache__. Paths are relative to stats.base (itself relative to the working directory).\nUnique-size files are not hashed. Duplicate content bytes include all copies; reclaimable bytes include only extra copies.\nRead/permission errors abort with exit 2. Use a quiescent evidence tree; this is not a filesystem snapshot.");
        return Ok(());
    }
    options.require_inputs()?;
    let maximum = options.number("--max-file-bytes", DEFAULT_MAX_FILE_BYTES)? as u64;
    let limit = options.limit()?;
    let cwd = std::env::current_dir().map_err(|e| format!("working directory: {e}"))?;
    let mut candidates = options.inputs.iter().map(|s| prepare_root(s, &cwd)).collect::<Result<Vec<_>>>()?;
    candidates.sort();
    let mut roots: Vec<PathBuf> = Vec::new();
    let mut overlapping_roots_skipped = 0u64;
    for path in candidates {
        if roots.iter().any(|root| path.starts_with(root)) {
            add(&mut overlapping_roots_skipped, 1)?;
        } else {
            roots.push(path);
        }
    }
    let mut base = roots[0].clone();
    if !metadata(&base)?.is_dir() { base.pop(); }
    for root in &roots {
        while !root.starts_with(&base) {
            if !base.pop() { return Err("cannot find common root directory".into()); }
        }
    }
    let inv = inventory(&roots, &base, maximum)?;
    let mut rows: Vec<(String, u64, Vec<String>)> = Vec::new();
    let mut hashed_files = 0u64;
    let mut hashed_bytes = 0u64;
    let mut unique_files = 0u64;
    let mut duplicate_files = 0u64;
    let mut duplicate_copies = 0u64;
    let mut duplicate_content_bytes = 0u64;
    let mut reclaimable_duplicate_bytes = 0u64;
    for (size, mut entries) in inv.sizes {
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        if entries.len() == 1 {
            add(&mut unique_files, 1)?;
            continue;
        }
        let mut hashes: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for entry in entries {
            let (digest, bytes) = hash(&entry)?;
            add(&mut hashed_files, 1)?;
            add(&mut hashed_bytes, bytes)?;
            hashes.entry(digest).or_default().push(entry.name);
        }
        for (digest, names) in hashes {
            let count = names.len() as u64;
            if count == 1 {
                add(&mut unique_files, 1)?;
                continue;
            }
            add(&mut duplicate_files, count)?;
            add(&mut duplicate_copies, count - 1)?;
            add(&mut duplicate_content_bytes, size.checked_mul(count).ok_or("duplicate byte count overflow")?)?;
            add(&mut reclaimable_duplicate_bytes, size.checked_mul(count - 1).ok_or("duplicate byte count overflow")?)?;
            rows.push((digest, size, names));
        }
    }
    rows.sort_by(|a, b| a.2[0].cmp(&b.2[0]));
    let extensions: Vec<Value> = inv.extensions.into_iter().map(|(extension, value)| {
        json!({"extension":extension,"files":value.files,"bytes":value.bytes})
    }).collect();
    let root_names = roots.iter().map(|root| relative(root, &base)).collect::<Result<Vec<_>>>()?;
    let stats = json!({
        "base": relative(&base, &cwd)?, "roots": root_names,
        "total_files": inv.total_files, "input_bytes": inv.input_bytes,
        "max_file_bytes": maximum, "hashed_files": hashed_files, "hashed_bytes": hashed_bytes,
        "unhashed_files": inv.total_files - hashed_files,
        "unique_files": unique_files, "unclassified_files": inv.oversized_files,
        "oversized_files": inv.oversized_files, "oversized_bytes": inv.oversized_bytes,
        "excluded_dirs": inv.excluded_dirs, "symlinks": inv.symlinks,
        "other_entries": inv.other_entries,
        "skipped_entries": inv.excluded_dirs + inv.symlinks + inv.other_entries,
        "overlapping_roots_skipped": overlapping_roots_skipped,
        "duplicate_groups": rows.len(), "duplicate_files": duplicate_files,
        "duplicate_copies": duplicate_copies, "duplicate_content_bytes": duplicate_content_bytes,
        "reclaimable_duplicate_bytes": reclaimable_duplicate_bytes,
        "extensions": extensions, "errors": 0
    });
    let rows = rows.into_iter().map(|(digest, size, names)| {
        json!([digest, size, names.len(), names[0], names[1..]])
    });
    report("bbp-evidence", &["sha256", "bytes", "count", "first_path", "duplicate_paths"], rows, limit, stats)
}

fn main() { main_result(run); }
