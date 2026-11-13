use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Temp(PathBuf);

impl Temp {
    fn new() -> Self {
        loop {
            let path = std::env::temp_dir().join(format!("llm-pipeline-tools-evidence-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create fixture: {error}"),
            }
        }
    }

    fn put(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, bytes).unwrap();
        path
    }
}

impl Drop for Temp {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}

fn execute(args: &[&str], roots: &[&Path]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bbp-evidence")).args(args).args(roots).output().unwrap()
}

fn success(args: &[&str], roots: &[&Path]) -> Value {
    let output = execute(args, roots);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert!(output.stderr.is_empty());
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn exact_duplicates_are_separate_from_same_size_and_unique_size_files() {
    let temp = Temp::new();
    temp.put("a.txt", b"abc");
    temp.put("z.txt", b"abc");
    temp.put("b.txt", b"abd");
    temp.put("empty", b"");
    temp.put("long.MD", b"four");
    let result = success(&[], &[&temp.0]);
    assert_eq!(result["cols"], serde_json::json!(["sha256", "bytes", "count", "first_path", "duplicate_paths"]));
    assert_eq!(result["total"], 1);
    assert_eq!(result["rows"][0], serde_json::json!([
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", 3, 2, "a.txt", ["z.txt"]
    ]));
    let stats = &result["stats"];
    assert_eq!(stats["total_files"], 5);
    assert_eq!(stats["input_bytes"], 13);
    assert_eq!(stats["hashed_files"], 3);
    assert_eq!(stats["hashed_bytes"], 9);
    assert_eq!(stats["unique_files"], 3);
    assert_eq!(stats["duplicate_files"], 2);
    assert_eq!(stats["duplicate_copies"], 1);
    assert_eq!(stats["duplicate_content_bytes"], 6);
    assert_eq!(stats["reclaimable_duplicate_bytes"], 3);
    assert_eq!(stats["extensions"], serde_json::json!([
        {"extension":"","files":1,"bytes":0},
        {"extension":"md","files":1,"bytes":4},
        {"extension":"txt","files":3,"bytes":9}
    ]));
}

#[test]
fn hashing_compares_full_files_not_just_a_prefix() {
    let temp = Temp::new();
    let mut bytes = vec![b'x'; 65537];
    temp.put("a.bin", &bytes);
    temp.put("copy.bin", &bytes);
    bytes[65536] = b'y';
    temp.put("different.bin", &bytes);
    let result = success(&[], &[&temp.0]);
    assert_eq!(result["total"], 1);
    assert_eq!(result["rows"][0][2], 2);
    assert_eq!(result["rows"][0][4], serde_json::json!(["copy.bin"]));
    assert_eq!(result["stats"]["hashed_bytes"], 65537 * 3);
    assert_eq!(result["stats"]["unique_files"], 1);
}

#[test]
fn oversized_files_are_inventoried_but_never_classified() {
    let temp = Temp::new();
    temp.put("a.burp", b"four");
    temp.put("b.burp", b"four");
    temp.put("c.txt", b"abc");
    temp.put("d.txt", b"abc");
    temp.put("wordlist", b"large");
    let result = success(&["--max-file-bytes", "3"], &[&temp.0]);
    let stats = &result["stats"];
    assert_eq!(stats["total_files"], 5);
    assert_eq!(stats["input_bytes"], 19);
    assert_eq!(stats["oversized_files"], 3);
    assert_eq!(stats["oversized_bytes"], 13);
    assert_eq!(stats["unclassified_files"], 3);
    assert_eq!(stats["unique_files"], 0);
    assert_eq!(stats["hashed_files"], 2);
    assert_eq!(result["total"], 1);
    assert_eq!(result["rows"][0][3], "c.txt");
}

#[test]
fn default_hash_limit_is_sixteen_mebibytes_and_zero_limit_hashes_empty_files() {
    let temp = Temp::new();
    for name in ["large.burp", "copy.burp"] {
        fs::File::create(temp.0.join(name)).unwrap().set_len(16 * 1024 * 1024 + 1).unwrap();
    }
    temp.put("a", b"");
    temp.put("b", b"");
    let result = success(&[], &[&temp.0]);
    assert_eq!(result["stats"]["oversized_files"], 2);
    assert_eq!(result["stats"]["oversized_bytes"], 2 * (16 * 1024 * 1024 + 1));
    assert_eq!(result["stats"]["hashed_files"], 2);
    assert_eq!(result["stats"]["hashed_bytes"], 0);
    let zero = success(&["--max-file-bytes", "0"], &[&temp.0]);
    assert_eq!(zero["rows"][0][2], 2);
    assert_eq!(zero["stats"]["unique_files"], 0);
}

#[test]
fn excluded_directories_are_counted_without_traversing_them() {
    let temp = Temp::new();
    for directory in [".git", "node_modules", "target", "__pycache__"] {
        temp.put(&format!("{directory}/nested/hidden.txt"), b"hidden");
    }
    temp.put("visible.txt", b"visible");
    let result = success(&[], &[&temp.0]);
    assert_eq!(result["stats"]["total_files"], 1);
    assert_eq!(result["stats"]["excluded_dirs"], 4);
    assert_eq!(result["stats"]["skipped_entries"], 4);
    let excluded_root = temp.0.join(".git/nested");
    let excluded = success(&[], &[&excluded_root]);
    assert_eq!(excluded["stats"]["total_files"], 0);
    assert_eq!(excluded["stats"]["excluded_dirs"], 1);
}

#[test]
fn overlapping_roots_and_repeated_file_roots_are_not_double_counted() {
    let temp = Temp::new();
    let a = temp.put("nested/a.txt", b"abc");
    temp.put("nested/b.txt", b"abc");
    let nested = temp.0.join("nested");
    let result = success(&[], &[&a, &nested, &temp.0, &a, &temp.0]);
    assert_eq!(result["stats"]["total_files"], 2);
    assert_eq!(result["stats"]["input_bytes"], 6);
    assert_eq!(result["stats"]["overlapping_roots_skipped"], 4);
    assert_eq!(result["rows"][0][3], "nested/a.txt");
    assert_eq!(result["rows"][0][4], serde_json::json!(["nested/b.txt"]));
    let file = success(&[], &[&a, &a]);
    assert_eq!(file["stats"]["total_files"], 1);
    assert_eq!(file["stats"]["hashed_files"], 0);
    assert_eq!(file["stats"]["unique_files"], 1);
}

#[test]
fn duplicate_statistics_and_all_names_survive_report_limits() {
    let temp = Temp::new();
    for name in ["a.txt", "b.txt", "c.txt"] { temp.put(name, b"abc"); }
    for name in ["d.bin", "e.bin"] { temp.put(name, b"four"); }
    let all = success(&["--all"], &[&temp.0]);
    let limited = success(&["--limit", "1"], &[&temp.0]);
    let zero = success(&["--limit", "0"], &[&temp.0]);
    assert_eq!(all["stats"], limited["stats"]);
    assert_eq!(all["stats"], zero["stats"]);
    assert_eq!(all["total"], 2);
    assert_eq!(limited["total"], 2);
    assert_eq!(limited["omitted"], 1);
    assert_eq!(zero["omitted"], 2);
    assert_eq!(limited["rows"][0][4], serde_json::json!(["b.txt", "c.txt"]));
    assert_eq!(all["stats"]["duplicate_content_bytes"], 17);
    assert_eq!(all["stats"]["reclaimable_duplicate_bytes"], 10);
    assert_eq!(zero["rows"], serde_json::json!([]));
    let override_limit = success(&["--limit", "0", "--all"], &[&temp.0]);
    assert_eq!(override_limit["rows"], all["rows"]);
}

#[test]
fn disjoint_roots_use_stable_relative_paths_and_escape_names() {
    let temp = Temp::new();
    let a = temp.put("left/quote\"\n.txt", b"same");
    let b = temp.put("right/back\\slash.txt", b"same");
    let first = success(&[], &[&a, &b]);
    let reverse = success(&[], &[&b, &a]);
    assert_eq!(first, reverse);
    assert_eq!(first["rows"][0][3], "left/quote\"\n.txt");
    assert_eq!(first["rows"][0][4], serde_json::json!(["right/back\\slash.txt"]));
}

#[cfg(unix)]
#[test]
fn symlinks_including_root_ancestors_are_not_followed() {
    use std::os::unix::fs::symlink;
    let temp = Temp::new();
    let outside = Temp::new();
    let file = temp.put("visible.txt", b"abc");
    outside.put("hidden.txt", b"abc");
    symlink(&file, temp.0.join("file-link")).unwrap();
    symlink(&outside.0, temp.0.join("dir-link")).unwrap();
    symlink(temp.0.join("missing"), temp.0.join("dangling-link")).unwrap();
    let result = success(&[], &[&temp.0]);
    assert_eq!(result["stats"]["total_files"], 1);
    assert_eq!(result["stats"]["symlinks"], 3);
    assert_eq!(result["stats"]["skipped_entries"], 3);
    let root = temp.0.join("dir-link/hidden.txt");
    let linked_root = success(&[], &[&root]);
    assert_eq!(linked_root["stats"]["total_files"], 0);
    assert_eq!(linked_root["stats"]["symlinks"], 1);
}

#[test]
fn missing_inputs_invalid_limits_and_stdin_fail_without_partial_reports() {
    let temp = Temp::new();
    let missing = temp.0.join("missing");
    for output in [
        execute(&[], &[&missing]),
        execute(&["-"], &[]),
        execute(&["--max-file-bytes", "no"], &[&temp.0]),
        execute(&["--limit", "-1"], &[&temp.0]),
        execute(&[], &[]),
    ] {
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
    }
}

#[cfg(unix)]
#[test]
fn unreadable_files_fail_even_when_no_hash_would_be_required() {
    use std::os::unix::fs::PermissionsExt;
    let temp = Temp::new();
    let file = temp.put("unreadable", b"unique-size");
    fs::set_permissions(&file, fs::Permissions::from_mode(0)).unwrap();
    // A privileged test runner may legitimately bypass Unix mode bits.
    if fs::File::open(&file).is_err() {
        let output = execute(&[], &[&temp.0]);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("unreadable"));
    }
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
}
