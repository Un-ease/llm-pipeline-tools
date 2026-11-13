# Verification and measured output sizes

This records the original five-tool offline release. Current typed recon workflow verification and its additional tests are documented in `RECON.md`; the delivery checksum manifest now covers all 12 executables.

## Verification

- Rust: `rustc 1.100.0 (0ef1bc386 2026-11-09)`; Cargo 1.100.0.
- `cargo test --locked --quiet`: **39 black-box tests passed**, zero failures. Evidence: 11; GraphQL: 4; HTTP/Aura: 8; logs: 8; URLs: 8.
- `cargo build --locked --release --bins --quiet`: succeeded.
- Five packaged executables identified by `file` as stripped Linux x86-64 ELF PIE binaries, dynamically linked to the system C runtime. No Rust/Python/AI runtime is required to run them; they are not fully static binaries.
- All five `--help` surfaces launched successfully. Twelve real-input scenarios completed across the tools (including bounded and all-row Wolt reports); JSON version, row widths, and `total = shown + omitted` were checked.
- The first smoke harness assumed Aura's report identifier matched the executable name. Actual Aura reports use `tool: "bbp-http-aura"`; the harness expectation was corrected and remaining scenarios completed. No binary change was needed.
- No live target requests, evidence edits, or destructive actions were performed. No lint/formatter suite was run.

## Method

Release executables ran from `~/Documents/H_Programs/BBP`, using relative input paths. Input bytes are actual saved-file sizes; output bytes include the complete compact JSON stdout and its trailing newline. Timings are single local runs, not statistical performance benchmarks. No temporary verification script was retained.

These are **lossy, task-specific projections**, not lossless compression or equivalent full-data reports. Default output limits to 20 rows; omitted counts remain visible. A saved schema lookup deliberately returns one type/member rather than thousands of unrelated types. No DeepSeek tokenizer, energy meter, or end-to-end productivity benchmark was used. Do not label these percentages token or environmental savings.

|Scenario|Input bytes|Output bytes|Byte reduction|Rows shown / total|Elapsed ms|
|---|---:|---:|---:|---:|---:|
|Wolt, seven Burp JSONL exports, default|2,153,309|6,382|99.70%|20 / 130|15.34|
|Wolt, same exports, `--all` groups|2,153,309|40,249|98.13%|130 / 130|12.37|
|Mercedes HTTPX JSONL|10,580|3,125|70.46%|18 / 18|0.71|
|Mercedes saved probe array|26,500|4,839|81.74%|20 / 20|0.73|
|FanDuel validation map|604|962|**-59.27%**|3 / 3|0.61|
|FanDuel request-only Aura capture|15,470|859|94.45%|1 / 1|0.82|
|Mercedes GraphQL `Query` fields|8,175,375|6,512|99.92%|20 / 172|82.45|
|Mercedes GraphQL `Query.users` lookup|8,175,375|892|99.99%|1 / 1|77.94|
|FanDuel JS literal URL inventory|5,905,026|633|99.99%|4 / 4|9.67|
|Cisco subdomain inventory|8,847,118|2,203|99.98%|20 / 282,450|277.38|
|Mercedes edge log, `--width 0`|3,807|4,100|**-7.70%**|20 / 29|0.98|

### Important counterexamples

The already-compact three-entry FanDuel map grows because the report adds grouping, provenance and accounting. The selected edge log has 29 unique lines and no repeats; hashes/references make its report larger even with snippets suppressed. Do not run these tools indiscriminately on small/already-projected data. Use `jq -c` or a targeted `rg` projection when that is smaller and sufficient.

### Semantics observed

- Wolt: all **801** saved records accepted; **130** response/endpoint groups; no unsupported records. `--all` confirms reduction is not solely the default row cap. Raw bodies/query values are still intentionally omitted.
- Aura: one **request** action, zero response actions. Null response state is not success. Parameter structure remained available without serialized Flow-state values.
- HTTPX: all 18 rows explicitly metadata-only. Matching sizes are not treated as matching bodies.
- GraphQL: 4,429 saved types; 172 `Query` members. The selected `users` field retained list/non-null wrappers and argument metadata.
- JS URLs: 21 literal candidates; 13 accepted occurrences, eight rejected, four distinct signatures. This is not complete dynamic-route discovery.
- Cisco: 282,453 source lines; 282,451 candidates, one rejected, two ignored lines; 282,450 distinct accepted signatures. Default output deliberately omits 282,430 rows.

## Evidence inventory

`bbp-evidence Fanduel Mercedes Hilton` completed in **75.65 ms**, emitting **7,429 bytes**. It inventoried **2,095 files / 114,217,724 bytes**, hashed **1,472 same-size candidates / 38,771,941 bytes**, and found **117 duplicate groups** covering 589 files. Full aggregate duplicate accounting remained available despite showing only 20 groups.

Reported additional-copy bytes: **17,961,479**. This is an inventory metric, **not a recommendation to delete evidence**: identical observations may have distinct provenance. Five excluded directories were counted; no oversized files, symlinks or read errors occurred in these selected trees. The 16 MiB default still skips oversized files in other projects, notably Cisco's 318 MB wordlists.

## Reproducing representative measurements

With this project's absolute path in `TOOLS`, run from the BBP root:

```sh
TOOLS="$HOME/Documents/Projects/llm-pipeline-tools/dist"
"$TOOLS/bbp-http" --all wolt/burp/*.jsonl | wc -c
"$TOOLS/bbp-http" --aura Fanduel/tmp/nav.json | wc -c
"$TOOLS/bbp-gql" --type Query --field users \
  Mercedes/agents/gitlab/evidence/gql_queryfields.json | wc -c
"$TOOLS/bbp-urls" Cisco/sub.txt | wc -c
```

Use `set -o pipefail` with bash to preserve producer failures. Source changes, working-directory/path lengths, different captures and different row limits change the measurements. `dist/SHA256SUMS` identifies the delivered builds.
