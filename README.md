# LLM pipeline tools

Rust tools for typed, audited recon workflows and compact offline evidence reduction. No AI API is required. Sources and release binaries live here, separately from BBP projects. Offline commands never contact targets; recon workflows perform explicitly requested network work and record their observations.

## Offline reduction tools

|Binary|Purpose|Avoided manual work|
|---|---|---|
|`bbp-http`|Index saved Burp/HTTPX/probe captures, fingerprint bodies, optionally group metadata-only captures without claiming equal bodies; `--aura` indexes Salesforce action shapes.|Repeated capture parsing and unsafe prefix/status deduplication.|
|`bbp-gql`|Look up saved GraphQL introspection types, members, wrapped return types and argument requirements.|Repeated multi-megabyte schema reads and guessed field selections.|
|`bbp-urls`|Extract literal HTTP(S) URLs; filter an exact host or DNS suffix with `--site`; compare saved inventories with `--since`.|Manual URL/query deduplication, suffix-filter snippets and observation-set comparisons.|
|`bbp-routes`|Normalize route families with origin, query names, provenance, bounded variants and explicit template/static/noise classes.|Manual locale/identifier reduction and hidden account-route clusters.|
|`bbp-evidence`|Inventory evidence trees; report exact-content duplicate groups, aggregate sizes and explicit skips.|Repeated listings/hash one-liners and re-reading identical bundles.|
|`tok-log`|Count exact repeated log lines; optional timestamp stripping; bounded Unicode snippets with full-line hashes.|Repeated raw log/envelope presentation and manual occurrence counts.|

## Typed recon workflows

`recon_subdomains`, `recon_resolve`, `recon_discover`, `recon_urls`, and `recon_ports` wrap workflows with typed JSON inputs, not backend switches. **Version 0.2 uses the breaking v2 result contract:** bounded `rows`, `total`, `omitted`, `completeness`, coverage and a journal receipt; old bare-array consumers must migrate. `recon_mcp` exposes five workflows plus two evidence tools. Interrupted usable backend output exits **3**, retains a failure receipt, and is never labelled complete.

Facts go to the root-owned system journal; model verdicts are appended separately. This protects existing records against ordinary user edits, not root, journal retention, or forged new entries. See [RECON.md](RECON.md) for exact guarantees, input schemas, limits and integration.


## Output contract

Every offline reduction report is one compact JSON object:

```json
{"v":1,"tool":"...","cols":["column", "names"],"rows":[["values", "once"]],"total":1,"omitted":0,"stats":{}}
```

Column names occur once instead of on every row. Default row limit: **20**. `--limit N` selects a different limit; `--all` emits all rows. Complete counts remain in `total`/`stats`, with excluded rows counted in `omitted`. This bounds row counts, not the byte size of every possible row. A schema field may have many arguments; an evidence group may have many filenames.

Aura mode identifies its report as `tool: "bbp-http-aura"`; other report identifiers match their executable names.

`--help` describes each command. Errors exit **2**, emit diagnostics to stderr and do not emit a success report. Files named `-` mean stdin except for `bbp-evidence`; use `--` before paths beginning with `-`. Unsupported or malformed input is not silently converted into a finding.

HTTP/URL summaries omit query values, URL userinfo, cookies, authorization headers and raw bodies. **This is data minimization, not a universal secret scrubber:** paths, parameter names, schema names, filenames and log snippets can still contain sensitive information. `tok-log --width 0` suppresses snippets, leaving fingerprints, counts and references.

## Examples

Run from this directory; no target requests occur:

```sh
BBP="$HOME/Documents/H_Programs/BBP"
./dist/bbp-http "$BBP/wolt/burp/"*.jsonl
./dist/bbp-http "$BBP/Mercedes/assets/httpx.json"
./dist/bbp-http --aura "$BBP/Fanduel/tmp/nav.json"
./dist/bbp-gql --type Query "$BBP/Mercedes/agents/gitlab/evidence/gql_queryfields.json"
./dist/bbp-gql --type Query --field users "$BBP/Mercedes/agents/gitlab/evidence/gql_queryfields.json"
./dist/bbp-urls --host help.fanduel.com "$BBP/Fanduel/tmp/app.js"
./dist/bbp-urls --site example.test captured-content.txt
./dist/bbp-urls --site example.test --since previous-complete.json captured-content.txt
./dist/bbp-routes --site example.test candidates.json
./dist/bbp-urls "$BBP/Cisco/sub.txt"
./dist/bbp-evidence "$BBP/Fanduel" "$BBP/Mercedes"
./dist/tok-log --strip-time --width 160 server.log
./dist/tok-log --width 0 "$BBP/Mercedes/agents/edge/evidence/path_matrix.txt"
```

For stdin, pipe a saved file into a command with `-`. In automation, preserve the producer's exit status (`set -o pipefail` in bash); a log compactor cannot recover an upstream command's exit status.

## Correctness boundaries

- **HTTP:** actual body fingerprints, not equal length/status or a 400-character prefix. Metadata-only observations are not proof of equal bodies. Record references identify parsed records, not necessarily physical lines. Aura request captures do not establish execution success.
- **GraphQL:** exact saved-type/member lookup, not full query validation, auth testing or live schema discovery. Missing saved fields can reflect incomplete/stale introspection. Selected arguments/input fields require saved `defaultValue` metadata (string or null); missing/invalid metadata fails instead of guessing requiredness or defaults. Default values, descriptions and response data are not emitted.
- **URLs:** literal extraction, not JavaScript execution. Query values are discarded, repeated names retained. Exact paths retain spelling. `--host` is an exact filter; `--site` is a DNS-label suffix filter, **not** public-suffix/eTLD inference or authorization. `--since` compares complete saved observation sets, not live/dead status, and rejects limited or delta baselines.
- **Routes:** normalized families are hypotheses, not live endpoints. Origin and real leaf operations remain distinct; variants/provenance are bounded with explicit omission counts. Source-supplied live tags are not independently verified.
- **Metadata grouping:** `bbp-http --group-metadata` is opt-in; equal status/length/MIME is not equal content. Metadata groups expose `equal_bodies:false`; insufficient body evidence is never promoted to complete-body equality.
- **Evidence:** SHA-256 of complete eligible files, never prefixes. Default hash-size cap: **16 MiB** (`--max-file-bytes N`). Larger files are inventoried but skipped for hashing, not asserted unique. Symlinks are not followed. `.git`, `node_modules`, `target`, and `__pycache__` directories are excluded and counted. No evidence is deleted. Run against a stable snapshot: concurrent file changes can invalidate an inventory.
- **Logs:** exact lines by default; `--strip-time` is explicit lossy normalization and leaves impossible calendar dates intact. Different identifiers/numbers are not merged. Stack lines remain individual lines; no root-cause, severity or server-health conclusion is inferred. Snippet truncation is counted and full-line SHA-256 retained.
- Input streaming does not imply constant memory: exact URL/log/HTTP grouping retains distinct keys. For multi-million-entry wordlists use external sorting (`sort -u`, `comm`) rather than assuming an in-memory index fits.

## Build and test

Requires a Rust 2024-capable toolchain and a C linker to build; compiled executables do not require Rust. Cargo downloads dependencies on the first build. `Cargo.lock` pins the verified resolution.

```sh
cargo test --locked
cargo build --release --locked --bins
mkdir -p dist
cp target/release/bbp-http target/release/bbp-gql target/release/bbp-urls \
   target/release/bbp-routes target/release/bbp-evidence target/release/tok-log dist/
cp target/release/recon_subdomains target/release/recon_resolve \
   target/release/recon_discover target/release/recon_urls target/release/recon_ports \
   target/release/recon_mcp target/release/evidence_read target/release/evidence_verdict dist/
```

Release builds use thin LTO and stripped symbols. The delivered Linux x86-64 executables use the system C runtime; they are standalone executables, not promised fully static or cross-platform builds. They are not installed into PATH. The default omp profile registers `recon_mcp` as server `recon`; the existing Reflex configuration is preserved. Run `/mcp reload` or start a new omp session to load it.

Without a host toolchain, `Dockerfile.build` pins a Rust 1.91 Debian builder with `libsystemd-dev`:

```sh
docker build -f Dockerfile.build -t llm-pipeline-tools-build:rust1.91 .
docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$PWD:/work" llm-pipeline-tools-build:rust1.91 cargo test --locked
docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$PWD:/work" llm-pipeline-tools-build:rust1.91 cargo build --release --locked --bins
```

Audited workflows require Linux systemd-journald, `libsystemd`, `journalctl`, and their fixed backends. DNS resolution and hostname HTTP/TCP workflows use `dnsx`; passive sources use `subfinder`/`gau`. `RECON_SCOPE` selects an operator-owned absolute policy file; `RECON_REQUIRED_HEADER`/`RECON_REQUIRED_HEADERS` enforce research attribution before HTTP network work. Missing backends, invalid policy and audit failure fail visibly. See [RECON.md](RECON.md) for enforcement, projections and checkpoint resumption.

See `AUDIT.md` for observed historical waste, nine-project coverage and work that must not be removed. See `BENCHMARKS.md` for measured output bytes and verification results; byte reduction is not a model-token or energy measurement.
