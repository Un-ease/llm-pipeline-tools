# Typed recon workflows

Version **0.3** wraps goals, not scanner switches. Requests are typed JSON; unknown fields, malformed domains/URLs, non-integer ports and oversized workloads are rejected. `--schema` describes each input. Examples are request shapes, not authorization; replace example run IDs with actual receipts.

## Workflow surface

| Tool | Typed input | Observation |
|---|---|---|
| `recon_subdomains` | `{"domain":"example.test"}` | Deduplicated passive names, fixed subfinder invocation and source captures. |
| `recon_resolve` | `{"hosts":["api.example.test"],"domain":"example.test"}` or `{"source_run":"32-lowercase-hex-id"}` | Compact host/address/CNAME/status/disposition rows; one explicit outcome per unique host, with verified source metadata when chained. |
| `recon_discover` | `{"hosts":["api.example.test"],"ports":[443],"paths":["/"]}` | Actual HTTP responses, compact titles/server metadata and honest coverage. |
| `recon_urls` | `{"domain":"example.test","mode":"archive"}` | Historical URLs; `crawl`/`combined` require explicit seeds. |
| `recon_surface` | `{"run":"32-lowercase-hex-id","prefix":"/account/settings"}` | Offline origin/path groups or detailed route families from verified saved URL evidence, with bounded examples and historical capture references. |
| `recon_ports` | `{"hosts":["api.example.test"],"ports":[443]}` | Actual open TCP endpoints; refusals and operational failures remain distinct. |
| `evidence_read` | `{"run":"32-lowercase-hex-id","select":{"kind":["http_response"],"status":[404]},"offset":0,"limit":20}` | Full-chain verification followed by compact filtered pagination. |
| `evidence_verdict` | `{"run":"32-lowercase-hex-id","verdict":"hypothesis","evidence":[1],"note":"Model interpretation"}` | Separately labelled model opinion, never replacement facts. |

No request accepts shell commands, backend executable paths, arbitrary flags, cookies, credentials or per-request headers. Operator settings are not model input.

## Breaking v2 result contract

Recon CLI stdout is a compact object, not the old bare array:

```json
{"v":2,"tool":"recon_subdomains","cols":[],"rows":["a.example.test"],"total":1,"omitted":0,"completeness":"complete","coverage":{},"queue":null}
```

Column names appear once for tabular results. Recon CLI defaults to 200 rows and a 24 KiB serialized-row budget; `--limit N` lowers/selects the row bound and `--all` explicitly removes presentation bounds. MCP defaults to 100 rows/24 KiB. **`recon_surface` defaults to 20 rows in both interfaces.** `total` and `omitted` always account for the full observation set. Full rows are recorded once as `workflow_result`; terminal events retain completion metadata. CLI stderr contains the run/hash/cursor receipt; MCP includes it in the response object.

Exit **0** means the bounded workflow finished, not exhaustive asset coverage. Exit **2** means invalid input, unusable/operational failure or unavailable evidence. Exit **3** returns usable but explicitly incomplete observations and a **failure** receipt; MCP marks the same result `isError:true`.

On backend timeout, overflow or nonzero exit, only the last newline-complete captured prefix can be parsed. Partial metadata includes captured/parsed/discarded-tail bytes, cutoff reason and backend exit/signal. Raw stdout/stderr remain unchanged in the journal. Zero usable output alone stays an error: partial parsing cannot recover bytes never captured. Completed crawl work can survive a later required archive-stage failure, but the combined run remains failed/partial.

## Operator scope and research identification

`RECON_SCOPE` selects an **absolute operator-owned JSON file**, never a model-supplied path. The file must be regular, non-symlink, owned by root/current UID and not group/other-writable. The hash covers the exact bytes read.

```json
{"v":1,"in_scope":{"suffixes":["example.test"],"hosts":[]},"out_of_scope":{"suffixes":[],"hosts":[],"cidrs":[]},"provider_cname_denylist":["vendor.example"],"deny_private_ips":true,"required_headers":{"X-Research":"researcher"},"max_rps":2}
```

Explicit denies win. Suffixes match DNS-label boundaries. Any denied/private address in a resolution set blocks probing, including IPv4-mapped IPv6; validated addresses are pinned into native HTTP rather than re-resolved at dispatch. Provider CNAME denial is an explicit operator rule, not a guess that every CDN means out-of-scope. Name heuristics never authorize or exclude a host. Scope is policy, **not legal authorization or proof of ownership**.

Private/non-global addresses are denied by default. Authorized internal/loopback work requires an operator policy explicitly setting `deny_private_ips:false`; models cannot override it in requests. `RECON_REQUIRE_SCOPE=1` additionally refuses network workflows without a selected scope. `max_rps` can only lower the built-in two requests/second.

Effective headers come from `RECON_HTTP_HEADERS` (JSON string map). `RECON_REQUIRED_HEADER` names a header that must be present; `RECON_REQUIRED_HEADERS` supplies exact required name/value pairs, merged with scope `required_headers` without conflicts. HTTP workflows fail **before DNS or sockets** when requirements are missing or mismatched. Failure diagnostics expose required names, not values. Actual sent header bytes remain in the protected request evidence. Invalid operator configuration refuses MCP startup.

Host, Authorization, Cookie, Proxy-Authorization, Content-Length, Transfer-Encoding and Connection overrides remain forbidden. Transport is GET-only, TLS-validating, unauthenticated, without ambient proxies/cookie jars or automatic redirects. The 256 KiB body capture explicitly marks truncation and body-read errors.

## DNS, negative observations and limits

`recon_resolve` accepts 1..512 typed hosts, or a `source_run` selecting a verified completed `recon_subdomains` snapshot of the same size bound. `RECON_DNSX` chooses an absolute DNSx executable (otherwise PATH); hostnames go through a fixed, supervised JSON-producing invocation, never model-controlled switches. Hostname HTTP/TCP workflows also use DNSx so CNAME policy is checked independently of caller claims. Addresses and aliases are observations, not service liveness.

Actual negative DNS answers, empty answers and errors remain distinct. **A backend that emits no row for a host produces `not_observed`, not invented NXDOMAIN/NODATA.** Scope-blocked inputs remain explicit and are not queried. Interrupted resolution retains partial coverage and unknown rows.

Refused TCP connections and observed negative DNS/HTTP responses are valid observations even if `rows` is empty. Timeouts, missing backend output and audit failures do not become fake successful negatives. Coverage reports outcomes and omissions.

Discovery permits 32 hosts, 128 integer ports, 64 paths, at most 256 host/port pairs and 256 HTTP probes. Defaults are ports `[80,443]` and path `["/"]`; ports require an explicit list for TCP checks. HTTPS is used on 443/8443. TCP uses 300 ms connection timeouts/concurrency eight. This is not a SYN/UDP/banner scan or vulnerability confirmation.

Subfinder/gau use fixed source/rate/time arguments and `RECON_SUBFINDER`/`RECON_GAU` absolute paths, otherwise PATH. Supervision bounds runtime to 120 seconds and captured output to 8 MiB. Command captures are not internal provider HTTP or DNS packet captures.

## Receipt-driven saved inputs and surface views

`recon_resolve` with `source_run` reads the **full recorded snapshot**, not its limited preview or `--since` delta. Nonempty `hosts` and `source_run` are mutually exclusive. An optional `domain` must match the recorded source domain. Partial, empty, oversized, wrong-workflow or inconsistent sources are rejected; oversized snapshots are not silently truncated. Current scope, CNAME and address policy still apply before probing.

`recon_surface` accepts `run` from a saved `recon_urls` workflow, optional DNS-suffix display filter `site`, and optional absolute-path `prefix`. Default rows group inferred route families by origin and first two normalized path segments. A prefix selects detailed families on path boundaries, not substring matches. Static assets and literal noise are excluded from actionable rows but counted. Examples and evidence sequence references have explicit totals and omission counts.

The tool verifies the entire source chain before selecting request/result/completion and compact crawl observations. It does not export raw body/command captures or fall back to mutable files. Captured HTTP statuses belong to the source run: current liveness, authentication states, API operations and object graphs remain unknown. A retained partial source stays partial with its original byte/cutoff facts; legacy sources without bounds retain unknown bounds. This is a navigation aid, not endpoint equivalence or vulnerability confirmation.

Completed v1 facts remain readable, including original completion arrays; any retained terminal rows must match the recorded result. v2 sources still require their v2 completion summary. The same strict saved-workflow reader serves receipt chaining, `--since` and crawl resume.

## Crawl scheduling and resumption

`archive` is provider-only and rejects seeds/checkpoints. `crawl` is independent of gau. `combined` requires both stages, preserving any failed stage as incomplete.

Native crawling separates **32 navigation/metadata** requests from **eight JavaScript assets**, depth two, exact seed origin including scheme/host/port. CSS/images/fonts cannot consume navigation budget. Real navigation and robots/sitemaps take priority over script literals. Templates/constants retain provenance as hints but are not blindly requested. Robots exclusions are honored. No forms, browser execution or redirects.

A bounded checkpoint retains pending URL/origin/depth/kind, visited URLs, omission count and scope fingerprint in `workflow_result`. Default pending limit is 512 (`RECON_QUEUE_LIMIT`, maximum 2000); visited history is bounded to 4096. Every omission is explicit. Default output exposes only queue counts and a resume run ID, not hundreds of repeated URLs.

```json
{"domain":"example.test","mode":"crawl","seeds":["https://app.example.test/"],"resume":"32-lowercase-hex-id"}
```

Resume reads the verified prior checkpoint internally, revalidates exact origins and current policy, skips visited application content and consumes pending work first. A changed scope fingerprint is rejected before sockets. Robots is refreshed as an explicitly counted safety check, not reused as stale authorization. Inline `queue` checkpoints are also typed/validated; `resume` and `queue` are mutually exclusive. `recon_urls --queue-out PATH` creates a mode-0600 checkpoint export and refuses to overwrite an existing file.

## Lean evidence and observed-set comparison

`evidence_read` intersects `select.kind`, `class`, numeric HTTP `status` and `seq`, then applies `offset`/`limit` (default 100, maximum 4096). An event lacking HTTP status cannot match a status filter. **The entire chain is verified before filtering**, including records outside the selected page.

Responses preserve run-level hash/cursor/attribution plus `run_events`, filtered `events_total`, `events_omitted` and `next_offset`. Compact events retain sequence/kind/class/size and available URL/status/host/outcome summaries. Per-event hash/cursor default off for metadata; `include_integrity` overrides this. `include_payloads:true` is explicit, can be large and defaults integrity on. Original v1 journal facts remain readable.

Subdomains/URLs accept typed `since` or CLI `--since RUN`. The prior completed run must be the same workflow/domain/mode/seeds. Full snapshots remain in the journal; the presentation emits new identities with `new`/`gone`/`unchanged` counts. Partial current results or changed policy cannot establish `gone`, which becomes null. These are observation-set differences, **not live/dead claims or a freshness cache**.

Offline `bbp-urls --site DOMAIN` filters exact domain/subdomains on label boundaries, not PSL/eTLD inference or authorization. Its `--since FILE` rejects truncated/delta baselines. `bbp-routes` collapses locales, parameter templates and identifier segments while preserving origins, query names and real leaf operations; static/noise classes and bounded variants/provenance remain explicit. `bbp-http --group-metadata` groups body-less compatible metadata only, with `equal_bodies:false`; it never replaces body hashes with status/length guesses.

## Evidence, not model-authored facts

The evidence writer is **systemd-journald**, a separate root-owned service already present on this workstation. The recon process sends structured, sequence/hash-linked observations; the agent does not generate a Markdown report and call it a test log. Before returning success, the tool verifies that the recorded run and terminal receipt can be read back from the journal. Missing logging fails closed; there is no user-writable file fallback.

Facts include validated input, command arguments and exact captured stdout/stderr for passive backends; native network attempts and observed responses; limits/truncation/errors; and terminal results. Trusted journal metadata (UID/PID/executable where available, cursor) is distinct from client-supplied fields. Large captures are chunked and checked on reassembly.

`evidence_verdict` appends a **separate model-supplied interpretation**, referencing existing fact sequence IDs. Even the word `confirmed` remains a model verdict; the evidence reader lets a reviewer check which concrete observation supports it. No tool permits altering/deleting original facts, or submitting arbitrary replacement fact events through MCP.

### Exact guarantee and threat boundary

- Ordinary client UID cannot overwrite existing root-owned system journal files through these tools. Read permissions do not confer edit permissions.
- Root/admin can manage or remove journals; automatic retention can remove old records. This is **not permanent WORM storage**. For long-lived submissions, export receipts/evidence into an independently controlled archive under operator policy.
- A hash chain detects incomplete or inconsistent captured runs. It is not a signature, execution attestation or proof against a malicious program forging new entries. Journal attribution is stronger than an agent-written text report, but a same-user editable executable plus unrestricted shell/ptrace remains outside a strong attestation boundary.
- This user has administrative/docker capabilities. If the agent is given those privileges, local file ownership is not an adversarial isolation boundary. Root-resistant evidence requires an external append-only service or a separately administered host and restricted tool permissions.
- Journald retention, rate limits and access policy are operator-controlled. Raw captures may contain sensitive data; limit journal readership and retention appropriately. Result minimization is not universal secret redaction.

## MCP integration

`dist/recon_mcp` serves **six workflows and two evidence tools** over MCP stdio, using strict schemas and one compact text response rather than duplicated structured/text payloads. Five workflows perform network work; `recon_surface` reads saved evidence only. Requests remain bounded to 64 KiB. Calls are serialized; the client must allow supervised backend runtime. The installed timeout is 20 minutes.

The user registration remains in `~/.omp/agent/mcp.json`; Reflex is preserved. Operator settings must be present **before server startup**:

```text
RECON_DNSX=/absolute/path/to/dnsx
RECON_SUBFINDER=/absolute/path/to/subfinder
RECON_GAU=/absolute/path/to/gau
RECON_REQUIRED_HEADER=X-Research
RECON_HTTP_HEADERS={"X-Research":"researcher"}
```

`RECON_SCOPE` is optional; the local MCP registration leaves it and `RECON_REQUIRE_SCOPE` unset. Without a file, no program allowlist, explicit denylist or provider-CNAME exclusion is enforced. Private/non-global address blocking, fixed limits, audit logging and configured required headers still apply. Requests must still stay within authorized targets.

To opt into program-file enforcement, set `RECON_SCOPE=/absolute/operator/program.json` and `RECON_REQUIRE_SCOPE=1`. The selected file binds the server to that program. Before changing programs, select the appropriate policy and research header requirements; the model cannot choose its own policy. User-owned files are trusted configuration, not isolation from an unrestricted same-UID agent.

Linux systemd-journald, `journalctl` and `libsystemd` are runtime prerequisites for audited workflows; network goals also require their applicable backends. `recon_surface` needs the journal but no scanner backend. Offline `bbp-*` reducers and `tok-log` need none of them. Builds additionally require Rust 2024 and `libsystemd-dev`; the pinned `Dockerfile.build` supports machines without a host toolchain. Binaries are not installed into PATH.

After replacing binaries/configuration, run `/mcp reload` or start a new omp session. An already-running server does not inherit later environment edits.

## Version 0.3 verification

**77 focused tests passed** across the changed library, routes, frontend, input-validation, saved-workflow and surface paths. After the real legacy-format failure, all **14 saved-reader tests** passed with the corrected fixture and additional contradiction regression; unaffected successful suites were not repeated. All **15 release binaries** were compiled and atomically packaged with refreshed `dist/SHA256SUMS`.

| Scenario | Observed result |
|---|---|
| Receipt chaining | A one-row subdomain delta preview referenced a full 315-host saved snapshot; the synthetic DNSx backend processed all 315 without a copied host list. |
| Partial source guard | A retained partial subdomain source was refused before any DNS-backend invocation. |
| Legacy saved Whatnot view | 588 result URLs plus compact crawl evidence yielded 141 actionable groups; the default MCP response showed 20, omitted 121 explicitly, and occupied 10,356 bytes. |
| Account-settings zoom | 13 families, zero omitted, 7,157 response bytes; no captured responses were falsely attributed to those unprobed paths. |
| Fresh MCP process | Version 0.3.0 advertised eight tools and accepted the existing operator configuration. |
| Network activity | Saved Whatnot evidence and synthetic local backends only; zero new target requests. |

The first smoke stopped on a driver-only assumption that receipts include a status field. The next exposed an actual compatibility bug: original v1 completion data was an array, not an object. The reader now verifies that array against the recorded result, rejects contradictions, and passed the saved-Whatnot MCP scenario. Completed source-chain checks were not repeated.

Build/test/smoke output is retained in `target/verification-v03-*.log`; original failure logs remain. Derived views reference the unchanged source run/hash and append their own journal receipts. Byte counts are measurements, not AI-token or energy measurements.

## Version 0.2 verification

The pinned Docker builder completed the integrated suite: **195 passed, zero failed, six ignored entries**. All **14 release binaries** were compiled and packaged with refreshed `dist/SHA256SUMS`.

An actual CLI smoke exposed DNS object rows paired with tabular column labels. The output was corrected to compact arrays; all seven affected DNS tests passed afterward and the release binaries were rebuilt. Unaffected successful suites were not repeated.

The packaged CLI/MCP surfaces were exercised with synthetic source backends and actual loopback HTTP/TCP, not bounty targets:

| Scenario | Observed result |
|---|---|
| CLI presentation | 10 rows shown out of 314; 304 explicitly omitted. |
| Journal-backed `--since` | A 315-row current set compared against the full 314-row saved snapshot yielded one new row, not a comparison against its limited preview. |
| Interrupted backend | Three complete rows retained, incomplete tail excluded, exit 3 and a verified failure terminal; an unusable prefix stayed exit 2 with no fake output. |
| Required headers/private address | Missing attribution performed no request/backend-resolution work; proper attribution reached the local server; private-address policy prevented contact. |
| Negative DNS/TCP | NXDOMAIN remained distinct from `not_observed`; an actual local TCP refusal returned empty open rows with an explicit refusal outcome. |
| Evidence projection | One selected HTTP response occupied 1,207 bytes while preserving run integrity and filtered totals. |
| Crawl resume | First run made 40 requests; continuation made 18, with zero repeated content requests and one explicitly refreshed robots document. |
| MCP preview | Seven tools advertised; a 100-of-314 subdomain response occupied 2,558 bytes. |
| Installed profile | A fresh process started successfully with the saved operator scope/header configuration. |
| Offline reducers | Site-boundary filtering, query-value-independent URL deltas, distinct account-operation route families and metadata grouping without body-equality claims all passed actual CLI scenarios. |

Local build/smoke outputs and native receipts are indexed in `target/verification-*.log` and `target/verification-smoke.json`. The first smoke failure is retained separately. These local summaries are not replacements for journal facts. The historical external gau timeout below was not retried or relabelled successful.

## Historical version 0.1 verification

Following the requested correctness review, `cargo test --locked --quiet` passed **126 tests**. Four ignored harness entries are subprocess fixtures explicitly launched by nonignored runner tests, not skipped behavioral assertions. Cargo emitted unused test-helper warnings; no test failed.

`cargo build --locked --release --bins --quiet` succeeded. All 12 offline/workflow/MCP/evidence executables are packaged under `dist/`, with delivery hashes in `dist/SHA256SUMS`. Real command/protocol surfaces were exercised, not just inspected.

|Scenario|Observed proof|Journal run|
|---|---|---|
|Native TCP workflow|Ephemeral loopback port observed open; seven events and trusted UID/PID/EXE attribution.|`45f9847761943d1fe0f79b8798908384`|
|HTTP discovery|Actual loopback response/title and X-HackerOne request header; 262,144 captured body bytes, explicit truncation, 350,254-byte event losslessly reassembled from chunks.|`3d52ce19bf032af3fc3440c5ec2e3ae4`|
|Separate verdict|`model_supplied` verdict references the HTTP observation; original fact hash and event count stayed unchanged.|`d8e7a3b9ffed518d19e2ac73af68fc22`|
|MCP workflow|Initialize/list/call worked with all six namespaced schemas and a real typed TCP workflow; no duplicate structured result envelope.|`4b4bad7c88c0384f964408418108ee91`|
|Actual subfinder|Passive provider lookup for reserved example.com completed in 60.72 seconds with 42,955 distinct in-scope names. These are provider observations, not verified resolving/live assets.|`9f0262bf5e9b421ce7a5f09738e24367`|
|Independent native URL crawl|With gau deliberately unavailable, crawl mode discovered four local URLs, made six GET requests, rejected a cross-origin link and verified 43 recorded events.|`7cab2ce1fe630294263dd6d69d974b50`|

The ordinary UID 1000 was denied `O_WRONLY` access to the root-owned persistent `system.journal`. The check did not truncate or write a journal file. This verifies the stated ordinary-user edit boundary, not resistance to root/admin or forged new entries.

### Failures retained, not disguised as success

- Initial subfinder supervision used a two-minute engine budget equal to its external deadline. The real run was killed at 120.04 seconds and recorded failure (`58008568ac2d993640141ae130337173`). The engine budget was corrected to one minute, leaving shutdown headroom; the subsequent actual-source run completed.
- Actual gau archive retrieval did not complete within its 120-second supervisor deadline. Its process group was killed/reaped, captured output retained, no success stdout emitted, and a failure receipt returned (`c44edf76fe3c8cacf6a0735d6384b488`). A positive live archive-provider completion was therefore **not verified**. The fixed-argv runner, parsers, timeout/output bounds and failure accounting passed isolated tests; explicit native crawl mode was verified end to end without gau.
- The initial HTTP smoke harness expected verdict class `model_verdict`; the actual class is explicitly `model_supplied`. The assertion was corrected against the already-recorded evidence, without repeating network work or changing the correct evidence format.

Active smoke traffic stayed on loopback. External requests were passive source-provider lookups for reserved example.com/localhost.localdomain, not probes of bounty targets. Receipts remain subject to journal retention.

### Requested second-pass review

Concrete corrections:

- Crawler audit/configuration failures propagate instead of being swallowed as ordinary unreachable URLs. Zero-response crawls fail with a recorded failure receipt; missing seed pages are not echoed as discovered URLs.
- HTML `<base href>` now resolves relative candidates correctly, while the exact-origin check still rejects external bases. Localhost normalization accepts case variations and a DNS root dot.
- MCP default previews bound both result counts and array bytes, preserve omission totals, and retain full recorded results. Invalid JSON-RPC IDs and non-object params are rejected before dispatch.
- Native journal reads reject duplicate required fields; verification rejects contradictory tool/model request attribution and model completions claiming tool confirmation. Valid stored v1 records remain readable.
- Offline HTTP imports preserve path-map context/status-code records, distinguish array-record provenance, and do not misinterpret captured Aura responses as saved requests.
- GraphQL lookup rejects missing/malformed default metadata instead of asserting unknown defaults/requiredness. Log timestamp stripping no longer merges impossible calendar dates into real timestamped events.

The rebuilt release binaries passed actual CLI/MCP/journal smoke proof without source-provider or bounty requests:

|Case|Observed result|Journal run|
|---|---|---|
|All loopback fetches fail|Exit 2, zero success stdout, three failed fetches and a verified failure receipt.|`f3566d09869247617a85710bd18666b7`|
|HTML base resolution|Fetched `/assets/account`, not the incorrect `/nested/account`; successful receipt read back.|`7c8e427724f56d899c6d9d50cc5ea2f1`|
|Large supervised fixture through MCP|2,500 full results retained in evidence; 100 previewed, 2,400 explicitly omitted; 2,397-byte MCP content payload.|`5589d6a18b07ba61f6c58522a501e47f`|

Existing v1 HTTP and model-verdict receipts were read successfully by the stricter journal verifier. The smoke fixture was temporary and removed. All 12 release checksums were refreshed. The subsequent MCP registration is described below; the earlier external gau timeout and documented journal/administrative limitations remain unresolved external/runtime constraints, not claimed successes.

### Local MCP registration verification

A fresh native omp RPC process discovered all six recon/evidence tools from the saved user configuration. A temporary, nonpersistent overlay made mounted tools visible in the RPC tool catalog and waited for initial connections; that overlay was removed and no persistent tool-visibility setting changed.

The installed official MCP client SDK then used the exact saved command, cwd and environment to list the six tools, execute `recon_ports` against an ephemeral loopback listener, and verify its receipt through `evidence_read`. The recorded run was `eceff1ab6df5ad0c8952f389bc1c366b`, with status `complete` and a matching final hash. No model inference or target/provider traffic was used. Existing Reflex configuration was preserved.

Use `/mcp reload` to activate the registration in an already-running conversation; `/mcp list` and `/mcp test recon` provide native session diagnostics. The configured timeout applies unless a process-wide `OMP_MCP_TIMEOUT_MS` overrides it.
