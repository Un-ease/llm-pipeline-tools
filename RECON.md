# Typed recon workflows

These tools wrap goals, not scanner flags. Requests are typed JSON; unknown fields, malformed domains/URLs, non-integer ports and oversized workloads are rejected before execution. Each CLI prints its input JSON Schema with `--schema`. `recon_mcp` exposes the same workflows as named MCP tools with typed schemas.

## Workflow surface

|Tool|Input|Result on CLI stdout|
|---|---|---|
|`recon_subdomains`|`{"domain":"example.com"}`|Sorted unique in-scope subdomain strings from passive source enumeration.|
|`recon_discover`|`{"hosts":["api.example.com"],"ports":[80,443],"paths":["/"]}`|Only observed HTTP endpoints, statuses and compact title/server metadata.|
|`recon_urls`|`{"domain":"example.com","mode":"archive"}`|Sorted unique URLs from `archive`, `crawl`, or `combined` workflow modes.|
|`recon_ports`|`{"hosts":["api.example.com"],"ports":[443,8443]}`|Only observed open TCP endpoints, including resolved address and integer port.|
|`evidence_read`|`{"run":"32-lowercase-hex-id","include_payloads":false}`|Verified event metadata; actual payloads only when explicitly requested.|
|`evidence_verdict`|`{"run":"32-lowercase-hex-id","verdict":"hypothesis","evidence":[1],"note":"Model interpretation"}`|A separately labeled model verdict, never replacement facts.|

Examples show request shapes, not authorization to contact these domains. CLI stdin is a JSON object; no arbitrary scanner arguments, shell expressions, commands, executable paths or report text are accepted in recon tool requests. Responses contain no banner, progress bar or raw scanner dump. A separate one-line stderr receipt identifies the recorded run, final hash, journal cursor and event count.

`recon_discover` defaults to ports `[80,443]` and path `["/"]`; `recon_ports` requires an explicit port list. Ports must be JSON integers in 1..65535, not strings such as `"80,443"`. Up to 32 hosts, 128 ports and 256 host/port pairs are allowed. Discovery additionally accepts up to 64 paths, with at most 256 total host/port/path probes. It uses HTTPS on 443/8443 and HTTP on other ports. This is response discovery, not vulnerability confirmation or a UDP/SYN/banner scan.

A domain limits discovered names/archived URLs using DNS-label boundaries. It does not establish legal authorization or automatically inherit a bounty program's scope. Supply only authorized assets; program traffic limits and required headers still take precedence. Authenticated scanning and arbitrary request/header injection are intentionally not part of these recon workflows.

## Whole-workflow execution

- **Subdomains:** execute installed `subfinder` once with fixed quiet/structured-output, rate and time settings; capture the command and all observed output; validate scope; normalize and deduplicate names.
- **Host/content discovery:** resolve supplied hosts, then send bounded GET probes to the specified services/paths. Record resolver outcomes, request intent, response metadata/body and operational failures. HTTP error responses remain observations, not findings.
- **URLs:** `archive` (default) collects saved historical URLs through installed `gau`; `crawl` requires seeds and performs native exact-origin discovery without requiring gau; `combined` crawls supplied seeds and then collects archives. Archive mode rejects seeds rather than silently ignoring them; crawl/combined require at least one seed. Historical URLs are not asserted live. Crawling is GET-only, bounded to 32 pages/depth two and exact origin including scheme/host/port; no form submission or automatic redirect escape. Linked resources, robots and sitemap references supply candidates. This is not browser execution or exhaustive JS analysis. A required stage failure remains a failure; combined mode does not silently substitute partial success.
- **Ports:** resolve supplied hosts, perform bounded native TCP connects with 300 ms connection timeouts/concurrency eight, and return only actual opens. Refused, timed-out and operational-error observations remain distinct in evidence.

For a local crawl: `{"domain":"localhost.localdomain","mode":"crawl","seeds":["http://localhost.localdomain:8080/"]}`. Domain-only archive lookup and seeded native crawling are distinct goals, not individual scanner-flag wrappers. A slow/unavailable archive source therefore does not block an explicitly requested crawl.

Subfinder and gau are reused rather than reimplemented. Their paths are operator environment settings (`RECON_SUBFINDER`, `RECON_GAU`, absolute paths), not model inputs; otherwise binaries are found on PATH. Missing/failed tools fail visibly. There is no mock, silent empty fallback or arbitrary-flag escape hatch. Captured source-tool output is command evidence, not a claim to have captured its internal provider HTTP traffic.

Active HTTP requests use native Rust transport: TLS validation, no ambient proxy or cookie jar, no credentials, no automatic redirects, a bounded timeout/body capture, and conservative request pacing. Captures describe HTTP semantics, not TLS wire packets. Bounded response capture explicitly records truncation instead of pretending the complete body was received. DNS evidence describes system-resolver calls/outcomes, not raw DNS packet capture.

Set operator environment `RECON_HTTP_HEADERS` to a JSON object of required research-identification headers before starting the CLI/MCP server (for example the program's `X-HackerOne` header). Names/values are validated; Host, Authorization, Cookie, Proxy-Authorization, Content-Length, Transfer-Encoding and Connection overrides are forbidden. Effective sent headers are recorded. HTTP pacing is process-wide, not a cross-process traffic governor: multiple CLI instances can aggregate traffic.

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

Run `dist/recon_mcp` as an MCP stdio server. It advertises exactly the four workflow tools and two evidence tools above; input schemas use `additionalProperties:false` and real integer port arrays. Tool replies have one compact text payload containing results and the evidence receipt, not duplicated text/structured copies. Requests are bounded to 64 KiB. The server accepts standard initialize, ping, tools/list and tools/call messages.

MCP workflow arrays are previews: at most **100 rows / 24 KiB of serialized array data**, with explicit `total`/`omitted` fields. Default evidence metadata applies the same bound and reports `events_total`/`events_omitted`. Full results remain in the protected journal and normal CLI output; presentation limits do not change recorded facts. Explicit `include_payloads:true` requests remain full and can be large.

Calls are currently serialized, without cancellation support. Passive supervision can take 120 seconds; large native batches can take longer, and system-resolver duration is OS-controlled. Configure the client timeout for the selected workload and use conservative batch sizes; a short default tool timeout is not suitable for every workflow.

The default omp profile now registers server `recon` in `~/.omp/agent/mcp.json`, preserving the existing Reflex entry. The registration pins the project working directory and absolute subfinder/gau paths, with a 1,200,000 ms (20-minute) request timeout. Executable reference:

```json
{"command":"/home/un-ease/Documents/Projects/llm-pipeline-tools/dist/recon_mcp","args":[]}
```

CLI example on an explicitly authorized host:

```sh
printf '%s\n' '{"hosts":["127.0.0.1"],"ports":[8080]}' | ./dist/recon_ports
```

Linux, systemd-journald, `journalctl` and `libsystemd` are runtime prerequisites for audited workflows. They are not required for the original offline tool semantics. Executables remain outside PATH; omp launches the registered stdio server. Run `/mcp reload` in an existing conversation, or start a new omp process, to load the registration.

## Verification

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
