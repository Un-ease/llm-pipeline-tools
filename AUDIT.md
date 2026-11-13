# Local AI pipeline audit

## Boundaries and provenance

This audits accessible local sessions and saved BBP artifacts, not provider internals or live targets. No bounty targets were contacted, existing evidence was not rewritten, and `omarchy_plugin` was left alone. Ten earlier sessions were discovered through the archive. Historical consults inspected available parent/child evidence; one bounty-recap consult was inaccessible. Availability of a session title does not imply complete execution telemetry.

FanDuel's original source JSONL line 3 and six child histories identify **deepseek/deepseek-v4-flash**; child `model_usage` also records provider `deepseek`. The OpenAI model used for these historical consults is not historical provenance. Other sessions must not be attributed to DeepSeek without original metadata.

## Observed unnecessary effort

### FanDuel — `01a1b495-8960-7285-87aa-486e1786566e`

Main and several workers independently decoded Aura requests and built Python/shell callers. Workers repeatedly fetched/searched the same bundles, components, login routes, Flow parameters and search methods. These were complementary assignments with overlapping prerequisites, not six identical investigations.

Historical evidence: `artifact://13` contained 19 captured requests repeating Aura context; `artifact://5` recorded four 503,497-byte shells and two 503,572-byte variants. Download output recorded `app.js` at 5,905,026 bytes. ChatMessaging printed 531 configuration lines; AuthIDOR emitted 401 enumeration lines. Whole-report redaction/consistency passes repeated after several payload revisions.

Retained local inputs include `Fanduel/tmp/nav.json` (request-only Aura capture), `validation-readonly.json`, and the evidence directory. SHA-256 identified `tmp/article.html` and `tmp/xfh_s.html` as identical, each 162,486 bytes. Historical `/tmp/fd` response captures are not retained; tooling must not pretend request-only records prove success.

Use `bbp-http --aura` for action descriptors and parameter shapes, `bbp-evidence` for duplicate bundles/artifacts, and targeted `rg` for source sinks. Share one capture/import step before distributing analysis.

### Wolt — `01a19802-21b9-7018-8e8c-8c87c2398580`

The recorded workflow revised the proxy parser three times, retried counts/offsets, dumped raw flows, then reread slices and grouped endpoints. `tools/burp_history.py` indexes only after initializing MCP; it whole-loads JSONL and deduplicates using the first 400 characters of request/response. Different bodies beyond that prefix can be lost.

Seven retained `burp/*.jsonl` exports contain 801 stored lines and 2,153,309 bytes. Stored rows are not unique traffic: host regexes overlap. A historical five-host checkpoint contained 719 stored rows and 1,836,631 bytes. Do not compare these different checkpoints as growth or savings.

Use `bbp-http` directly on saved JSONL: no MCP initialization, full response-body fingerprints, parameter names rather than credentials/query values. Exact groups retain counts and source references.

### Mercedes — `01a1c4c3-2a86-72a7-8e4c-ee00180b6ddf`

Repeated shell/Python matrices classified response status, sizes, headers and bodies. Overlapping root/edge/validator workers revisited ACL and Host tests. An exhausted realm branch was revisited after 1,364 requests per host had been recorded. Repeated report propagation corrected severities, realm counts and version references.

The largest avoidable read: `agents/gitlab/evidence/gql_queryfields.json`, **8,175,375 bytes / 4,429 types**, was repeatedly loaded and printed. It is byte-identical to `gql_typenames.json`. Invalid GraphQL selections then required further iterations. `bbp-gql` looks up actual saved fields, nested type wrappers and argument requirements without dumping descriptions or data. It is a schema lookup, not a full GraphQL query validator or an authorization test.

Use `bbp-http` for saved JSON/JSONL response classification. Do not infer identical content from matching status/length alone.

### Other accessible historical workflows

- Wolt recon (`01a19800-a41a-76b0-aa82-cb98fd97c949`): attached assessment contained misparsed static-chunk endpoints and a purported four-hour schedule totaling 270 minutes. No historical execution trace supports counting repeated reads in that source. URL inventory is useful; claimed 927-host coverage was not independently counted.
- Export workflow (`01a1c158-5207-7365-9629-889202509cb9`): a 20,001-byte sliced history failed JSON parsing; later retrieval/parsing overlapped. The same deterministic `EXTENSION_MISMATCH` appeared five times in one sequence and eight in another. Async polling itself was necessary; repeating a protocol failure and complete envelopes was not. Shared `/tmp/relay.py` was overwritten by another worker.
- Reflex integration (`01a17df5-e674-7381-93bd-2a5bfec0360a`): identical results were exposed through several nested envelopes and printed again. Existing Reflex already has compact replies, clipped observations and pinned plans. Its documented 2,605-to-1,982-byte serialization change is not a token benchmark. Preserve exact-command review and pin checks; batch predictable commands rather than delegating a fixed sequence.
- Minecraft disconnect/startup sessions (`01a188bc-eb9e-73c9-8044-7d21d0a4bb12`, `01a187d5-b260-747d-933d-ca8ccf51b2a8`): repeated pasted server logs included irrelevant DEBUG/HTML/changelog content. The client/server evidence distinction was explained late. `FATAL` did not establish process termination: later startup completion and gameplay were recorded. `tok-log` is deliberately mechanical, not a crash/root-cause classifier.
- Apple skill-loading session (`01a1bc2a-486b-7496-9f96-8bb78502ef95`): short `/skill idor` lookup failed and emitted an inventory; full skill name succeeded. Resolve aliases once; this single occurrence does not justify another Rust binary.
- Bounty recap (`01a19cda-a917-7426-b26a-e514f4cb1600`): consult could not access its contents. No findings are attributed to it.

## All BBP directories surveyed

Paths below are relative to `~/Documents/H_Programs/BBP`.

|Directory|Observed artifact and useful reduction|
|---|---|
|Fanduel|Aura request capture, three-entry validation map, duplicated 162,486-byte HTML shells; action-shape index and evidence manifest.|
|Mercedes|18-line HTTPX JSONL; saved probe arrays; duplicated 8,175,375-byte GraphQL schema; HTTP and schema indexes.|
|wolt|801 saved Burp JSONL lines; 137 `.body`, 140 `.hdr`, 18 `.headers` files under sweep; offline HTTP indexing.|
|walt|Empty, distinct from `wolt`; no inputs to automate.|
|Bolt|Nested `cloud_probe_output.json` has 12 HTTP entries; 101-line recon ledger. Existing unsupported nested schemas must not be silently treated as HTTP captures.|
|moonpay|414 endpoint records in a 946,968-byte contract map; six saved YAML specifications. Existing Python contract-map/render helpers already address some work; no redundant YAML parser added.|
|NBA|9,739,886-byte historical recon JSON; 396 candidates and 35 blocked/exhausted entries. Existing merge scripts encode ledger semantics; generic compaction cannot adjudicate findings.|
|Hilton|1,526 inventory entries, 420 HTTPX observations; identical 208,644-byte main/dev JS bundles. Evidence inventory and literal URL extraction.|
|Cisco|Two identical 318,411,397-byte wordlists, each 9,363,094 lines; 282,453-line subdomain file. Stream URL candidates; default evidence hashing skips files over 16 MiB and explicitly reports skips.|

## Necessary work not labeled waste

Owned-account boundaries, negative controls, independent browser execution, fresh evidence/currentness checks, dummy-only listener receipts and frozen-submission integrity were valuable. FanDuel's later successful form submission disproved an earlier blanket blocking conclusion; that verification was essential. Scope/authentication/agent-only blockers should be recorded and revisited only when prerequisites or evidence change.

## Pipeline changes

1. Collect authorized evidence once and preserve raw files; keep worker scratch paths namespaced.
2. Run local indexes before exposing artifacts to an LLM. Use bounded compact output, then select a source record/type/field for deeper inspection.
3. Share deterministic imports/bundle hashes across workers; allocate distinct hypotheses only after that prerequisite.
4. Track blocked prerequisites and evidence changes. A uniform 401, same-sized body or schema field is not proof of access or impact.
5. Retain raw artifacts and omission counts. Compaction is intentionally lossy presentation, not a replacement evidence store.
6. Reuse existing fast tools: `rg -n -o` for targeted source matches, `jq -c` for known JSON projections, `sort -u`/`comm` for external-sort set work, `sha256sum` for frozen submissions, and `pdfinfo`/`pdftotext`/`pdfimages` for documents. Do not reconstruct them through repeated model-written snippets.

Byte reductions from real CLI smoke runs are recorded separately in `BENCHMARKS.md`. They are output-size measurements, not measured DeepSeek tokens, energy savings, or proof of end-to-end research productivity.
