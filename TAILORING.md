# Tool tailoring review — historical design input

Implementation: **0.2**; the current interfaces and safety semantics are documented in
[RECON.md](RECON.md). This review is retained as design history, not a current API
specification. In particular, missing DNS output is unknown, stored bytes are not
measured model tokens, and operator scope is selected through `RECON_SCOPE`.

Input evidence: `/home/un-ease/Documents/H_Programs/BBP/Whatnot/` (snapshot
2026-11-13). That run is the first end-to-end use of the typed recon layer
against a real HackerOne program, and it exposes where deterministic work still
leaked back to the model.

## 1. Measured problem

| Observation | Number |
|---|---:|
| Passive hostname candidates | 314 |
| DNS-positive (dnsx) | 156 |
| No positive record (**not** proven NXDOMAIN) | 158 |
| Hosts after policy triage / actually probed | 314 → **4** |
| HTTP requests | 37 (33×200, 4×404) |
| HTTP bodies truncated at the 256 KiB cap | 5 |
| Crawl candidates / queued-not-fetched | 588 / 557 |
| gau archive coverage | **0 bytes** (SIGKILL, timeout) |
| MCP subdomain preview / omitted | 100 / 214 |
| Stored handoff assets + report | **271,989 B + 9,504 B**; not measured consumed tokens |

The tools' own output was compact. Stored artifact volume was concentrated in the
derived layer; actual model-token consumption depends on what was read/printed:

| Asset | Bytes | Redundancy |
|---|---:|---|
| `host-triage.json` | 116,767 | 314 hosts × 7 fields; compact TSV is 20,804 B |
| `subdomains.sources.json` | 43,058 | same hosts again |
| `homepage-html-surface.json` | 37,332 | 151 links from a truncated page |
| `www-crawled-urls.json` | 35,566 | 588 raw URLs, ~198 template/junk |
| `subdomains.txt` | 7,720 | same 314 names a third time |
| `evidence/dnsx-*` | ~290,000 | 50 KB observations + 240 KB journal |

Three copies of the host list, and 116 KB to express "314 → 4".

The useful crawl surface exists but is buried: `/account/settings/{change-email,
change-password,change-phone-number,passkey,delete-account,payments}`,
`/authorize/oauth`, `/inbox`, `/messages`, `/order`, `/player`, `/short_video`,
`/livestream-recorder`, `/dashboard/{analytics,ledger,lives,shipments}` — mixed
with `/$`, `/1`, `[locale]`, and `w3.org` namespace literals.

## 2. Invariants that must not change

1. Typed JSON input, `deny_unknown_fields`, no CLI flags passed to backends, no
   shell, no model-supplied scanner arguments.
2. No silent truncation, no silent empty fallback, no guessed defaults, no
   prefix-based equality.
3. Evidence is written before success is reported; a missing/partial journal
   write is a failure, never a success.
4. Offline tools never contact targets.
5. Recorded facts and model verdicts remain separate classes.
6. Every output states `total`, `omitted`, and enough completeness metadata to
   decide whether to ask for more.

The changes below add **partial results** and **projection**. Neither weakens
1–5; both reduce the cases where a model falls back to raw files or shell.

---

## 3. P0.1 — Preserve captured stdout when a backend does not complete

**Problem.** `passive.rs:78-80` requires `!timed_out && !output_overflow &&
status.success()`. `command_output` (`passive.rs:261-269`) returns `Err` before
parsing, so `capture.stdout` is journaled but never returned. Whatnot's gau run
produced 0 usable bytes after 120 s (`signal=Some(9), timeout=true`).

**Spec.**

```
command_output(backend, domain, audit):
  capture = capture_command(...)
  audit.record("command_capture", capture.evidence())
  if capture.succeeded(): parse all stdout normally

  else:
    prefix = stdout truncated at the last b'\n'
    if prefix is empty: return Err (unchanged: exit 2, no stdout)
    parse prefix
    record observation with:
      "partial": true,
      "cutoff_reason": "timeout" | "output_overflow" | "exit_status" | "io_error",
      "captured_bytes": <len(stdout)>,
      "parsed_bytes": <len(prefix)>,
      "discarded_tail_bytes": <len(stdout) - len(prefix)>,
      "backend_exit": <code|null>, "backend_signal": <n|null>
    return Partial { items, completeness }
```

**Result surface.**

- stdout: the same bare result array as today (no shape change).
- stderr receipt: adds `"completeness":"partial"`, `"rows_total"`,
  `"cutoff_reason"`.
- exit code: **3** (new). `0` still means complete; `2` still means no result.
- Journal terminal event remains class `failure` (no schema change) and carries
  `{"error":..., "partial":{"accepted":N,"cutoff_reason":...}}`. Parsed prefix
  rows are recorded as normal `tool_observation` events **before** the failure
  event, so `evidence_read` shows exactly what was accepted and what was cut.

**Rules.**

- Truncate only at a complete newline; never parse a half-record.
- A partial result is never labelled complete and never counts as coverage.
- Future interrupted runs with captured complete records can return usable prefix rows.
- This recorded gau case had zero stdout bytes, so partial parsing cannot recover URLs from it.
- Partial data is not merged across runs.

**Acceptance.** Fixture: backend prints 100 valid records, then is killed.
Result contains 100 rows, exit 3, receipt `completeness=partial`,
`discarded_tail_bytes>0`, journal has 100 accepted and one failure event.
Existing 126 tests unchanged.

---

## 4. P0.2 — Bound recon CLI output and unify the result contract

**Problem.** `frontend.rs:92` rejects every CLI argument
(`provide typed JSON on stdin, not CLI flags`). The CLI therefore always emits
the full result: 314 names today, 42,955 in the earlier example.com run. The MCP
path is bounded (`100 rows / 24 KiB`), the CLI fallback is not — so the only
unbounded path is the one a shell-invoking model would use.

**Spec — result contract v2 (breaking, documented).**

```json
{"v":2,"tool":"recon_subdomains","rows":["a.example.com"],
 "total":314,"omitted":0,"completeness":"complete",
 "coverage":{},"queue":[]}
```

- `rows` replaces the bare array; `total`/`omitted`/`completeness` are always
  present. `coverage` and `queue` are tool-specific objects (empty otherwise).
- CLI accepts `--limit N` and `--all` (default `--limit 200`), mirroring the
  offline tools. `--schema`, `--help`, and stdin-only input are unchanged.
- MCP keeps its 100-row / 24 KiB preview budget and reports the same field
  names; `mcp_result` already computes `total`/`omitted`.
- `evidence_read` keeps its own shape; only `include_integrity` (P2.1) is added.

**Acceptance.** `recon_subdomains --limit 10` emits 10 rows, `total=314`,
`omitted=304`, exit 0. Without a flag the default is 200.

---

## 5. P1.1 — New workflow: `recon_resolve`

**Why.** The DNS and triage stage was performed by hand this run: 50 KB of
`dnsx` JSONL, 240 KB journal export, and a 116 KB hand-written triage file. It
is fully deterministic, uses fixed arguments, and is the step that decides which
hosts may ever be probed. It belongs in the typed layer.

**Input.**

```json
{"hosts":["api.example.com","www.example.com"],
 "domain":"example.com",
 "scope":"whatnot",
 "record_types":["a","aaaa","cname","ttl"]}
```

| Field | Rule |
|---|---|
| `hosts` | 1..512 validated `Host` values (reuses `types.rs`); required |
| `domain` | optional `Domain`; when present, out-of-domain hosts are rejected input, not silently dropped |
| `scope` | optional operator scope name (P1.2) |
| `record_types` | subset of `a,aaaa,cname,ttl`; default all four |

**Backend.** `dnsx` with fixed argv, resolved like subfinder/gau
(`RECON_DNSX` absolute path, else PATH):

```
dnsx -silent -json -a -aaaa -cname -ttl -retry 1 -threads 10 -timeout 5
```

No user-supplied resolver list, threads, retries, or output format. 120 s
supervisor, 8 MiB capture, partial-parse on timeout (P0.1).

**Output rows** (compact; full address lists behind `--all`):

```
[host, status, a_count, aaaa_count, cname_target, ttl_min, disposition]
```

| `status` | Meaning |
|---|---|
| `positive` | at least one A/AAAA/CNAME record observed |
| `no_record` | backend returned a record with no positive answer (e.g. NOERROR/NODATA) |
| `error` | SERVFAIL/REFUSED/timeout, distinguished in `coverage` |
| `not_queried` | input rejected by `domain`/scope before querying |

`no_record` requires an actual negative backend observation. Silent missing DNSx
rows are `not_observed`, never invented NXDOMAIN/NODATA results.

`disposition` is emitted only when a scope is supplied (P1.2); otherwise null.

**Coverage object.**

```json
{"hosts_in":314,"hosts_out":314,"positive":156,"no_record":158,
 "errors":0,"internal_address":1,"max_hosts":512,"complete":true}
```

**Evidence events.** `resolve_intent` (hosts, record types, argv, limits),
`resolve_capture` (verbatim stdout/stderr, base64, chunked, `not_network_packet_evidence:true`),
`resolve_result` (rows' counts and dispositions), `workflow_result`.

**Acceptance.** 314-host fixture → ≤ 12 KB output; counts reconcile with the
capture; `localhost` → `127.0.0.1` produces `internal_address` and is never
queued for probing; a 10-record timeout fixture returns 10 rows with exit 3.

---

## 6. P1.2 — Scope as operator-owned data

**Why.** Whatnot's 116 KB triage file encodes policy decisions a human derived
by hand: loopback host excluded, 37 vendor-namespace CNAMEs excluded (zendesk,
scalar, statuspage), 167 non-production name hints deprioritized, 42 wildcard
hosts with unverified ownership. That is deterministic policy application, and
it is the only guardrail that makes a bounded run both legal and useful.

**Location.** `RECON_SCOPE_DIR` (absolute path, operator-owned, default unset).
Typed input may name a scope from that directory; it may never supply scope
content.

```json
{"scope":"whatnot"}
```

Resolution: `$RECON_SCOPE_DIR/<name>.json`, name matched `^[a-z0-9][a-z0-9._-]{0,63}$`.
The file must be a regular file, not a symlink, and not group/other-writable.
Its SHA-256 is recorded as `scope_file_sha256` on every run that uses it.

**File format.**

```json
{"v":1,
 "program":"whatnot",
 "in_scope":{"suffixes":["whatnot.com"],"hosts":["www.whatnot.com"]},
 "out_of_scope":{"suffixes":["zendesk.com","scalar.com","statuspage.io"],
                 "hosts":[],"cidrs":["127.0.0.0/8","10.0.0.0/8",
                                     "169.254.0.0/16","::1/128"]},
 "require_headers":{"X-HackerOne-Research":"un-eaze"},
 "max_rps":2}
```

**Rules, in order.**

1. `out_of_scope.hosts` / `.suffixes` win over everything (DNS-label boundary,
   reusing `Domain::contains_host`).
2. `in_scope.hosts` allow exactly; `in_scope.suffixes` allow host == suffix or
   `*.suffix`.
3. Any resolved address inside `out_of_scope.cidrs` → `internal_address`,
   never probed, regardless of name scope.
4. CNAME target matching `out_of_scope.suffixes` → `vendor_namespace`,
   not probed by default.
5. Name heuristics may set `priority_hint` (`nonproduction`, `staging`,
   `admin`) but must never change scope. Name-based exclusion is the caller's
   decision, recorded, never automatic.
6. `max_rps` may only lower the built-in 2 rps.

**Enforcement points.**

| Tool | Effect |
|---|---|
| `recon_resolve` | assigns `disposition`; `internal_address` and `vendor_namespace` rows never become probe candidates |
| `recon_discover` | rejects hosts not allowed by scope; refuses `internal_address` resolution results before any request |
| `recon_ports` | same rejection; `cidrs` checked on every resolved address |
| `recon_urls` crawl | seeds must be in scope; cross-origin rejection unchanged |
| `recon_subdomains` | output filtered to in-scope suffixes (current behavior already filters to `domain`) |

**Absent scope.** Behavior is unchanged, and the receipt records
`"scope":"unset"`. A new operator switch `RECON_REQUIRE_SCOPE=1` makes HTTP
workflows fail closed (exit 2, no requests) when no scope is selected.

**Boundary.** A scope file expresses operator policy. It is not legal
authorization, not proof of ownership, and not a substitute for reading the
program policy. The tool can only enforce what the operator wrote down.

---

## 7. P1.3 — Required research headers

**Problem.** `~/.omp/agent/mcp.json` sets `RECON_SUBFINDER` and `RECON_GAU` but
not `RECON_HTTP_HEADERS`. Any MCP `recon_discover` or crawl against a HackerOne
target therefore sends no `X-HackerOne-Research` header. The Whatnot run avoided
this by using standalone binaries with per-command env; the next agent has no
reason to know that.

**Spec.**

- `RECON_REQUIRED_HEADERS` (JSON object of name→exact value). Selected scope
  files may also supply `require_headers`; both are merged and must agree.
- Before any DNS/TCP/HTTP work, HTTP workflows verify that every required
  name/value is present in the effective `RECON_HTTP_HEADERS`. Missing or
  mismatched → exit 2, zero requests, journal records `header_policy` with the
  missing names (names only, never values).
- On success, record `header_policy:{"required":[...],"satisfied":true}` next to
  the existing base64 `effective_headers` (`network.rs:144-146`).
- `recon_mcp` reads the two variables at startup. If
  `RECON_REQUIRED_HEADERS` is present but invalid, the server refuses to start
  rather than serving tools that would silently omit a required header.

**Acceptance.** With a required header set and absent from
`RECON_HTTP_HEADERS`, `recon_discover` exits 2 with no socket activity and a
`header_policy` journal event. With both set, the request evidence contains the
header and `satisfied:true`.

---

## 8. P2.1 — Evidence projection and pagination

**Problem.** `Audit::read` (`audit.rs:165-168`) returns every event with
`hash` (64 hex) and `cursor` (~120 chars). For a 100-event preview that is
~18 KB of the 24 KiB budget spent on integrity fields, so fewer real events fit
and the next step is often a full payload dump. The Whatnot run worked around
this by exporting the whole journal (96 KB).

**Input.**

```json
{"run":"<32hex>","include_payloads":false,"include_integrity":false,
 "select":{"kind":["http_response"],"class":["tool_observation"],
           "status":[500],"seq":[3,7,9]},
 "offset":0,"limit":50}
```

**Rules.**

- Chain verification always runs over the **complete** run, never the filtered
  subset. Filtering happens after verification, on verified events only.
- `select` is an intersection of the named predicates; unknown keys are
  rejected.
- `status` filters inside `data.status` for HTTP events; ignored when the event
  has no status field.
- `offset`/`limit` page the filtered list; `events_total` / `events_omitted`
  report the filtered totals, and the unfiltered count is retained as
  `run_events`.
- `include_integrity` defaults to **false** in previews and **true** when
  `include_payloads` is true. When false, per-event `hash`/`cursor` are omitted;
  the run-level `hash`, `cursor` and `attribution` are always present.
- `evidence_verdict` continues to reference `seq` values, which remain visible
  in every mode, so dropping per-event hashes does not weaken verdicts.

**Acceptance.** A 199-event crawl run filtered to `status:[404]` returns exactly
the four 404 observations, `run_events=199`, and a payload under 2 KB.

---

## 9. P2.2 — `bbp-routes`: route-family reduction

**Problem.** 588 crawl candidates, ~198 of them template or constant noise,
hiding `/account/settings/*`, `/authorize/oauth`, `/dashboard/*`. The manual
sitemap reduction to 18 families was correct and should be programmable.

**Input.** `bbp-routes [--site DOMAIN] [--keep-locale] [--limit N|--all] FILE...`
accepts `bbp-urls` reports (`rows` arrays) or raw URL/hostname lists.

**Normalization** (ordered, applied to the path only; query names retained,
values never read):

1. Remove a leading locale segment matching `^[a-z]{2}(-[A-Za-z]{2})?$` or
   `[locale]`/`{locale}`/`:locale` unless `--keep-locale`.
2. Replace `[param]`, `{param}`, `:param`, `<param>` with `:param`.
3. Replace a full UUID, a 16+ hex segment, or an all-digit segment with `:id`.
4. Strip a trailing slash except for `/`.
5. Optional trailing `*` is dropped and the family marked `prefix:true`.
6. Case is preserved. No case folding and no dot-segment resolution.

**Output rows.** `[family, count, params, variants_shown, prefix]`, sorted by
count desc then family. `stats`: `candidates`, `accepted`, `rejected`,
`families`, `template_candidates`, `locale_collapsed`.

**Acceptance.** Fixture derived from the Whatnot shape: 588 candidates → ≤ 60
families; `/account/settings/change-password` and
`/account/settings/delete-account` remain distinct families (last segment is
not a parameter); `[locale]/dashboard` collapses into `/dashboard`.

---

## 10. P2.3 — `bbp-urls --site` (suffix match, no PSL)

**Problem.** `--host` is exact, so extracting first-party literals from captured
bodies required a hand-built 3.4 KB file. The unfiltered inventory contains
`w3.org`, `localhost`, and `http://a/` noise.

**Spec.** `--site DOMAIN` matches `host == domain` or `host` ends with
`.<domain>` on a label boundary. No public-suffix-list dependency; this is a
suffix match, documented as such, not an eTLD+1 computation. `--host` and
`--site` are mutually exclusive. A short built-in noise filter is **not**
added — `--site` is the mechanism.

**Acceptance.** Whatnot captured-content inventory filtered with
`--site whatnot.com` drops the `w3.org`, `localhost` and `a` entries and retains
`www.whatnot.com`, `help.whatnot.com`, and the `developers.*` literals.

---

## 11. P2.4 — Crawl queue export and bounded resume

**Problem.** 557 URLs were queued and discarded when the 32-page budget was
reached. The next bounded run re-fetches the same 32 pages.

**Spec.** Contract v2 `recon_urls` adds:

```json
"queue":[{"url":"https://www.whatnot.com/browse?x=1","origin":"https://www.whatnot.com","depth":1}]
```

bounded to 512 entries (configurable by `RECON_QUEUE_LIMIT`, max 2000). Input
adds `"queue":[...]` (max 512), each entry re-validated by `WebUrl::parse` and
the exact-origin rule before queueing; validated seeds still required. The
crawler spends its 32-page budget on queue entries first, then discovery.
`queue_omitted` reports entries dropped by the bound.

**Boundary.** Resume is not a cache: pages are re-fetched and re-recorded, and
the run's coverage object states `resumed_from_queue`.

**Acceptance.** Run A hits the page budget and emits 512 queue entries with
`queue_omitted=45`; run B consumes them first, records 32 new responses, and
does not re-request run A's pages within the same queue.

---

## 12. P3 — deferred items

| Item | Change | Acceptance |
|---|---|---|
| Metadata grouping (`bbp-http`) | `--group-metadata` groups body-less records by `(status, content_length, mime)`; identity `meta:<sha256>`, rows carry `equal_bodies:false`. Default off. | 5,000 httpx endpoints with repeated sign-in pages collapse to a handful of groups; the honesty flag is present on every grouped row. |
| `--since <run>` | Offline and recon tools may subtract a prior recorded set (`subdomains`, `urls`) and emit `new`/`gone`/`unchanged` counts plus the delta rows. | Re-running the same fixture yields `new=0`; adding one host yields `new=1`. |
| Negative results as success | `discover` with zero responses and `ports` with zero open/refused return exit 0 with `coverage.outcomes` populated; exit 2 is reserved for invalid input and audit failure. | An all-timeout fixture returns `{"rows":[],"coverage":{"outcomes":{"timed_out":8}}}` and exit 0. |

`--since` and metadata grouping are deliberately last: both change how a number
is interpreted, and the Whatnot run does not require them.

---

## 13. Test plan and fixtures

Each item needs: a unit test for the pure function, a behavioural test for the
exit/receipt contract, and an offline reconciliation test against a fixture.

**Fixtures are synthetic.** Recreate the Whatnot *shapes* (314 hosts, 588
candidates, 199-event crawl, 156/158 split) with reserved names and RFC 5737 /
`2001:db8::/32` addresses. Do not commit the real recon data, hostnames,
HackerOne alias, or journal exports into this repository.

The preserved Whatnot assets are used only as an external, local comparison for
output sizes; the comparison result is recorded as a number in `BENCHMARKS.md`,
not as a committed fixture.

**Contract tests to add.**

- exit 3 partial: rows present, `completeness=partial`, journal failure event
  carries the partial summary.
- contract v2: `total = shown + omitted` for every tool, CLI and MCP.
- scope: out-of-scope wins; CIDR check runs on resolved addresses; a
  group-writable scope file is refused; `scope_file_sha256` is recorded.
- required headers: no socket activity when the policy is unsatisfied.
- projection: filtered counts reconcile with the unfiltered `run_events`.
- routes: idempotent normalization; `/` never becomes an empty family.

`cargo test --locked` must stay green, and the four ignored subprocess fixtures
remain launched by their runner tests.

---

## 14. Rollout

1. P0.1 + P0.2 together (they both touch the result surface). Bump the contract
   to `v:2`, update `README.md` "Output contract", `RECON.md` "Workflow
   surface", and the MCP schema descriptions.
2. P1.1 adds `recon_resolve` as a seventh MCP tool; `dist/SHA256SUMS` and the
   omp profile need no structural change beyond the new binary.
3. P1.2/P1.3 add `RECON_SCOPE_DIR`, `RECON_REQUIRE_SCOPE`,
   `RECON_REQUIRED_HEADERS`. Breaking only for operators who set them.
4. P2 items are additive flags or fields. `bbp-routes` is a new offline binary
   and must obey the no-network rule.
5. Regenerate all checksums and record the new `--help` surfaces.

Versioning: `v:2` is a breaking result contract. Keep the v1 shape readable in
`evidence_read` only (journal events are unchanged), and state the break
prominently in `README.md`.

---

## 15. Non-goals

- POST/PUT/PATCH/DELETE, request bodies, cookies, `Authorization`, or
  per-request headers. The recon layer stays GET-only, unauthenticated, and
  operator-header-controlled. Nothing in this document changes that.
- Authorization guarantees. A scope file is operator policy, not proof of
  ownership or permission, and `--site`/`hosts` still "do not establish legal
  authorization or automatically inherit a bounty program's scope".
- JavaScript execution, SPA route rendering, redirect following, or browser
  automation.
- A public-suffix-list dependency, or automatic eTLD+1 inference.
- Adding Whatnot (or any target) data to this repository.
- Changing journal storage, the hash chain, or the model-verdict separation.
