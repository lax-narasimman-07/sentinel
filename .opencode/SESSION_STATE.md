# Session State — 2026-09-17 (save checkpoint)

## Current phase
Phase 0 — Diagnose & Repair: **COMPLETE**. Phase 1 — Architecture hardening: **COMPLETE**. Phase 2 — guardrails + follow-up: **COMPLETE**. Phase 3 — feature modules: **COMPLETE** (first increment tool surface ✓, second increment vuln triage ✓, edge-hardening ✓). Phase 4 — quality bar: **COMPLETE** (health_check ✓, README matrix ✓). All planned work done.

## Completed this session
### Phase 3 second increment (vuln detection triage) — COMPLETE
- ✅ `OmegaServer._triage_nuclei_findings`: maps nuclei `parsed_output["findings"]` → `Finding` records (severity map, `[nuclei]` prefix, template ref link, `technical_details`, raw-text lines skipped).
- ✅ `OmegaServer._triage_nikto_findings`: maps nikto `vulnerabilities` → `Finding` records (OSVDB/CVE refs, severity heuristic, `[nikto]` prefix).
- ✅ Both no-op when `engagement_id` empty; `_run_recon` auto-triages for `tool_name in ("nuclei","nikto")` and returns `"triaged_findings"`. Dedup + authorization stamping via `FindingEngine.create_finding`. 7 new tests.

### Phase 3 leftover — web/API engine edge hardening — COMPLETE
- ✅ `omega/web/__init__.py`:
  - `normalize_target_url` rejects non-http(s)/ws(s) schemes (`javascript:`, `data:`, `file:`, ...) via `_DANGEROUS_SCHEMES` + `_ANY_SCHEME`.
  - `analyze_cors` guards `parsed.hostname is None` (malformed URLs no longer produce `None.evil.com` origins).
  - `extract_endpoints` strips surrounding quotes (`["\'](https?://[^"\']+)["\']`), captures ws(s) URLs, and drops bare-keyword hints (`graphql`, `swagger`, `openapi.json`, ...) that previously fabricated bogus endpoints.
  - `analyze_javascript` no longer emits `null` findings entries.
  - `analyze_jwt` now: redacts full tokens to `token_preview` (never serializes credentials — matches the `secrets.value_preview` pattern), fixes `exp` check to `time.time()` (was hardcoded year-2001 threshold), logs decode failures, and moved `import base64` to module level.
  - `full_scan` no longer re-fetches the body — `analyze_headers` returns `body` and `extract_endpoints` reuses it (one fewer network call, consistent content).
- ✅ `omega/api/__init__.py`:
  - `full_scan` adopts WebSecurityEngine's `_safe()` component isolation: partial results + `scan_errors` + `success` (previously one failure killed the whole scan).
  - `infer_endpoints` is bounded: `asyncio.Semaphore` concurrency (clamped ≤16) + `asyncio.wait_for` overall deadline (default 60s) + per-request timeout (8s) — worst-case 96 sequential probes can no longer stall for minutes.
  - `discover_openapi` returns `paths_count`/`spec_size` and caps spec paths (>500 → `_truncated`); `discover_graphql` tolerates non-list `types` and drops `__*` types.
  - `test_idor` validates `{id}`/`:id` placeholder (returns structured error instead of sending 3 identical requests) + timeout.
  - `analyze_graphql_introspection` uses `.get("name")` so one malformed type no longer discards the whole result.
  - All `except Exception: pass` blocks now log (`logger.debug`/`warning`).
  - WebSocket handler replies with structured `{type:"error"}` on `JSONDecodeError` and logs other failures (no more silent swallow).
  - `broadcast_event` bounds `findings`/`engagements`/`evidence` at 500 like `logs` (unbounded growth fixed).
  - Removed duplicate `import asyncio` / unused `import traceback`.
- ✅ 19 new tests: `tests/test_phase17_engine_hardening.py` (offset scheme tests, FakeHTTP-based JWT redaction/expiry, extract_endpoints quote/hint behavior, JS findings, single-fetch full_scan, OpenAPI summary/cap, GraphQL malformed-type tolerance, IDOR placeholder validation, API full_scan isolation, broadcast bounds).

### Phase 4 (quality bar) — COMPLETE
- ✅ MCP tool `omega_health_check` (guarded, read-only): DB/registry/cache/worker-pool → `ready|degraded`. 1 harness case + 1 test.
- ✅ README external-binaries matrix + "Vulnerability Triage" bullet + "60+ MCP Tools".

### Housekeeping — COMPLETE
- ✅ `tests/fixtures.py::TestServer` now sets `__test__ = False` — eliminates the `PytestCollectionWarning` (previously re-collected from every phase test file).
- ✅ `test_core.py::TestScope::test_rate_limiting` is now a real assertion: STEALTH (rps 1 / burst 3) → first 3 calls allowed, 4th/5th denied (replaces the `allowed or not allowed` no-op).

## In progress (exact stopping point)
- Everything planned in SESSION_STATE is complete and verified: **376 green** (374 non-harness + 2 harness). Uncommitted.

## Next steps (ordered)
1. **Commit this checkpoint** (`git -c user.name='lax' -c user.email='lax@localhost' commit -m "wip: checkpoint 2026-09-17"`).
2. Optional/future (not planned): `L6` from audit — degrade gracefully instead of warning when `omega.api.routes` fails to import (deliberately left as fail-safe); `L3` redundant CORS probe in `analyze_authentication`; REST/parse surface parity with MCP tool surface.

## Known issues / blockers
- `test_core.py::TestScope::test_rate_limiting` real assertion added (resolved the no-op note).
- Full suite takes ~2.5–3.5 min (real harness MCP subprocess + integration suite); bash default 120s timeout too short — use ≥300s.
- Remaining ruff debt is pre-existing: `S101` asserts in tests + `assert orch` handlers, `S314` xml parse (`NmapAdapter`), `E501` long lines (recon normalize, MCP tool `ToolAnnotations`/assert blocks, reporting signatures), `S108` `/tmp/omega-sandbox` default in `ExecutionConfig`, `B007/B904/B905/C401`, `S110/S608/S105`, `SIM102/SIM105/SIM118`, `UP017/UP035/UP041/UP042`, `TC001`, `A002`. No NEW categories added (ruff-category set verified identical vs baseline; S101 count grew only by the new test file's asserts).

## Test status
- Passing: full suite `376` (374 non-harness incl. 19 phase17 hardening + 15 phase3 triage + health_check; 2 harness MCP).
- Failing: none.

## Notes/decisions made this session
- **JWT redaction**: full JWTs are never serialized to MCP output; only `token_preview` (16 chars + "…") is returned. Decoding still happens internally on the full token before redaction. Matches the existing `secrets.value_preview` pattern and the audit-log secret-redaction posture.
- **infer_endpoints bounds**: concurrency clamped to `[1, 16]`, overall deadline default 60s, per-request 8s. This bounds a hostile/hanging host without changing default results for healthy targets.
- **API `full_scan` now mirrors web `full_scan`**: `{"target", "success", "scan_errors", openapi/graphql/auth/endpoints}` — component-isolated partial results instead of all-or-nothing.
- **broadcast_event bounded at 500** per list (findings/engagements/evidence now capped like logs) to prevent unbounded dashboard memory growth.
- **`__test__ = False` on `TestServer`** is the canonical pytest opt-out for helper classes in `fixtures.py` — removes the long-standing collection warning.

## Repo state
- Branch: `master`
- Last committed: `910d6e4` (Phase 3 second increment + Phase 4 checkpoint). Edge hardening + housekeeping uncommitted.
- Changed/new this session:
  - CHANGED: `omega/web/__init__.py` (scheme validation, CORS/endpoint/JS fixes, JWT redaction+expiry, single-fetch full_scan)
  - CHANGED: `omega/api/__init__.py` (full_scan isolation, bounded infer_endpoints, OpenAPI/GraphQL robustness, IDOR validation, logging, WS/broadcast fixes)
  - NEW: `tests/test_phase17_engine_hardening.py` (19 tests)
  - CHANGED: `tests/fixtures.py` (`__test__ = False`), `tests/test_core.py` (real rate-limit assertion)
  - CHANGED: `.opencode/SESSION_STATE.md`