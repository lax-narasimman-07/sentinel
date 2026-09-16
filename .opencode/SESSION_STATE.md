# Session State — 2026-09-16 (save checkpoint)

## Current phase
Phase 0 — Diagnose & Repair: **COMPLETE**. Phase 1 — Architecture hardening: **COMPLETE** (1.3 ✓, 1.7 ✓, 1.4 ✓, 1.5 ✓, 1.6 ✓). Phase 2 — guardrails + follow-up: **COMPLETE**. Phase 3 — feature modules, first increment (tool surface): **COMPLETE**.

## Completed this session
### Phase 0 (diagnose/repair) — COMPLETE
- ✅ Isolated harness timeout culprit: **katana** (`omega_recon_crawl`) hung 30s+ on dead host `http://127.0.0.1:1` (no `-timeout` CLI flag, adapter default 300s).
- ✅ Adapter fail-fast in `omega/recon/__init__.py`: Katana `-timeout <min(timeout*0.8,20)>` + per-request timeout (30); WhatWeb temp-file JSON output + per-request timeout (30); Gobuster (60), Nuclei (120 + `-timeout 5`), Nikto (120) timeout forwarding.
- ✅ `omega/mcp/__init__.py`: `timeout` param forwarding for recon_probe/portscan/fuzz/tech/crawl/subdomains.
- ✅ `tests/test_harness.py`: per-case progress + harness ceiling + short adapter timeouts.
- ✅ Full suite: 278 passed, 1 known non-fatal collection warning.

### Phase 1.3 + 1.7 (error contract + audit logging) — COMPLETE
- ✅ `omega/core/errors.py`: `ErrorCode` StrEnum (`SCOPE_DENIED`, `TOOL_NOT_FOUND`, `NOT_FOUND`, `BINARY_MISSING`, `TIMEOUT`, `RATE_LIMITED`, `INVALID_ARGS`, `INTERNAL`); `ToolError`; `err()` → `json.dumps({"error": {"code","message","retryable"}})`; `@guarded_tool()` (wraps-preserving, JSONL audit `<base_dir>/audit.jsonl`, secret-key redaction).
- ✅ Wired into `omega/mcp/__init__.py`: 40/41 handlers decorated (skip `omega_audit_log`); `_scope_denial` raises `ToolError(SCOPE_DENIED)`; `"not found"` returns → `ToolError(NOT_FOUND)`.
- ✅ Tests updated to `err.get("code") == "SCOPE_DENIED"`. Suite: 278 passed.

### Phase 1.4 (subprocess hardening) — COMPLETE
- ✅ `omega/tools/__init__.py` base helpers: `_require_binary()`, `_binary_missing_hint()`, `_missing_binary_result()`, `_max_output_bytes()`, `_run_failure()`, `_binary_missing_run()`; hardened `_run_subprocess`/`_run_subprocess_with_input` (rc 127 + hint, TimeoutError → rc -1, output capped).
- ✅ `omega/recon/__init__.py`: all 14 adapters migrated. 15 phase14 tests; full suite 293 passed.

### Phase 1.5 (concurrency / rate limiting) — COMPLETE
- ✅ `omega/core/concurrency.py`: `AsyncTokenBucket`, `WorkerPool`, module singletons `get_worker_pool()`/`tool_bucket()`/`reset_concurrency()`.
- ✅ `RateLimitConfig` extended: `enabled`, `wait_seconds` (+ envs). Base runners: `_rate_limit_acquire()` then `async with get_worker_pool().run():`. `ToolExecutor` exposes `self.pool`.
- ✅ 16 phase15 tests; **full suite 309 passed**.

### Phase 1.6 (recon output caching) — COMPLETE
- ✅ `omega/core/cache.py`: `ReconCache` (SQLite, read-through, wall-clock TTL, event-loop-safe, fail-open); `cache_key`/`ttl_for`/`cache_get`/`cache_put`; `ToolConfig.cache_ttl_seconds` (opt-in, default 0).
- ✅ Base runners cache successful runs at the subprocess boundary keyed on `(tool, cmd, input-hash)`. 14 phase16 tests; **full suite 323 passed**.

### Phase 2 (guardrails + follow-up) — COMPLETE
- ✅ All 41 MCP tools + agent paths gate via `_scope_denial`; multi-target bypass closed in `recon_probe` and `ToolExecutor.execute`; `.value` bug fixed.
- ✅ Findings/report authorization metadata (`authorization_status/basis/mode/id`, "## Scope & Authorization", `authorization_summary`); SQLite ALTER migration.
- ✅ REST API layer `_gate()` on all 15 live-target routes (web/api-security/http/auth-diff-test); README "Security Authorization Model" section; 9 API gate tests.
- ✅ **Full suite: 342 passed**.

### Phase 3 — Feature modules, first increment (tool surface) — COMPLETE
- ✅ `Orchestrator` gained lazy `self.api` property → `APISecurityEngine` (avoids importing FastAPI dashboard surface at core startup; `omega.api.__init__` pulls fastapi at module load).
- ✅ 20 new MCP tools, all `_scope_denial`-gated + `@guarded_tool()`:
  - Web (2): `omega_web_jwt`, `omega_web_tech` (passive).
  - API security (6): `omega_api_openapi`, `omega_api_graphql`, `omega_api_auth`, `omega_api_introspection` (passive); `omega_api_idor`, `omega_api_full_scan` (active).
  - Recon (8, orphans now exposed): `omega_recon_vuln_scan` (nuclei, active), `omega_recon_server_audit` (nikto, active), `omega_recon_dirbrute` (gobuster, active), `omega_recon_port_rapid` (masscan, active), `omega_recon_fastportscan` (naabu, active, binary missing), `omega_recon_webcrawl` (gospider, passive), `omega_recon_dns_lookup` (dnsx, passive, binary missing), `omega_recon_waf_detect` (wafw00f, passive, binary missing).
  - CTF (4): `omega_ctf_resolve_hypothesis`, `omega_ctf_add_note`, `omega_ctf_add_artifact`, `omega_ctf_hypothesis_ledger`.
- ✅ DRY helper `OmegaServer._run_recon(...)`: scope gate → execute → on success+engagement store evidence (`evidence.store_tool_output`) + best-effort asset ingestion (`db.save_asset` for each `normalized_output["assets"]`); returns `{"success","result","assets","error","duration_ms"}`.
- ✅ Reporting polish: `ReportEngine` now pulls `db.get_hypotheses` and emits "## Hypotheses" (active/succeeded/failed + success rate) in markdown, hypothesis list in JSON, md pipeline in HTML.
- ✅ NEW `tests/test_phase3_tools.py` (8 tests): registration, active-tool deny-by-default (pentest no-rules), active-tool deny (analysis_only), passive-tool permitted (analysis_only), missing-binary structured error, CTF hypothesis lifecycle, report includes hypotheses (md + JSON), orch.api lazy wiring vs live TestServer.
- ✅ Harness sweep extended to ~60 tools (20 new cases incl. CTF bogus-id structured responses); harness ceiling 300→420s.
- ✅ **Full suite: 350 passed** (342 + 8), same 1 warning (+ new file re-collects TestServer warning, same fixture pattern). Ruff: no new violation categories vs baseline.

## In progress (exact stopping point)
- Phase 3 first increment COMPLETE and verified (350 green). This checkpoint pending commit.
- Remaining Phase 3 items (next session): vuln-triage (nuclei/nikto findings → `Finding` mapping), report polish refinements if needed, web/API engine edge-case hardening, README feature/tool-surface refresh.

## Next steps (ordered)
1. **Commit this checkpoint** (`git -c user.name='lax' -c user.email='lax@localhost' commit -m "wip: checkpoint 2026-09-16"`).
2. **Phase 3 second increment**: vuln detection triage — map nuclei/nikto `parsed_output` findings/vulnerabilities to `FindingEngine` records (with authorization stamping via scope); optionally `WebSecurityEngine`/`APISecurityEngine` edge hardening.
3. **Phase 4 quality bar**: README external-binaries matrix, `health_check` MCP tool.

## Known issues / blockers
- `tests/fixtures.py:167` `TestServer` has `__init__` → PytestCollectionWarning (non-fatal, now also re-collected from `test_phase3_tools.py`).
- `test_core.py::TestScope::test_rate_limiting` is a no-op assertion (covered by phase0 regressions).
- Full suite takes ~3.3 min (real harness MCP subprocess + integration suite + 8 new phase3 tests); bash default 120s timeout too short — use ≥300s.
- Remaining ruff debt is pre-existing: `S101` asserts in tests, `S314` xml parse (`NmapAdapter`), `E501` long lines (recon normalize, MCP tool `ToolAnnotations`/assert blocks, reporting signatures), `S108` `/tmp/omega-sandbox` default in `ExecutionConfig`, `B007/B904/I001` in `test_harness.py`.

## Test status
- Passing: full suite `350` (278 base/phase0 + 15 phase14 + 16 phase15 + 14 phase16 + 10 phase2 + 9 api-gate + 8 phase3).
- Failing: none.

## Notes/decisions made this session
- **API engine wiring is lazy** (`Orchestrator.api` property, cached `self._api`): `omega/api/__init__.py` imports FastAPI at module load, so eager import would couple the core MCP server to FastAPI. Lazy import keeps `Orchestrator(db)` construction FastAPI-free while still exposing `orch.api.*`.
- **Generic recon helper** (`_run_recon`) used only for the 8 NEW recon tools; existing 6 recon handlers left untouched to avoid regressions. Evidence + asset ingestion happen only when `engagement_id` present and run succeeded.
- New recon MCP `tool_name` values ("nuclei", "nikto", ...) match adapter `version()`/registry capability names so audit log + `omega_tools_list` stay consistent.
- Passive new tools (gospider/dnsx/wafw00f/web analytics/API discovery) correctly permitted under `analysis_only` — matches the established observation-only posture.
- Test `successful` bool argument accepted by harness as a real bool (wrapped tuple to keep <120 char).
- `NaabuAdapter`/`DnsxAdapter`/`WafW00fAdapter` are NOT installed → open-world calls return clean structured `BINARY_MISSING`, satisfying the harness robustness contract.

## Repo state
- Branch: `master`
- Last committed: `67533c0` (Phase 2 follow-up REST gate). Phase 3 first increment uncommitted.
- Changed/new this session:
  - NEW: `tests/test_phase3_tools.py`
  - CHANGED: `omega/agents/__init__.py` (lazy `orch.api`), `omega/mcp/__init__.py` (+20 tools, `_run_recon` helper), `omega/reporting/__init__.py` (hypotheses in reports), `tests/test_harness.py` (+20 cases, ceiling 420s), `.opencode/SESSION_STATE.md`