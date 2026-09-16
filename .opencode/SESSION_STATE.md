# Session State — 2026-09-16 (save checkpoint)

## Current phase
Phase 0 — Diagnose & Repair: **COMPLETE**. Phase 1 — Architecture hardening: **COMPLETE** (1.3 ✓, 1.7 ✓, 1.4 ✓, 1.5 ✓, 1.6 ✓). Phase 2 — guardrails: **IN PROGRESS** (audit ✓, fixes ✓, tests ✓; commit follows).

## Completed this session
### Phase 0 (diagnose/repair) — COMPLETE
- ✅ Isolated harness timeout culprit: **katana** (`omega_recon_crawl`) hung 30s+ on dead host `http://127.0.0.1:1` (no `-timeout` CLI flag, adapter default 300s).
- ✅ Adapter fail-fast in `omega/recon/__init__.py`: Katana `-timeout <min(timeout*0.8,20)>` + per-request timeout (30); WhatWeb temp-file JSON output + per-request timeout (30); Gobuster (60), Nuclei (120 + `-timeout 5`), Nikto (120) timeout forwarding.
- ✅ `omega/mcp/__init__.py`: `timeout` param forwarding for recon_probe/portscan/fuzz/tech/crawl/subdomains.
- ✅ `tests/test_harness.py`: per-case progress + 300s harness ceiling + short adapter timeouts.
- ✅ Full suite: 278 passed, 1 known non-fatal collection warning.

### Phase 1.3 + 1.7 (error contract + audit logging) — COMPLETE
- ✅ `omega/core/errors.py`: `ErrorCode` StrEnum (`SCOPE_DENIED`, `TOOL_NOT_FOUND`, `NOT_FOUND`, `BINARY_MISSING`, `TIMEOUT`, `RATE_LIMITED`, `INVALID_ARGS`, `INTERNAL`); `ToolError`; `err()` → `json.dumps({"error": {"code","message","retryable"}})`; `@guarded_tool()` (wraps-preserving, JSONL audit `<base_dir>/audit.jsonl`, secret-key redaction).
- ✅ Wired into `omega/mcp/__init__.py`: 40/41 handlers decorated (skip `omega_audit_log`); `_scope_denial` raises `ToolError(SCOPE_DENIED)`; `"not found"` returns → `ToolError(NOT_FOUND)`.
- ✅ Tests updated to `err.get("code") == "SCOPE_DENIED"`. Suite: 278 passed. Ruff clean on new file.

### Phase 1.4 (subprocess hardening) — COMPLETE
- ✅ `omega/tools/__init__.py` base helpers added to `ToolAdapter`:
  - `_require_binary()` (raises `ToolError(BINARY_MISSING)`), `_binary_missing_hint()`, `_missing_binary_result()` (non-raising structured `ToolResult`), `_max_output_bytes()` (from config, default 2_000_000), `_run_failure()` (normalizes `(stdout,stderr,rc,duration)` → error string), `_binary_missing_run()`.
  - Hardened `_run_subprocess`/`_run_subprocess_with_input`: binary pre-check (rc 127 + hint), `TimeoutError` → rc -1 + timed-out stderr, output capped.
- ✅ `omega/recon/__init__.py`: all 14 adapters migrated to `_missing_binary_result()` + `_run_failure(...)` + `max_output_bytes`. WhatWeb temp-file flow rewritten. ffuf rc==1 tolerated.
- ✅ 15 phase14 tests; full suite 293 passed.

### Phase 1.5 (concurrency / rate limiting) — COMPLETE
- ✅ NEW `omega/core/concurrency.py`:
  - `AsyncTokenBucket` — awaitable token bucket; `acquire(timeout)->bool` sleeps until a token refills or the wait exceeds `timeout`; starts full at `burst`.
  - `WorkerPool` — process-wide `asyncio.Semaphore` with `async with pool.run():` contextmanager (reusable across loops).
  - Module singletons `get_worker_pool()` (sized from `RateLimitConfig.max_concurrent`), `tool_bucket(name)` (per-tool, from `per_tool_rps`/`burst_size`), `reset_concurrency()` for tests; all config created lazily (no import cycle).
- ✅ `RateLimitConfig` extended: `enabled` (default True), `wait_seconds` (30); `from_env` now reads `OMEGA_RATE_LIMIT`, `OMEGA_TOOL_RPS`, `OMEGA_MAX_CONCURRENT`, `OMEGA_BURST`, `OMEGA_RATE_WAIT`. Removed unused `typing.Any` import.
- ✅ Base runners now: `_rate_limit_acquire()` (per-tool token wait; fails-open with log on config error) then `async with get_worker_pool().run():` around the shared `_spawn()` core. `_run_failure` maps `rc==-1` + "rate limit exceeded" → `RATE_LIMITED`.
- ✅ `ToolExecutor` exposes `self.pool` (public API). Deliberately does NOT wrap `adapter.execute` in the pool — nesting the same semaphore deadlocks at `max_concurrent=1`.
- ✅ NEW `tests/test_phase15_concurrency.py` (16 tests): bucket burst/block/refill/zero-rps/wait, pool concurrency bound, shared singletons + config sizing, adapter throttled (depleted bucket → rc -1 RATE_LIMITED stderr), adapter proceeds with tokens, `_run_failure` RATE_LIMITED mapping, disabled config bypasses throttling.
- ✅ **Full suite: 309 passed** (293 + 16 new), same 1 warning. Ruff: no new violations vs baseline (S101/S314/E501 pre-existing).

### Phase 1.6 (recon output caching) — COMPLETE
- ✅ NEW `omega/core/cache.py`:
  - `ReconCache` — SQLite (`recon_cache.db` under `base_dir`) read-through cache, one table `recon_cache(key PK, tool, cmd, input_hash, stdout, stderr, rc, stored_at)`; short-lived per-op connections (event-loop-safe for MCP stdio + pytest); `asyncio.Lock` serializes ops; wall-clock `time.time()` timestamps so entries survive process restarts.
  - `cache_key(tool, cmd, input_data)` — content-addressed SHA-256 over `{tool, cmd, input-hash}`; `ttl_for(tool)` reads `ToolConfig.cache_ttl_seconds`; `set_cache_path()`/`get_cache_path()`.
  - `cache_get`/`cache_put` module helpers — failures (rc≠0) never stored; all cache errors swallowed (fail-open to a real run).
- ✅ `ToolConfig.cache_ttl_seconds: float = 0` (opt-in; 0 = off) added to config.
- ✅ Base runners (`_run_subprocess`/`_run_subprocess_with_input`): when TTL>0, check cache before rate-limit/wait, and `cache_put` successful runs after `_spawn`. Input-sensitive keying for stdin-fed tools (sqlmap/JtR).
- ✅ NEW `tests/test_phase16_cache.py` (14 tests): key determinism + input sensitivity, TTL resolution (default/per-tool), put/get roundtrip, staleness, failing runs not stored, zero-TTL no read, clear-by-tool/total, adapter integration (2nd identical call spawns once; failures re-spawn; disabled default re-spawns; expired TTL re-spawns; different stdin → distinct entries).
- ✅ **Full suite: 323 passed** (278 + 15 phase14 + 16 phase15 + 14 phase16), same 1 warning. Ruff: no new violations.

## In progress (exact stopping point)
- Phase 2 (guardrails) implementation complete: scope-gating audit done, multi-target bypass closed, `omega_scan` gated, authorization metadata added to findings/reports, 10 regression tests written. 333 green. This checkpoint commit pending.
- Remaining Phase 2: audit `omega/web`/`api`/`http`/`pwn` modules for scope bypasses (light follow-up), document no-autonomous-exploitation / no-brute-force / no-DoS posture in README.

## Next steps (ordered)
1. **Commit this checkpoint** (`git -c user.name='lax' -c user.email='lax@localhost' commit -m "wip: checkpoint 2026-09-16"`).
2. **Phase 2 follow-up**: audit `omega/web`, `omega/api`, `omega/http`, `omega/pwn` modules for live-target paths that bypass scope gating; document no-autonomous-exploitation / no brute-force / no-DoS posture (README).
3. **Phase 3 feature modules**: recon/OSINT consolidation, vuln detection, reporting polish, CTF toolkit.
4. **Phase 4 quality bar**: README external-binaries matrix, `health_check` MCP tool.

## Known issues / blockers
- `tests/fixtures.py:167` `TestServer` has `__init__` → PytestCollectionWarning (non-fatal).
- `test_core.py::TestScope::test_rate_limiting` is a no-op assertion (covered by phase0 regressions).
- Full suite takes ~2.6 min (real harness MCP subprocess + integration suite); bash default 120s timeout too short — use ≥300s.
- Remaining ruff debt is pre-existing: `S101` asserts in tests, `S314` xml parse (`NmapAdapter`), `E501` long lines in recon normalize methods, `S108` `/tmp/omega-sandbox` default in `ExecutionConfig`.

### Phase 2 (guardrails) — IN PROGRESS
- ✅ Scope-gating audit of all 41 MCP tools + agent paths: every handler gates via `_scope_denial`; `omega_scan` added handler-level gate (risk active unless scan_type=="recon").
- ✅ Closed multi-target scope bypass: `omega_recon_probe` now authorizes EVERY newline-separated target; `ToolExecutor.execute` authorizes + rate-limits every entry in `parameters["targets"]` (covers agent `httpx` path). Fixed latent `.value` bug → `risk_str = str(cap.risk_level)`.
- ✅ Analysis-only engagement + passive tool always allowed in `_scope_denial` (observation-only posture; preserves `test_orchestrator_scan_analysis_only`).
- ✅ `Finding` schema + `findings` table gained `authorization_status` (authorized|not_in_scope|unverified), `authorization_basis`, `authorization_mode`, `authorization_id`; `FindingEngine(db, scope=None)` stamps them at creation by `authorize_target(affected_asset)`; SQLite ALTER migration added.
- ✅ `ReportEngine` markdown shows "## Scope & Authorization" + per-finding Authorization/Basis lines; JSON gains `authorization_summary` counts.
- ✅ NEW `tests/test_phase2_guardrails.py` (10 tests): MCP recon_probe multi-target deny, scan analysis_only/deny-by-default, executor multi-target deny/allow, finding authorized/not_in_scope/unverified stamping, report markdown/json authorization content.
- ✅ **Full suite: 333 passed** (323 + 10 phase2), same 1 warning. Ruff: no new violations vs baseline.

## Test status
- Passing: full suite `333` (278 base/phase0 + 15 phase14 + 16 phase15 + 14 phase16 + 10 phase2).
- Failing: none.

## Notes/decisions made this session
- Multi-target hardening lives at two layers: MCP handler (`recon_probe` per-target `_scope_denial`) AND `ToolExecutor.execute` (agent/sub-target path). Handler adapters call `adapter.execute` directly (bypass executor), so both layers needed.
- `FindingEngine.scope` is optional (default None → findings remain `unverified`); passing scope enables attestation. This kept all existing `FindingEngine(db)` fixtures/behavior intact.
- Phase 2 recap: `_scope_denial` short-circuits for `analysis_only`+`passive`; active scans denied by mode; no-rules engagements deny (except CTF/exclusion-only flows in `authorize_target`).
- Caching is opt-in per tool (`cache_ttl_seconds`, default 0) so existing 278-test baseline is untouched; infrastructure is in place and proven by phase16 tests.
- Cache lives at the subprocess boundary keyed on `(tool, cmd, input-hash)`, NOT on normalized outputs — uniform across all 14 adapters with zero adapter changes. Only rc=0 runs cached; synthetic duration 0 for hits.
- Wall-clock (`time.time()`) timestamps for persisted TTLs (monotonic resets between processes would otherwise invalidate/wrongly-validate entries).
- Phase 1.5 recap: pool + per-tool token bucket in `_run_subprocess*`; `AsyncTokenBucket.acquire(timeout)`; `WorkerPool`; `ToolExecutor.pool` exposed (no nesting to avoid `max_concurrent=1` deadlock); `RateLimitConfig` gained `enabled`, `wait_seconds` (+envs `OMEGA_RATE_LIMIT`, `OMEGA_TOOL_RPS`, `OMEGA_MAX_CONCURRENT`, `OMEGA_BURST`, `OMEGA_RATE_WAIT`).
- Git identity NOT configured globally: always commit with `-c user.name/-c user.email = lax/lax@localhost`.
- Next session: "continue"/"resume" → read this file, 2–3 line recap, proceed to Next steps without asking. "stop"/"pause" → update this file + commit checkpoint.

## Repo state
- Branch: `master`
- Last committed: (this checkpoint — Phase 1.5) — run `git log --oneline -3`
- Changed/new this session:
  - NEW: `omega/core/errors.py`, `tests/test_phase14_subprocess.py`, `omega/core/concurrency.py`, `tests/test_phase15_concurrency.py`
  - CHANGED: `omega/mcp/__init__.py`, `omega/tools/__init__.py`, `omega/recon/__init__.py`, `omega/config/__init__.py`, `tests/test_phase0_regressions.py`, `.opencode/SESSION_STATE.md`