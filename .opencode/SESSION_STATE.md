# Session State — 2026-09-16 (save checkpoint)

## Current phase
Phase 0 — Diagnose & Repair: **COMPLETE**. Phase 1 — Architecture hardening: **in progress** (1.3 ✓, 1.7 ✓, 1.4 ✓, 1.5 ✓; 1.6 next).

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

## In progress (exact stopping point)
- Phase 1.5 done and verified (309 green, ruff baseline-clean). Committed as `wip: checkpoint 2026-09-16` (`4448bff` had 1.3/1.4; this commit adds 1.5).

## Next steps (ordered)
1. **Phase 1.6 Caching**: cache recon outputs in SQLite keyed by target+tool+params+timestamp; staleness window from config; `omit_cache`/`force` param; skip cache when `RateLimitPolicy`/mode demands fresh data; wire via a small cache layer used by adapters or the ToolExecutor.
2. **Phase 2 guardrails**: audit active tools for scope gating; authorization metadata (authorization basis, rules matched, risk level) on findings/reports; no autonomous exploitation / brute-force / DoS tooling.
3. **Phase 3 feature modules** + **Phase 4 quality bar** (README external-binaries matrix, `health_check` tool).

## Known issues / blockers
- `tests/fixtures.py:167` `TestServer` has `__init__` → PytestCollectionWarning (non-fatal).
- `test_core.py::TestScope::test_rate_limiting` is a no-op assertion (covered by phase0 regressions).
- Full suite takes ~2.7 min (real harness MCP subprocess + integration suite); bash default 120s timeout too short — use ≥300s.
- Remaining ruff debt is pre-existing: `S101` asserts in tests, `S314` xml parse (`NmapAdapter`), `E501` long lines in recon normalize methods, `S108` `/tmp/omega-sandbox` default in `ExecutionConfig`.

## Test status
- Passing: full suite `309` (278 base/phase0 + 15 phase14 + 16 phase15). 
- Failing: none. Not yet run: Phase 1.6 tests (to be written).

## Notes/decisions made this session
- Rate limiting design: token bucket lives at the adapter subprocess boundary (per-tool), NOT in MCP handlers, so direct adapter.execute() calls in Unit tests and the MCP path are throttled consistently. Per-target limits remain in `ScopeEngine.enforce_rate_limit` (per-engagement token bucket keyed per target; values hardcoded per policy: STEALTH 1rps/burst3, NORMAL 5/10, AGGRESSIVE 20/50).
- Global pool bounds only actual `_run_subprocess*` spawns (the real FD/process bottleneck). `WorkerPool` and per-tool buckets are lazily created from `get_config()` → no config/tools/recon import cycle.
- Nesting the SAME `WorkerPool` semaphore (executor-level wrap + subprocess-level wrap) deadlocks at `max_concurrent=1` — avoided by exposing `ToolExecutor.pool` instead of wrapping.
- AsyncTokenBucket has no await between refill and decrement → benign in the single-threaded event loop; waits happen only in `asyncio.sleep`/refill phases.
- Error format: `{"error": {"code", "message", "retryable"}}` — backward compatible with harness assertions.
- `@guarded_tool` `functools.wraps` preserves MCP SDK `inspect.signature` → schema extraction (verified via 41-tool harness). `omega_audit_log` not decorated (audit-recursion guard).
- Git identity is NOT configured: commit with `git -c user.name='lax' -c user.email='lax@localhost' commit …` (matches prior commits; no persistent config change).
- Next session: "continue"/"resume" → read this file, 2–3 line recap, proceed to Next steps without asking. "stop"/"pause" → update this file + commit checkpoint.

## Repo state
- Branch: `master`
- Last committed: (this checkpoint — Phase 1.5) — run `git log --oneline -3`
- Changed/new this session:
  - NEW: `omega/core/errors.py`, `tests/test_phase14_subprocess.py`, `omega/core/concurrency.py`, `tests/test_phase15_concurrency.py`
  - CHANGED: `omega/mcp/__init__.py`, `omega/tools/__init__.py`, `omega/recon/__init__.py`, `omega/config/__init__.py`, `tests/test_phase0_regressions.py`, `.opencode/SESSION_STATE.md`