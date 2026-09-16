# Session State — 2026-09-16 (save checkpoint)

## Current phase
Phase 0 — Diagnose & Repair: **COMPLETE** (all 278 tests green). Phase 1 — Architecture hardening: just started (no code written yet).

## Completed this session
- ✅ Isolated harness timeout culprit: **katana** (`omega_recon_crawl`) hung 30s+ on dead host `http://127.0.0.1:1` (no `-timeout` CLI flag, adapter default 300s).
- ✅ Fixed adapter fail-fast behavior in `omega/recon/__init__.py`:
  - KatanaAdapter: added `-timeout <min(timeout*0.8,20)>` CLI flag + per-request timeout (default 30).
  - WhatWebAdapter: replaced `/dev/stdout` log path (whatweb cannot write there) with a temp JSON file; per-request timeout (default 30); graceful read of temp file.
  - GobusterAdapter (60s), NucleiAdapter (120s + `-timeout 5`), NiktoAdapter (120s): per-request timeout forwarding.
- ✅ `omega/mcp/__init__.py`: added `timeout` param forwarding to recon tools — `recon_probe`, `recon_portscan`, `recon_fuzz`, `recon_tech`, `recon_crawl`, `recon_subdomains`.
- ✅ `tests/test_harness.py`: per-case progress + overall 300s harness ceiling + short adapter-level timeouts → deterministic.
- ✅ Fixed `tests/test_phase0_regressions.py::test_scope_gated_tools_allow_after_include_rule`: assertion `"Scope denied" not in data.get("error","")` failed because probe returns `"error": null` on success → changed to `(data.get("error") or "")`.
- ✅ **Full suite: 278 passed** (262 base + 14 phase0 regressions + 2 harness), 1 known non-fatal collection warning.

## In progress (exact stopping point)
- **Phase 1 has NOT been coded yet.** I just finished reading `omega/mcp/__init__.py` (the `OmegaServer` class + `_register_tools`) and located the MCP SDK source at `.venv/lib/python3.13/site-packages/mcp/server/mcpserver/server.py` to understand how `@mcp.tool()` derives the input schema from handler function signatures (for safe wrapping). No design/implementation decisions were made beyond that.

## Next steps (ordered)
1. Read `.venv/lib/python3.13/site-packages/mcp/server/mcpserver/server.py` — confirm how the `tool()` decorator builds `inputSchema` (inspect.signature? follows `__wrapped__`?), so a wrapper decorator preserves schema extraction.
2. **Phase 1.3 Uniform error contract**: create `omega/core/errors.py`:
   - `ErrorCode` enum: `SCOPE_DENIED`, `TOOL_NOT_FOUND`, `BINARY_MISSING`, `TIMEOUT`, `RATE_LIMITED`, `INVALID_ARGS`, `INTERNAL`.
   - `err(code, message, retryable) -> str` returning `json.dumps({"error": {"code", "message", "retryable"}})`.
   - A `@guarded_tool` decorator capturing exceptions → `INTERNAL` error (keep signature via `functools.wraps`).
   - Apply it around every tool handler (double decoration: `@mcp.tool(...)` outer, `@guarded_tool` inner, or wrap inside `_register_tools`).
3. **Phase 1.7 Structured invocation logging**: append-only JSONL audit file `{timestamp, tool, target, args, outcome}` — hook into same wrapper; make `omega_audit_log` read it. Discover where config stores base dir (`OMEGA_BASE_DIR`, `config/__init__.py`).
4. **Phase 1.4 Subprocess hardening**: consolidate all adapters on shared `_run_subprocess_with_input` (`omega/tools/__init__.py`); ensure max output cap + stderr→structured error on nonzero rc everywhere.
5. **Phase 1.5 Concurrency / rate limiting**: verify per-target active-tool limits; add global worker pool / semaphore for concurrent scans.
6. **Phase 1.6 Caching**: cache recon outputs in SQLite keyed by target+timestamp.
7. **Phase 2 guardrails**: audit active tools for scope gating; add authorization metadata to findings/reports.
8. Phase 3 feature modules + Phase 4 (README binaries matrix, `health_check` tool).

## Known issues / blockers
- `tests/fixtures.py:167` `TestServer` has `__init__` → PytestCollectionWarning (non-fatal).
- `test_core.py::TestScope::test_rate_limiting` is a no-op assertion (covered by phase0 regressions).
- Note: full suite takes ~2.5 min (harness boots real MCP server subprocess twice + big integration suite).

## Test status
- Passing: full suite `278` (262 base + 14 phase0 regressions + 2 harness).
- Failing: none.
- Not yet run: Phase 1+ tests (to be written).

## Notes/decisions made this session
- Fail-fast philosophy: adapter-level timeout defaults must be well under the CLI tool's own internal timeout so the shared subprocess async timeout fires first with a structured error, never a client-side hang.
- whatweb cannot use `--log-json=/dev/stdout`; temp file is the reliable approach.
- Harness passes short `timeout` args for offline-safe, deterministic sweeps.
- Next session: if user types just "continue", read this file and proceed to `Next steps` (item 1 onward) without asking.

## Repo state
- Branch: `master`
- Last commit: `95fc105` — "wip: checkpoint 2026-09-15"
- Uncommitted changes this session (to be committed as `wip: checkpoint 2026-09-16`): `omega/recon/__init__.py`, `omega/mcp/__init__.py`, `tests/test_harness.py`, `tests/test_phase0_regressions.py`, `.opencode/SESSION_STATE.md`.