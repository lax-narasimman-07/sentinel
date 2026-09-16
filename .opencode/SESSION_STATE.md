# Session State — 2026-09-16 (save checkpoint)

## Current phase
Phase 0 — Diagnose & Repair: **COMPLETE**. Phase 1 — Architecture hardening: **in progress** (1.3 ✓, 1.7 ✓, 1.4 ✓; 1.5/1.6 next).

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
  - `_require_binary()` (raises `ToolError(BINARY_MISSING)`), `_binary_missing_hint()`, `_missing_binary_result()` (non-raising structured `ToolResult`), `_max_output_bytes()` (from config, default 2_000_000), `_run_failure()` (normalizes `(stdout,stderr,rc,duration)` → error string: rc 0 → None; rc -1+timeout → `TIMEOUT:`; rc 127 → `BINARY_MISSING:`; else `INTERNAL:`; truncates to 400 chars), `_binary_missing_run()` (detects a missing-executable outcome tuple).
  - Hardened `_run_subprocess`/`_run_subprocess_with_input`: pre-spawn binary existence check (rc 127 + install hint), `FileNotFoundError` → rc 127, `TimeoutError` → rc -1 + "…timed out after {t}s" (kill via `contextlib.suppress`), output capped at `max_output_bytes`.
- ✅ `omega/recon/__init__.py`: all 14 adapters (subfinder, httpx, nmap, ffuf, whatweb, gobuster, katana, nuclei, nikto, naabu, wafw00f, gospider, dnsx, masscan) migrated to `self._missing_binary_result()` + `self._run_failure(...)` + `max_output_bytes=self._max_output_bytes()`. WhatWeb temp-file flow rewritten (no longer swallows failures). ffuf rc==1 → success (completed, no matches). Removed dead `mode` var + unused imports (asyncio/shutil/time).
- ✅ Cleaned lint in touched code: `contextlib.suppress` over try/except/pass, builtin `TimeoutError`, `ScopeEngine`/`Database` → `TYPE_CHECKING` block, removed `_find_binary`'s unused `cap`.
- ✅ NEW `tests/test_phase14_subprocess.py` (15 tests): install-hint result, `_require_binary` ToolError, base-runner rc 127 (name + abs path), `_binary_missing_run`, `_run_failure` mapping (success/nonzero/timeout/rc127), real-spawn output cap (1MB → 200 bytes), default 2MB cap, adapter timeout via monkeypatched runner, adapter missing-binary result, static migration checks (all 14 adapters use the 3 shared helpers; no `create_subprocess_shell`/`shell=True`/string-built commands).
- ✅ **Full suite: 293 passed** (278 + 15 new), same 1 warning. Ruff: no NEW violations vs baseline (remaining `S101`/`S314`/`E501` are pre-existing repo-wide debt).

## In progress (exact stopping point)
- Phase 1.4 done and verified (293 green, ruff baseline-clean). Not yet committed.

## Next steps (ordered)
1. **Commit checkpoint**: `git add -A && git commit -m "wip: checkpoint 2026-09-16"`.
2. **Phase 1.5 Concurrency / rate limiting**: verify per-target active-tool limits; add global worker pool/semaphore for concurrent scans (rate-limit config per tool; awaited Semaphore around `_run_subprocess*`; expose in `ToolExecutor`).
3. **Phase 1.6 Caching**: cache recon outputs in SQLite keyed by target+timestamp (respect `--no-cache`/staleness config).
4. **Phase 2 guardrails**: audit active tools for scope gating; authorization metadata on findings/reports; no autonomous exploitation / brute-force / DoS tooling.
5. **Phase 3 feature modules** + **Phase 4 quality bar** (README external-binaries matrix, `health_check` tool).

## Known issues / blockers
- `tests/fixtures.py:167` `TestServer` has `__init__` → PytestCollectionWarning (non-fatal).
- `test_core.py::TestScope::test_rate_limiting` is a no-op assertion (covered by phase0 regressions).
- Full suite takes ~2.7 min (real harness MCP subprocess + big integration suite); bash default 120s timeout is too short — use ≥300s.
- Remaining ruff debt is pre-existing: `S101` asserts in tests (636 repo-wide), `S314` xml parse (`NmapAdapter`, untouched), `E501` long lines in recon normalize methods (untouched) and elsewhere (e.g. `omega/mcp`).

## Test status
- Passing: full suite `293` (278 base/phase0 + 15 phase14). 
- Failing: none. Not yet run: Phase 1.5/1.6 tests (to be written).

## Notes/decisions made this session
- Fail-fast: adapter-level timeout defaults must be well under the CLI tool's internal timeout so the shared subprocess async timeout fires first.
- Binary-missing check lives INSIDE base `_run_subprocess*` (rc 127 tuple, not raised) — deliberately NOT at top of `adapter.execute()` so unit tests monkeypatching the runners never require real binaries. `_find_binary()` check in `execute()` remains a non-raising fast path returning `_missing_binary_result()`.
- Subprocess contract `(stdout, stderr, rc, duration_ms)` is stable; all monkeypatched `_run_subprocess`/`_run_subprocess_with_input` fakes must keep the 4-tuple shape.
- Error format: `{"error": {"code", "message", "retryable"}}` — backward compatible with harness assertions (`"error" in parsed`).
- `@guarded_tool` `functools.wraps` preserves MCP SDK `inspect.signature` → schema extraction (verified via 41-tool harness). `omega_audit_log` not decorated (audit-recursion guard).
- Next session: "continue"/"resume" → read this file, 2–3 line recap, proceed to Next steps without asking. "stop"/"pause" → update this file + commit checkpoint.

## Repo state
- Branch: `master`
- Last committed: `af3726a` — "wip: checkpoint 2026-09-16" (before Phase 1.3 work)
- Uncommitted changes this session (to be committed as updated checkpoint):
  - NEW: `omega/core/errors.py`, `tests/test_phase14_subprocess.py`
  - CHANGED: `omega/mcp/__init__.py`, `omega/tools/__init__.py`, `omega/recon/__init__.py`, `tests/test_phase0_regressions.py`