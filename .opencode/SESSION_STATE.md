# Session State — 2026-09-15

## Current phase
Phase 0 — Diagnose & Repair (fixes done; per-tool harness sweep in progress)

## Completed this session
- ✅ Baseline: full suite runs green before changes — `262 passed` (92.65s).
- ✅ Phase 0 diagnosis: enumerated all **41 registered MCP tools** (engagement 3, scope 3, recon 6, web 6, http 1, orchestrated scan 1, graph 3, findings 7, evidence 1, ctf 6, report 1, tools_list/audit/doctor 3). Read every engine + adapter. Verified `mcp.server.mcpserver` / `mcp.types.ToolAnnotations` imports are valid in this SDK. Checked installed binaries (present: subfinder/amass/httpx/nmap/ffuf/gobuster/katana/whatweb/nuclei/exiftool/binwalk/strings/file; missing: sqlmap/hashcat/john/checksec).
- ✅ Confirmed latent bugs → all fixed:
  - `omega/recon/__init__.py` — **HttpxAdapter fed NO targets to httpx** (broken `omega_recon_probe`). Now builds `... -l /dev/stdin` and pipes targets via stdin.
  - `omega/recon/__init__.py` — removed duplicate `DnsxAdapter._run_subprocess_with_input` (now inherited).
  - `omega/tools/__init__.py` — added shared base `ToolAdapter._run_subprocess_with_input(cmd, input_data, timeout, max_output_bytes, env)`.
  - `omega/scope/__init__.py` — `RateLimiter` rewritten as time-aware token bucket (was: bucket never refilled → permanent hard lockout after burst; stray `burst :=` walrus removed; broken `refill()` removed). `import time` now module-level.
  - `omega/scope/__init__.py` — removed duplicated unreachable CTF `if mode == EngagementMode.CTF:` block in `authorize_target` (lines 126-136 old).
  - `omega/mcp/__init__.py` — added `OmegaServer._scope_denial(engagement_id, target, action, risk_level)` helper (full authorize pipeline; runs open-world when engagement_id empty). Wired into previously **ungated** tools: `recon_probe` (passive), `recon_fuzz` (active), `recon_tech` (passive), `recon_crawl` (passive), all six web tools (passive), `http_request` (active only for non-GET/HEAD/OPTIONS).
  - `omega/http/__init__.py` — `HTTPClient.request` now catches `httpx.HTTPError` (+ generic fallback) and returns a structured error dict (`status_code: 0`, `"error": "..."`) instead of raising — the unhandled-async-exception failure class (this is what broke the harness on `omega_web_headers`).
- ✅ `tests/test_phase0_regressions.py` — **14 passed** (httpx stdin feeding, RateLimiter refill/burst/cap/isolation, scope gating for recon/web/http tools deny-without-rules + allow-after-rule, CTF exclude path, no permanent rate lockout).
- ✅ Full suite re-run after fixes: `262 passed` (no regressions).

## In progress (exact stopping point)
- File: `tests/test_harness.py`
- Function/section: `test_all_registered_tools_have_structured_responses` (and the `HARNESS_CASES` list it drives)
- What's half-done: The harness boots the real MCP server over stdio and calls all 41 tools with benign, fail-fast args asserting structured TextContent responses + server survival (Phase 0 deliverable). It initially caught the `omega_web_headers` unhandled-HTTP-exception bug (now fixed). After the HTTPClient fix, the run gets further but **one tool call now times out** (asyncio TimeoutError at ~33s total → a 30s case). **The exact tool is not yet identified** — the harness does not print per-case progress. Primary suspects (in order): `omega_recon_tech` (whatweb `-a 3` against `http://127.0.0.1:1`) and `omega_recon_crawl` (katana). The two 90s cases (`omega_web_full_scan`, `omega_scan`) are not the culprit (would have shown ~90s).

## Next steps (ordered)
1. Identify the timing-out harness case: add per-case progress output (e.g. `print(name, flush=True)` inside the loop) and run `.venv/bin/python -m pytest tests/test_harness.py -x -s`. Then either make the offending adapter fail-fast (cap retries/timeout) or bump its harness timeout to be genuinely fail-fast via the adapter.
2. Re-run `.venv/bin/python -m pytest -q` — target: all green (262 + 14 regressions + harness).
3. Finish rest of Phase 0: confirm all 41 tools respond cleanly through the harness; update the tool catalog table (name → input schema → external call → status) if it still needs to be written down somewhere (results can be folded into the Phase 1 REPORT/DOC).
4. Phase 1 hardening: uniform error contract `{ error: { code, message, retryable } }`, config layer, worker-pool queue + concurrency, caching, structured invocation logging.
5. Phase 2 guardrails (user says hard constraints): enforce scope gating for ALL active tools incl. outside-engagement flows; ensure no autonomous exploitation / live credential brute-forcing / DoS; add authorization notes to finding/report metadata.
6. Phase 3.1-3.4 + Phase 4 feature modules and quality pass (see original prompt lists).

## Known issues / blockers
- `tests/test_harness.py::test_all_registered_tools_have_structured_responses` FAILS (timeout, culprit tool TBD — see In progress). `test_server_survives_unknown_tool_then_healthy_tool` in same file PASSES.
- Existing suite has 1 known non-fatal pytest warning: `TestServer` class in `tests/fixtures.py:167` has `__init__` (collection warning).
- Note: `test_core.py::TestScope::test_rate_limiting` made only a no-op assertion (`allowed or not allowed`); behavior now covered properly by the new regression tests.
- First commit in this repo—after this one, ensure future commits are incremental.

## Notes/decisions made this session
- Design pattern adopted (`_scope_denial`): with **no** engagement_id, recon/web/http tools run open-world (ungated) — matches the recon adapters' existing `open_world_hint=True` design and keeps existing open-world tests passing (verified). With an engagement_id, the full `authorize` pipeline (target scope → action → execution mode → rate limit) applies, and every previously-ungated tool now fails with a structured `{"error": "Scope denied: ..."}`.
- HttpxAdapter stdin: targets are newline-joined and encoded UTF-8; `-l /dev/stdin` flag added. Single fallback to `request.target` preserved.
- Kept `omega_recon_subdomains` / `omega_recon_portscan` scope logic untouched (they already gated via `authorize_target`/`authorize`).
- HTTPClient now returns `status_code: 0` + `error` on network failure rather than raising; all web-engine methods use `.get()` so they degrade gracefully.

## Test status
- Passing: `tests/test_phase0_regressions.py` (14), full pre-existing suite (262), `tests/test_harness.py::test_server_survives_unknown_tool_then_healthy_tool`
- Failing: `tests/test_harness.py::test_all_registered_tools_have_structured_responses` (timeout on one 30s case)
- Not yet run: none outstanding (the whole suite was re-run green after the Phase 0 fixes)

## Repo state
- Branch: `master`
- Note: `git status` shows the entire project as staged A/untracked — this repo has NO commits yet. This checkpoint commit will be the first.
- Files changed this session: `omega/tools/__init__.py`, `omega/recon/__init__.py`, `omega/scope/__init__.py`, `omega/mcp/__init__.py`, `omega/http/__init__.py`, `tests/test_phase0_regressions.py` (new), `tests/test_harness.py` (new), `.opencode/SESSION_STATE.md` (new).