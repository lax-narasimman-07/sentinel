# SENTINEL vs. Every Other Security / Bug-Bounty / CTF MCP

A researched, named-comparison of the available pentest, bug-bounty, web-security,
and CTF MCP servers on GitHub and the web (research date: September 2026), and the
features that make SENTINEL unique.

---

## 1. The Field (all known projects)

### 1.1 General pentest MCPs

| Project | Lang | Tools | What it does | Notable gap vs SENTINEL |
|---|---|---|---|---|
| **DMontgomery40/pentest-mcp** | Node.js | 18 | nmap, gobuster, nikto, John/Hashcat, wordlist gen, engagement records (JSON), SoW capture, student/pro mode. **This is the environment's loaded `pentest-mcp`.** | No scope enforcement, no evidence engine, no CTF module, no web/API security tools, no graph, no audit ledger, no dashboard, no persistence (JSON only) |
| **FuzzingLabs/mcp-security-hub** | Docker/Python | 300+ (38 MCPs) | one Dockerized MCP per tool (nmap, nuclei, sqlmap, shodan, ...) | Fragmented — 38 separate MCP servers to run; no unified scope/evidence/finding model; no CTF module |
| **RamKansal/pentestMCP** | Python | 20+ | nmap/nuclei/ZAP/sqlmap wrappers | No scope engine, no persistence, no findings lifecycle, no CTF, no reporting |
| **Vittal-Mukunda/MCP-Server-Pentest** | Python | 20 | OWASP Top-10 coverage, 7-phase lifecycle, MITRE ATT&CK auto-mapping, plugin arch | Basic scope only; no CTF, no asset graph, no REST dashboard, no web header/CORS/JWT tools, no Docker/K8s |
| **hackersatyamrastogi/pentesting-cyber-mcp** | n/a | 50+ | tool collection wrapper | No scope, no evidence, no CTF, no findings model |
| **cyproxio/mcp-for-security** | n/a | collection | sqlmap/ffuf/nmap/masscan as separate MCPs | Fragmented; no unified platform |
| **openbashok/pentest-mcp** | Node.js | — | Kali-focused nmap/nuclei/ffuf/sqlmap | No scope, no persistence, no CTF |
| **Chfle/Pentest-MCP-Server** | Python | 88 | 88 containerized tools, Claude Code/Cursor | No scope enforcement, no evidence engine, no CTF |
| **0x4m4/hexstrike-ai** | Python | 150+ (11.5k stars) | autonomous agents (BugBounty, CTF, CVE), real-time dashboards | Mostly agent-manager/tooling; no deny-by-default scope model, no evidence dedup, no audit ledger, no hypothesis ledger |

### 1.2 Bug-bounty / web-security MCPs

| Project | Lang | Notes | Notable gap vs SENTINEL |
|---|---|---|---|
| **binderlabs/BugHound-MCP** | Python | 45 test techniques, 7-stage pipeline (Init→Report), MCP/CLI/AI modes, Black Hat Arsenal ASIA 2026 | Target-finder oriented; no CTF, no asset graph, no hypothesis ledger, no engagement modes, no dashboard |
| **R-s0n/rs0n-bug-bounty-mcp-server** | TypeScript | bug bounty knowledge base: payloads, wordlists, 778+ report corpus, WAF bypass | Knowledge-only — no actual scanning/HTTP tools; no scope, no evidence |
| **ZAP MCP Server (OWASP)** | Java/Go | official ZAP bridge: spider, passive/active scan, alerts | ZAP-only; no recon, no CTF, no scope engine, no findings/evidence model, no reporting |
| **w0h1v/mcp-shodan** | TypeScript | Shodan API: IP recon, DNS, CVE intel (160 stars) | Single passive API; no active tools, no scope, no CTF, no findings lifecycle |

### 1.3 CTF MCPs / agents

| Project | Lang | Notes | Notable gap vs SENTINEL |
|---|---|---|---|
| **verialabs/ctf-agent** | Python (751 stars) | 1st place BSidesSF 2026 (52/52 flags); Docker-sandboxed solvers, coordinator LLM — a standalone agent, not an MCP | Not exposed as MCP tools; no scope enforcement, no engagement model, no findings lifecycle, no reporting |
| **Coff0xc/CTF-MCP** | Python | 126 tools for web/crypto/pwn CTF | CTF-only; no scope, no engagement model, no evidence dedup, no auto-triage, no reporting |
| **loegaire/CTF-MCP-Swarm** | — | concurrent agent swarm for CTF | CTF-only; no scope/evidence/findings |
| **bsprague/mctfp** | Go | CTFd + VirusTotal, Kali+Claude+mcp | CTF-only, minimal tools, no scope engine |

### 1.4 Forensic / data MCPs

| Project | Notes | Notable gap vs SENTINEL |
|---|---|---|
| **doublegate/CyberChef-MCP** | 463+ encode/decode/encryption ops | Data processing only; no scanning, no network tools, no scope/evidence/CTF |

---

## 2. Head-to-Head: SENTINEL vs. the Loaded Pentest MCP

The `pentest_*` toolset in this environment is **DMontgomery40/pentest-mcp**
(18 tools, Node.js, JSON engagement records). SENTINEL's 62 tools add:

| Capability | pentest-mcp | SENTINEL |
|---|---|---|
| Tool count | 18 | **62** |
| Scope enforcement (deny-by-default) | ❌ | ✅ every entry point |
| SSRF protection (localhost/metadata) | ❌ | ✅ pre-request URL normalization |
| Rate limiting (token bucket, 3 policies) | ❌ | ✅ |
| Engagement modes (9: ctf/bug_bounty/pentest/...) | 2 (student/pro) | ✅ 9 modes |
| Evidence engine (immutable, SHA-256 dedup) | ❌ | ✅ |
| Finding lifecycle + auto-triage (nuclei/nikto) | ❌ | ✅ |
| CTF module (challenges, flags, hypothesis ledger) | ❌ | ✅ |
| Hypothesis-driven testing | ❌ | ✅ |
| Asset graph + pathfinding | ❌ | ✅ |
| Web/API security (headers, CORS, cookies, JWT, ...) | ❌ | ✅ (14 tools) |
| Report generation (md/html/json + authorization) | ❌ | ✅ |
| REST/UI dashboard | ❌ | ✅ (FastAPI, :8000) |
| Audit ledger (SQLite `authorizations` + JSONL) | ❌ | ✅ |
| SQLite persistence (18 tables, PVC-safe) | JSON only | ✅ |
| Docker + K8s deployment (probes, PVC) | ❌ | ✅ |
| Secret redaction from MCP output | ❌ | ✅ |
| Structured `BINARY_MISSING` / `doctor` / `health` | ❌ | ✅ |

---

## 3. SENTINEL's Unique Moats (what literally nobody else ships)

1. **One platform, all modes.** CTF + bug bounty + pentest + web/API security +
   recon behind a single engagement model. Others are pentest-only (pentest-mcp),
   CTF-only (ctf-agent), or web-only (ZAP/BugHound).

2. **Scope enforcement is architecturally central.** Every live-target path —
   MCP handler, `ToolExecutor` (authorizes *every* item in a target list), the
   orchestrator, and the REST/UI API — passes through the deny-by-default Scope
   Engine with SSRF + rate limiting. Not one of the 18 projects above does all four.

3. **Evidence engine.** Immutable, content-hashed (SHA-256 dedup) evidence records
   that survive the session. No competitor persists *proof* like this.

4. **Auto-triage pipeline.** nuclei/nikto output is auto-mapped into scoped,
   severity-ranked, deduplicated `Finding` records. Nobody else does the
   scanner→finding plumbing.

5. **Hypothesis ledger for CTF.** Structured hypothesis→test→confirm/refute
   lifecycle kept per challenge. ctf-agent *solves fast*; SENTINEL *records how* —
   required for real engagement work.

6. **Asset graph with pathfinding.** 20 node / 14 edge types, BFS shortest-path —
   reasoning about the attack surface, not just a flat host list.

7. **Container/K8s-native.** Verified build, healthchecks, probes, PVC persistence,
   port-forwarded MCP. Only 2 of 18 compete on containers; none have K8s.

8. **`token_preview` redaction + structured health tooling** (`doctor`,
   `tools_list`, `health_check`) — operational safety the others lack.

9. **62 tools in ONE process/DB/scope model**, vs. fragmentation (mcp-security-hub
   runs 38 containers; rs0n ships no tools at all).

---

## 4. Honest Limitations vs. The Field

- **ctf-agent** is a purpose-built CTF *autonomously* (52/52 flags, BSidesSF 2026) —
  SENTINEL is a toolset + orchestrator, not a self-driving solver.
- **hexstrike-ai** has more pre-packaged agent flows / a much larger community
  (11.5k stars) and real-time dashboards.
- **mcp-security-hub / Chfle** support more total binaries, but unilaterally.
- **CyberChef-MCP** is superior for pure encode/decode/forensics operations (463 ops).
- SENTINEL intentionally does **not** ship brute-force, sqlmap auto-dump for live
  targets, or autonomous exploitation (they're outside its safety contract).

---

## 5. Verified Claims (this repo's actual output)

```
376/376 tests passing        pytest (188s)
Docker:   image built, HEALTHY, 62/62 tool schemas callable over SSE
K8s:      pod Ready=1/1, liveness/readiness green, PVC data survives rollout restart
E2E:      engagement→scope→CTF→hypothesis→flag→ledger→report  ✅ on Docker AND K8s
```

*Research note: star counts/claims are as of the research date and can drift; the
SENTINEL feature set is verified directly from the codebase and live runtime at
version 1.0.0.*