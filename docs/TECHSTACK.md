# SENTINEL — Technology Stack Explained From Scratch

This document explains every technology SENTINEL is built on: what it is, why it
was chosen, and how it fits into the platform. It assumes no prior knowledge of
the individual libraries.

---

## 1. The Problem Shape

SENTINEL is a server you run that exposes **62 security tools** to AI assistants
(Claude, OpenCode, Cursor, any MCP client). The AI calls these tools to do
reconnaissance, web testing, CTF solving, and bug-bounty research. Everything the
AI does must be:

1. **Authorized** — only touch targets the engagement scope allows (deny by default).
2. **Remembered** — every action, piece of evidence, and finding must persist.
3. **Safe** — rate-limited, SSRF-protected, no autonomous exploitation.
4. **Explainable** — a full audit trail and generated reports for humans.

These requirements drove every technology choice below.

---

## 2. Language: Python ≥ 3.11

**What it is:** The programming language the entire platform is written in.
Version 3.11+ is required because SENTINEL uses modern features like `StrEnum`,
`asyncio` task groups, `except*`, and improved tracebacks.

**Why it's used:**
- Security tooling has a huge Python ecosystem (libraries for nmap parsing,
  HTTP scanning, cryptography, etc.).
- The official MCP SDK has a first-class Python implementation.
- Python's `asyncio` gives concurrent I/O without the complexity of threads —
  SENTINEL fires dozens of HTTP probes at once.
- Readability matters for a platform whose safety gating is critical to review.

---

## 3. Protocol Layer: MCP SDK ≥ 2.0 (`mcp==2.2.0`)

**What it is:** The Model Context Protocol (MCP) SDK implements a
JSON-RPC-over-transport protocol that standardises how an LLM discovers and calls
tools on a server. It's the "USB-C of AI tool integration": write once, works in
Claude, OpenCode, Cursor, and any MCP-native client.

**Why it's used:**
- The SDK handles: tool schema generation from Python type hints, session
  management, JSON-RPC message serialization, and transport negotiation.
- SENTINEL uses all three transports:
  - `stdio` — for locally launched clients (`python -m sentinel.mcp`).
  - `sse` — Server-Sent Events over HTTP (port 3000) for remote/web clients.
  - `streamable-http` — the modern HTTP transport.
- Every `sentinel_*` tool handler is registered through the SDK, which exposes it
  to the LLM with full parameter schemas automatically derived from Pydantic models.

---

## 4. Data Models: Pydantic ≥ 2.0 (`pydantic==2.13.5`)

**What it is:** A data-validation library that turns Python type annotations into
runtime validation and JSON Schemas.

**Why it's used — three jobs:**
1. **MCP tool schemas.** When MCP lists tools, it needs JSON Schema per tool
   (parameter names, types, defaults, required flags). Pydantic generates this
   automatically from `@server.tool()` decorated functions.
2. **Request validation.** Every incoming agent call and every REST request is
   validated against a Pydantic model before any code runs. A rogue
   `"severity": 42` is rejected instead of corrupting state.
3. **Configuration.** `sentinel/config/` uses Pydantic settings so environment
   variables, `.env`, and defaults are coerced and validated at startup.
   Pydantic v2 is ~5-50x faster than v1 and used throughout `sentinel/core/schemas.py`
   (Engagement, ScopeRule, Evidence, Finding, Hypothesis, AuditEvent, ...).

---

## 5. Storage: SQLite + `aiosqlite` (18 tables)

**What it is:** SQLite is a file-based relational database (a single `sentinel.db`).
`aiosqlite` is an async wrapper so queries never block the event loop.

**Why it's used:**
- **Zero ops.** No DB server to install, configure, or secure — perfect for a
  container runtime with limited disk.
- **Single file.** One `.db` lives in `SENTINEL_BASE_DIR`; easy to back up,
  wire to a Kubernetes PVC, or reset.
- **ACID transactions.** Concurrent tool calls from parallel agents stay
  consistent (no torn writes to the audit log, ever).
- **Declarative schema.** `sentinel/storage/__init__.py` creates 18 tables at
  startup (idempotent `CREATE TABLE IF NOT EXISTS`), covering:
  `engagements`, `scope_rules`, `authorizations`, `assets`, `services`,
  `endpoints`, `evidence`, `hypotheses`, `findings`, `jobs`, `tool_runs`,
  `graph_nodes`, `graph_edges`, `audit_log`, `reports`, `ctf_challenges`,
  `workspaces`, `requests_history`.
- **A deliberate design trade-off:** the architecture isolates DB access behind
  a `Database` class, so SQLite can be swapped for PostgreSQL for multi-replica
  production without touching tool handlers.

---

## 6. Async HTTP: `httpx` + `aiohttp`

**What they are:** Modern async HTTP client libraries.


- **httpx** is the primary client — HTTP/1.1+HTTP/2, connection pooling, proxies,
  TLS control, timeouts, and full request/response capture.
- **aiohttp** is used as a complementary async client for the HTTP-level MCP tools
  and dashboard routes.

**Why they're used:**
- Nearly every web/API security tool (`sentinel_web_*`, `sentinel_http_*`) makes
  outbound HTTP requests. Async lets SENTINEL run many probes concurrently within
  the global rate budget.
- **Redirect control is a safety feature.** SSRF protection needs to see the final
  destination; httpx lets us block redirects to private hosts after the first hop.
- **Evidence capture.** Response bodies, headers, and TLS details are captured and
  fed into the EvidenceEngine as immutable records — the proof behind every finding.

---

## 7. Web Server: FastAPI + uvicorn + Starlette + sse-starlette

**What they are:**
- **Starlette** is a low-level ASGI web framework (routing, middleware, WebSockets).
- **FastAPI** is a higher-level framework built on Starlette that derives
  request/response models and OpenAPI docs from type hints.
- **uvicorn** is the ASGI server process that actually serves requests; the
  `[standard]` extra bundles `uvloop` (faster event loop) and `websockets`.
- **sse-starlette** adds Server-Sent Events support to Starlette.

**Why they're used:**
- The **dashboard app** (`sentinel/api/__init__.py`) serves the human UI, the
  `/api/health` probe (used by Kubernetes liveness/readiness), and hundreds of
  REST routes (`sentinel/api/routes.py`, 1200+ lines: engagements, CTF, scope,
  recon, web, findings, ...). FastAPI auto-generates interactive API docs.
- The **MCP SSE transport** is built on `sse-starlette`: GET `/sse` opens the
  server→client event stream, POST `/messages/` carries client→server commands —
  this is how OpenCode/remote clients talk to the running container or pod.
- **Why not a "batteries included" framework (Django)?** SENTINEL is a low-footprint
  async service; Django's ORM/migrations/admin would be overkill and block the
  event loop. Starlette+FastAPI is async-native end to end.

---

## 8. Realtime: `websockets` (17.x)

**What it is:** async WebSocket server/client library.

**Why it's used:** part of the `uvicorn[standard]` stack and the FastAPI app for
real-time communication (live job/progress updates to the dashboard). It pairs
with SSE so both push channels (full-duplex WS and one-way SSE) are available
depending on the transport.

---

## 9. CLI: Click ≥ 8.1 (`click==8.5.0`)

**What it is:** Python's de-facto CLI framework (`@click.command()`,
`@click.option()`, auto help output).

**Why it's used:** `pyproject.toml` exposes a `sentinel` console script that maps
to `sentinel.cli:main`. It provides:
- `sentinel doctor` — dependency/binary checks.
- `sentinel tools` — enumerate tools and their availability.
- `sentinel inspect` — show configuration.
- `sentinel serve` / `sentinel start` — run the server (stdio, SSE, HTTP, or both).
This is how the Docker image starts with
`CMD ["sentinel", "start", "--dashboard-host", "0.0.0.0", "--mcp-host", "0.0.0.0"]`.

---

## 10. Optional Runtime: Playwright (browser automation)

**What it is:** Microsoft's cross-browser automation library (Chromium/Firefox/WebKit).

**Why it's used (optional `[browser]` extra):** Some testing needs a real browser —
dynamic JavaScript-heavy pages, DOM-level checks. Playwright runs headless in
containers (no display server), controllable via `SENTINEL_BROWSER_ENABLED` and
`SENTINEL_BROWSER_HEADLESS`. It's optional to keep the core image small.

---

## 11. Optional Auth: PyJWT + cryptography

**What they are:** `PyJWT` issues/validates JSON Web Tokens; `cryptography`
provides the underlying primitives.

**Why they're used:** When `SENTINEL_AUTH_ENABLED=true`, the API/MCP layer requires
a Bearer token. Tokens are stateless (verified per request), so there is no
session store to hijack. This protects the dashboard when exposed on a network.

---

## 12. Security Tool Binaries (external adapters)

SENTINEL doesn't reimplement attack tooling — it wraps battle-tested binaries in
**structured adapter classes** (in `sentinel/recon/` and `sentinel/tools/`) that add
scope validation, rate limiting, evidence capture, parsing, and graceful
`BINARY_MISSING` handling.

| Tool | Type | Purpose |
|---|---|---|
| `subfinder` | passive recon | subdomain enumeration across 50+ passive sources |
| `httpx` (PD) | probing | live-host verification + tech fingerprinting |
| `nmap` | scanning | flexible port/service/OS scanning |
| `naabu` | scanning | fast SYN port discovery |
| `masscan` | scanning | internet-scale port scanning |
| `nuclei` | scanning | template-based vulnerability detection (8000+ templates) |
| `katana` | crawling | modern JS-aware site crawling |
| `ffuf` | fuzzing | fast web fuzzing (dirs, params, VHOST) |
| `gobuster` | brute-force | directory & DNS enumeration |
| `whatweb` | fingerprinting | CMS/framework/WAF detection |
| `wafw00f` | fingerprinting | WAF identification |
| `dnsx` | recon | fast DNS resolution/multiple record types |

---

## 13. Runtime Platforms: Docker + Kubernetes

### Docker (built and verified with Docker 26.1.5)

**What it is:** container packaging — the image bundles Python ≥3.11, all Python
deps, the Go security binaries, nmap, and the app code in one reproducible unit
built from `python:3.12-slim` via a multi-stage `Dockerfile`.

**Why it's used:** security tools have messy system deps; the image guarantees the
same working environment everywhere. Runs as a non-root `sentinel` user (defense in
depth), keeps data on a volume, and exposes:
- `8000` — the reconciliation dashboard / REST API
- `3000` — the MCP SSE server (`/sse`, `/messages/`)

### Kubernetes (verified on kind v1.31.0)

**What it is:** container orchestration. SENTINEL deploys as a Deployment with
management resources (manifests under `/tmp/opencode/k8s/`):
- **Liveness probe** — `/api/health` every 20s → kubelet restarts a hung pod.
- **Readiness probe** — `/api/health` every 10s → only ready pods receive traffic.
- **PVC (1Gi)** — SQLite DB + workspaces survive pod restarts and rollouts
  (verified: `kubectl rollout restart` preserved all engagement data).
- **ConfigMap/Secret** — config and auth material decoupled from the image.
- **Services** — stable endpoints (`sentinel-dashboard:8000`,
  `sentinel-mcp:3000`) and port-forward for remote MCP access.
- **securityContext** — non-root, read-only rootfs where possible.

---

## 14. Quality & CI: ruff, mypy, pytest

- **ruff** (line-length 120, 12 rule sets) — extremely fast linter; catches bugs,
  unused imports, security anti-patterns (`S`), conventions (`N`), `TCH` etc.
- **mypy** (`strict = true`) — static type checking; in a codebase whose safety
  gating is type-heavy (`ScopeCheckResult`, schemas), strict typing prevents a
  whole class of runtime errors.
- **pytest + pytest-asyncio** (`asyncio_mode = "auto"`) — the test runner. **376
  tests currently pass** across unit, integration, MCP protocol, and security tests
  (the SSRF/scope/redaction tests live in `tests/`).

---

## 15. How It All Fits Together (runtime picture)

```
MCP client ──(stdio / SSE / http)──► sentinel.mcp (62 tools, Pydantic-validated)
                                        │
            every live-target call ─► ScopeEngine (deny-by-default, SSRF, rate limit)
                                        │  ├─ authorize()   → audit_log + authorizations ledger
                                        │  └─ enforce_rate_limit() → token-bucket
                                        ▼
                              ToolExecutor / Tool adapters
                                        │  (async httpx/aiohttp, subprocess wrappers)
                                        ▼
                    EvidenceEngine (immutable, SHA-256 dedup)  ──┐
                    FindingsEngine (lifecycle, clustering)      ──┤
                    KnowledgeGraph (assets, pathfinding)        ──┤
                                        │                        │
                                        ▼                        ▼
                                 SQLite (aiosqlite, 18 tables)   ──┘
                                        ▲
               FastAPI dashboard (uvicorn) ◄──── report generator (md/html/json)
```

---

## 16. Deployment Cheat-Sheet

```bash
# Local stdio
python -m sentinel.mcp

# Remote SSE (container/k8s friendly)
sentinel start --dashboard-host 0.0.0.0 --mcp-host 0.0.0.0

# Docker
docker build -t sentinel .
docker run -d -p 8000:8000 -p 3000:3000 \
       -v sentinel-data:/data/sentinel sentinel

# Kubernetes (kind test cluster verified)
kubectl apply -f /tmp/opencode/k8s/
curl http://sentinel-dashboard:8000/api/health   # liveness/readiness
kubectl port-forward svc/sentinel-mcp 3001:3000  # remote MCP access
```

---

*Documented & verified: 376 tests passing, Docker health-check green, K8s probes
Ready, PVC persistence confirmed, full E2E MCP workflow green on Docker and K8s.*