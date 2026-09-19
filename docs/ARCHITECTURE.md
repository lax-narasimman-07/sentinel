# SENTINEL Architecture

## System Overview

SENTINEL is an MCP (Model Context Protocol) server that exposes 62 security research tools through a standardized interface. The system is built around a layered architecture:

```
MCP Client (OpenCode, Claude, etc.)
        |
    [MCP Protocol]
        |
    SentinelServer (sentinel/mcp/__init__.py)
        |
    Orchestrator (sentinel/agents/__init__.py)
        |
    +--------+--------+--------+--------+
    |        |        |        |        |
 ScopeEngine  ToolExecutor  EvidenceEngine  FindingEngine  WebSecurityEngine
    |        |
    v        v
 Database   Tool Adapters (subfinder, nmap, httpx, ffuf, ...)
 (SQLite)   (sentinel/recon/__init__.py, sentinel/tools/__init__.py)
```

## Module Map

| Module | Path | Description |
|---|---|---|
| `sentinel.mcp` | `sentinel/mcp/__init__.py` | MCP server, tool registration, stdio/HTTP transports |
| `sentinel.agents` | `sentinel/agents/__init__.py` | Multi-agent orchestrator: ReconAgent, WebAgent, CTFWebAgent, PlannerAgent, Orchestrator |
| `sentinel.scope` | `sentinel/scope/__init__.py` | Scope enforcement, SSRF protection, rate limiting, authorization pipeline |
| `sentinel.tools` | `sentinel/tools/__init__.py` | ToolAdapter base class, ToolRegistry, ToolExecutor with evidence collection |
| `sentinel.recon` | `sentinel/recon/__init__.py` | Recon adapters: SubfinderAdapter, HttpxAdapter, NmapAdapter, FfufAdapter, WhatWebAdapter, GobusterAdapter, KatanaAdapter |
| `sentinel.web` | `sentinel/web/__init__.py` | Web security engine: headers, CORS, cookies, endpoints, JS analysis |
| `sentinel.http` | `sentinel/http/__init__.py` | HTTP client with proxy support, redirect control, evidence storage |
| `sentinel.ctf` | `sentinel/ctf/__init__.py` | CTF engine: challenge management, hypothesis ledger, flag tracking |
| `sentinel.evidence` | `sentinel/evidence/__init__.py` | Immutable evidence storage with deduplication |
| `sentinel.findings` | `sentinel/findings/__init__.py` | Finding lifecycle, hypothesis tracking, deduplication, clustering |
| `sentinel.knowledge` | `sentinel/knowledge/__init__.py` | Asset graph: in-memory + persistent, BFS pathfinding, neighbor queries |
| `sentinel.storage` | `sentinel/storage/__init__.py` | SQLite database layer with 16 tables |
| `sentinel.config` | `sentinel/config/__init__.py` | Configuration from environment variables, Pydantic models |
| `sentinel.reporting` | `sentinel/reporting/__init__.py` | Report generation: Markdown, HTML, JSON |
| `sentinel.orchestration` | `sentinel/orchestration/__init__.py` | Async job management with retry and cancellation |
| `sentinel.workspace` | `sentinel/workspace/__init__.py` | Isolated per-engagement working directories |
| `sentinel.core` | `sentinel/core/schemas.py` | Data models, enums, Pydantic schemas |
| `sentinel.cli` | `sentinel/cli/__init__.py` | CLI entry point (doctor, tools, serve, inspect) |
| `sentinel.browser` | `sentinel/browser/` | Playwright browser automation (optional) |
| `sentinel.forensics` | `sentinel/forensics/` | Forensics analysis (extensible) |
| `sentinel.reversing` | `sentinel/reversing/` | Reverse engineering (extensible) |
| `sentinel.pwn` | `sentinel/pwn/` | Binary exploitation (extensible) |
| `sentinel.crypto` | `sentinel/crypto/` | Cryptography (extensible) |
| `sentinel.mobile` | `sentinel/mobile/` | Mobile security (extensible) |
| `sentinel.cloud` | `sentinel/cloud/` | Cloud security (extensible) |
| `sentinel.telemetry` | `sentinel/telemetry/` | Telemetry and metrics (extensible) |

## Data Flow

The core data pipeline follows this sequence:

```
1. SCOPE
   engagement_create -> scope_add_rule -> scope_check
   "Is this target authorized for testing?"

2. DISCOVERY
   recon_subdomains -> recon_probe -> recon_portscan -> recon_fuzz -> recon_crawl
   "What assets exist in scope?"

3. EVIDENCE
   http_request -> web_headers -> web_cors -> web_cookies -> web_js_analyze
   "Collect proof and observations"

4. FINDINGS
   hypothesis_create -> hypothesis_update -> finding_create -> finding_validate
   "What vulnerabilities were found?"

5. REPORTS
   report_generate
   "Produce deliverable documentation"
```

## SQLite Schema (16 Tables)

Defined in `sentinel/storage/__init__.py`:

| Table | Purpose | Key Indexes |
|---|---|---|
| `engagements` | Engagement records (name, mode, status) | PK: id |
| `scope_rules` | Authorization rules (include/exclude, pattern matching) | engagement_id |
| `authorizations` | Credentials, tokens, cookies for engagements | engagement_id |
| `assets` | Discovered assets (subdomains, IPs, URLs, technologies) | engagement_id, asset_type |
| `services` | Open services from port scans | host, port |
| `endpoints` | Discovered HTTP endpoints | url |
| `evidence` | Immutable evidence records with content hashes | engagement_id, evidence_type, content_hash |
| `hypotheses` | Vulnerability hypotheses with validation status | validation_status |
| `findings` | Security findings (vulnerabilities) with severity/confidence | engagement_id, severity, validation_status |
| `jobs` | Async job queue for long-running tool executions | status |
| `tool_runs` | Tool execution history with raw output | tool_name |
| `graph_nodes` | Asset graph nodes (20 types) | node_type |
| `graph_edges` | Asset graph edges (14 types) | source_node_id, target_node_id |
| `audit_log` | Complete audit trail of all actions | engagement_id, event_type |
| `reports` | Generated reports (markdown/html/json) | engagement_id |
| `ctf_challenges` | CTF challenge data with hypothesis ledger | engagement_id |
| `workspaces` | Isolated per-engagement working directories | engagement_id |
| `requests_history` | HTTP request/response history | url |

## MCP Tools (62 Tools)

### Engagement Management
| Tool | Description |
|---|---|
| `sentinel_engagement_create` | Create security engagement (ctf, bug_bounty, pentest, local_lab, analysis_only) |
| `sentinel_engagement_list` | List all engagements |
| `sentinel_engagement_get` | Get engagement details with scope rules and asset count |

### Scope Management
| Tool | Description |
|---|---|
| `sentinel_scope_add_rule` | Add include/exclude scope rule (domain, wildcard, ip, cidr, url, port) |
| `sentinel_scope_check` | Check if target is in scope |
| `sentinel_scope_list_rules` | List all scope rules for engagement |

### Reconnaissance
| Tool | Description |
|---|---|
| `sentinel_recon_subdomains` | Passive subdomain enumeration via subfinder |
| `sentinel_recon_probe` | HTTP probing via httpx |
| `sentinel_recon_portscan` | Port scanning via nmap (syn/tcp/udp) |
| `sentinel_recon_fuzz` | Directory fuzzing via ffuf |
| `sentinel_recon_tech` | Technology fingerprinting via whatweb |
| `sentinel_recon_crawl` | Website crawling via katana |

### Web Security
| Tool | Description |
|---|---|
| `sentinel_web_headers` | HTTP security header analysis (HSTS, CSP, X-Frame-Options, etc.) |
| `sentinel_web_cors` | CORS misconfiguration testing |
| `sentinel_web_cookies` | Cookie security property analysis (HttpOnly, Secure, SameSite) |
| `sentinel_web_endpoints` | Endpoint extraction from HTML/JavaScript |
| `sentinel_web_full_scan` | Full web security analysis (headers + CORS + cookies + endpoints) |
| `sentinel_web_js_analyze` | JavaScript secret and endpoint analysis |

### HTTP Client
| Tool | Description |
|---|---|
| `sentinel_http_request` | Execute HTTP requests (GET/POST/PUT/PATCH/DELETE) with evidence collection |

### Orchestrated Scanning
| Tool | Description |
|---|---|
| `sentinel_scan` | Run coordinated multi-agent scan (full, recon, web, ctf_web) |

### Asset Graph
| Tool | Description |
|---|---|
| `sentinel_graph_add_node` | Add node (domain, subdomain, ip, port, service, url, endpoint, finding, etc.) |
| `sentinel_graph_add_edge` | Add edge (resolves_to, hosts, serves, calls, uses_technology, etc.) |
| `sentinel_graph_query` | Query graph nodes by type or label |

### Findings & Hypotheses
| Tool | Description |
|---|---|
| `sentinel_hypothesis_create` | Create vulnerability hypothesis |
| `sentinel_hypothesis_update` | Update hypothesis status/evidence |
| `sentinel_finding_create` | Create security finding (vulnerability report) |
| `sentinel_finding_list` | List findings with optional severity filter |
| `sentinel_finding_validate` | Mark finding as validated (confirmed) |
| `sentinel_finding_reject` | Reject finding (false positive) |
| `sentinel_finding_summary` | Summary counts by severity and status |

### Evidence
| Tool | Description |
|---|---|
| `sentinel_evidence_list` | List evidence records with optional type filter |

### CTF Engine
| Tool | Description |
|---|---|
| `sentinel_ctf_challenge_create` | Create CTF challenge workspace (web, crypto, pwn, rev, forensics, osint, misc, stego, mobile, blockchain) |
| `sentinel_ctf_challenge_list` | List CTF challenges for engagement |
| `sentinel_ctf_hypothesis` | Add hypothesis to challenge |
| `sentinel_ctf_submit_flag` | Submit candidate flag |
| `sentinel_ctf_confirm_flag` | Confirm flag as correct |
| `sentinel_ctf_ledger` | Get hypothesis ledger (active/succeeded/failed) |

### Reporting & Utilities
| Tool | Description |
|---|---|
| `sentinel_report_generate` | Generate report (markdown, html, json) |
| `sentinel_tools_list` | Discover installed security tools |
| `sentinel_audit_log` | View audit trail for engagement |
| `sentinel_doctor` | Self-diagnostics (Python version, installed tools, dependencies) |

## Agent System

The agent system (`sentinel/agents/__init__.py`) implements a multi-agent architecture:

### Orchestrator
The top-level coordinator. Wires together all engines and manages engagements.

### PlannerAgent
Mode-based strategy selector. Determines which specialist agents to run:
- **CTF mode**: `recon` -> `ctf_web` -> `web`
- **Web/bug bounty**: `recon` -> `web`
- **Network security**: `recon`

### ReconAgent
Subdomain enumeration and HTTP probing pipeline:
1. Subdomain enumeration (subfinder)
2. HTTP probing (httpx)
3. Graph node creation for discovered assets

### WebAgent
Full web security analysis: headers, CORS, cookies, endpoints.

### CTFWebAgent
CTF-specific web analysis: headers, CORS, endpoint extraction, body preview.

## Scope Engine

Located in `sentinel/scope/__init__.py`. Central safety gate -- every active tool call must pass through.

### Modes

| Mode | Scope Behavior | Active Testing |
|---|---|---|
| `ctf` | Allow all targets (unless explicitly excluded) | Allowed |
| `local_lab` | Allow all targets | Allowed |
| `bug_bounty` | Deny by default (require include rules) | Allowed |
| `pentest` | Deny by default (require include rules) | Allowed |
| `analysis_only` | Allow target check | Blocked (passive only) |
| `reversing` | Analysis only | Blocked |
| `api_security` | Require include rules | Allowed |
| `web_security` | Require include rules | Allowed |
| `network_security` | Require include rules | Allowed |

### Authorization Pipeline

Every active tool call goes through 4 checks:
1. **Target scope** -- Is the target within the engagement's scope rules?
2. **Action permission** -- Is this specific action allowed on this target?
3. **Execution mode** -- Does the engagement mode allow this risk level?
4. **Rate limit** -- Has the per-target rate limit been exceeded?

## Evidence Pipeline

The evidence engine (`sentinel/evidence/__init__.py`) provides:

- **Automatic deduplication** via content hashing (SHA-256 truncated to 16 hex chars)
- **Immutable records** -- evidence is never modified after creation
- **Type taxonomy** -- 15 evidence types (http_request, http_response, screenshot, dns_record, certificate, port_scan, service_info, file, code_snippet, tool_output, browser_event, diff, hash, timeline_event, command_execution)
- **Parent-child linking** -- HTTP request/response pairs are linked via `parent_event_id`
- **Tool output capture** -- Every tool execution stores its output as evidence

## Finding Lifecycle

```
hypothesis -> candidate -> testing -> validated
                              |
                              +-> rejected (false positive)
                              +-> duplicate (merged with existing)
```

### Stages
1. **Hypothesis** -- Initial vulnerability theory, untested
2. **Candidate** -- Needs evidence collection and validation
3. **Testing** -- Actively being verified
4. **Validated** -- Confirmed vulnerability with evidence
5. **Rejected** -- Determined to be false positive
6. **Duplicate** -- Merged with a similar existing finding

### Deduplication
Findings are checked for duplicates on creation:
- Same title + same affected_endpoint = duplicate
- Same affected_asset + same CWE + same affected_endpoint = duplicate
