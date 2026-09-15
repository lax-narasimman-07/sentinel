# OMEGA-CYBER-MCP Architecture

## System Overview

OMEGA-CYBER-MCP is an MCP (Model Context Protocol) server that exposes 30+ security research tools through a standardized interface. The system is built around a layered architecture:

```
MCP Client (OpenCode, Claude, etc.)
        |
    [MCP Protocol]
        |
    OmegaServer (omega/mcp/__init__.py)
        |
    Orchestrator (omega/agents/__init__.py)
        |
    +--------+--------+--------+--------+
    |        |        |        |        |
 ScopeEngine  ToolExecutor  EvidenceEngine  FindingEngine  WebSecurityEngine
    |        |
    v        v
 Database   Tool Adapters (subfinder, nmap, httpx, ffuf, ...)
 (SQLite)   (omega/recon/__init__.py, omega/tools/__init__.py)
```

## Module Map

| Module | Path | Description |
|---|---|---|
| `omega.mcp` | `omega/mcp/__init__.py` | MCP server, tool registration, stdio/HTTP transports |
| `omega.agents` | `omega/agents/__init__.py` | Multi-agent orchestrator: ReconAgent, WebAgent, CTFWebAgent, PlannerAgent, Orchestrator |
| `omega.scope` | `omega/scope/__init__.py` | Scope enforcement, SSRF protection, rate limiting, authorization pipeline |
| `omega.tools` | `omega/tools/__init__.py` | ToolAdapter base class, ToolRegistry, ToolExecutor with evidence collection |
| `omega.recon` | `omega/recon/__init__.py` | Recon adapters: SubfinderAdapter, HttpxAdapter, NmapAdapter, FfufAdapter, WhatWebAdapter, GobusterAdapter, KatanaAdapter |
| `omega.web` | `omega/web/__init__.py` | Web security engine: headers, CORS, cookies, endpoints, JS analysis |
| `omega.http` | `omega/http/__init__.py` | HTTP client with proxy support, redirect control, evidence storage |
| `omega.ctf` | `omega/ctf/__init__.py` | CTF engine: challenge management, hypothesis ledger, flag tracking |
| `omega.evidence` | `omega/evidence/__init__.py` | Immutable evidence storage with deduplication |
| `omega.findings` | `omega/findings/__init__.py` | Finding lifecycle, hypothesis tracking, deduplication, clustering |
| `omega.knowledge` | `omega/knowledge/__init__.py` | Asset graph: in-memory + persistent, BFS pathfinding, neighbor queries |
| `omega.storage` | `omega/storage/__init__.py` | SQLite database layer with 16 tables |
| `omega.config` | `omega/config/__init__.py` | Configuration from environment variables, Pydantic models |
| `omega.reporting` | `omega/reporting/__init__.py` | Report generation: Markdown, HTML, JSON |
| `omega.orchestration` | `omega/orchestration/__init__.py` | Async job management with retry and cancellation |
| `omega.workspace` | `omega/workspace/__init__.py` | Isolated per-engagement working directories |
| `omega.core` | `omega/core/schemas.py` | Data models, enums, Pydantic schemas |
| `omega.cli` | `omega/cli/__init__.py` | CLI entry point (doctor, tools, serve, inspect) |
| `omega.browser` | `omega/browser/` | Playwright browser automation (optional) |
| `omega.forensics` | `omega/forensics/` | Forensics analysis (extensible) |
| `omega.reversing` | `omega/reversing/` | Reverse engineering (extensible) |
| `omega.pwn` | `omega/pwn/` | Binary exploitation (extensible) |
| `omega.crypto` | `omega/crypto/` | Cryptography (extensible) |
| `omega.mobile` | `omega/mobile/` | Mobile security (extensible) |
| `omega.cloud` | `omega/cloud/` | Cloud security (extensible) |
| `omega.telemetry` | `omega/telemetry/` | Telemetry and metrics (extensible) |

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

Defined in `omega/storage/__init__.py`:

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

## MCP Tools (30+ Tools)

### Engagement Management
| Tool | Description |
|---|---|
| `omega_engagement_create` | Create security engagement (ctf, bug_bounty, pentest, local_lab, analysis_only) |
| `omega_engagement_list` | List all engagements |
| `omega_engagement_get` | Get engagement details with scope rules and asset count |

### Scope Management
| Tool | Description |
|---|---|
| `omega_scope_add_rule` | Add include/exclude scope rule (domain, wildcard, ip, cidr, url, port) |
| `omega_scope_check` | Check if target is in scope |
| `omega_scope_list_rules` | List all scope rules for engagement |

### Reconnaissance
| Tool | Description |
|---|---|
| `omega_recon_subdomains` | Passive subdomain enumeration via subfinder |
| `omega_recon_probe` | HTTP probing via httpx |
| `omega_recon_portscan` | Port scanning via nmap (syn/tcp/udp) |
| `omega_recon_fuzz` | Directory fuzzing via ffuf |
| `omega_recon_tech` | Technology fingerprinting via whatweb |
| `omega_recon_crawl` | Website crawling via katana |

### Web Security
| Tool | Description |
|---|---|
| `omega_web_headers` | HTTP security header analysis (HSTS, CSP, X-Frame-Options, etc.) |
| `omega_web_cors` | CORS misconfiguration testing |
| `omega_web_cookies` | Cookie security property analysis (HttpOnly, Secure, SameSite) |
| `omega_web_endpoints` | Endpoint extraction from HTML/JavaScript |
| `omega_web_full_scan` | Full web security analysis (headers + CORS + cookies + endpoints) |
| `omega_web_js_analyze` | JavaScript secret and endpoint analysis |

### HTTP Client
| Tool | Description |
|---|---|
| `omega_http_request` | Execute HTTP requests (GET/POST/PUT/PATCH/DELETE) with evidence collection |

### Orchestrated Scanning
| Tool | Description |
|---|---|
| `omega_scan` | Run coordinated multi-agent scan (full, recon, web, ctf_web) |

### Asset Graph
| Tool | Description |
|---|---|
| `omega_graph_add_node` | Add node (domain, subdomain, ip, port, service, url, endpoint, finding, etc.) |
| `omega_graph_add_edge` | Add edge (resolves_to, hosts, serves, calls, uses_technology, etc.) |
| `omega_graph_query` | Query graph nodes by type or label |

### Findings & Hypotheses
| Tool | Description |
|---|---|
| `omega_hypothesis_create` | Create vulnerability hypothesis |
| `omega_hypothesis_update` | Update hypothesis status/evidence |
| `omega_finding_create` | Create security finding (vulnerability report) |
| `omega_finding_list` | List findings with optional severity filter |
| `omega_finding_validate` | Mark finding as validated (confirmed) |
| `omega_finding_reject` | Reject finding (false positive) |
| `omega_finding_summary` | Summary counts by severity and status |

### Evidence
| Tool | Description |
|---|---|
| `omega_evidence_list` | List evidence records with optional type filter |

### CTF Engine
| Tool | Description |
|---|---|
| `omega_ctf_challenge_create` | Create CTF challenge workspace (web, crypto, pwn, rev, forensics, osint, misc, stego, mobile, blockchain) |
| `omega_ctf_challenge_list` | List CTF challenges for engagement |
| `omega_ctf_hypothesis` | Add hypothesis to challenge |
| `omega_ctf_submit_flag` | Submit candidate flag |
| `omega_ctf_confirm_flag` | Confirm flag as correct |
| `omega_ctf_ledger` | Get hypothesis ledger (active/succeeded/failed) |

### Reporting & Utilities
| Tool | Description |
|---|---|
| `omega_report_generate` | Generate report (markdown, html, json) |
| `omega_tools_list` | Discover installed security tools |
| `omega_audit_log` | View audit trail for engagement |
| `omega_doctor` | Self-diagnostics (Python version, installed tools, dependencies) |

## Agent System

The agent system (`omega/agents/__init__.py`) implements a multi-agent architecture:

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

Located in `omega/scope/__init__.py`. Central safety gate -- every active tool call must pass through.

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

The evidence engine (`omega/evidence/__init__.py`) provides:

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
