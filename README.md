# SENTINEL

**Agentic Security Research Platform** -- An MCP server for CTF solving, authorized bug bounty research, penetration testing, web/API security testing, reverse engineering, and reconnaissance.

Version 1.0.0 | Python 3.11+ | MCP SDK 2.0+

## Features

- **CTF Solving** -- Challenge management, hypothesis-driven flag hunting, hypothesis ledger tracking
- **Bug Bounty** -- Scope enforcement, SSRF protection, rate limiting, audit logging
- **Penetration Testing** -- Full reconnaissance pipeline, port scanning, service detection
- **Web/API Security** -- Header analysis, CORS testing, cookie auditing, endpoint discovery, JS secret scanning
- **Reconnaissance** -- Subdomain enumeration, HTTP probing, directory fuzzing, tech fingerprinting, crawling
- **Reverse Engineering** -- Binary analysis support (extensible adapter framework)
- **Evidence Pipeline** -- Immutable evidence records with automatic deduplication
- **Hypothesis-Driven Testing** -- Structured vulnerability hypothesis lifecycle
- **Asset Graph** -- In-memory + persistent graph for reasoning about discovered assets
- **Vulnerability Triage** -- nuclei/nikto scan results auto-map to `Finding` records (severity-guided, scope-stamped, deduplicated) when an engagement is active
- **Reporting** -- Markdown, HTML, and JSON report generation with findings and evidence
- **60+ MCP Tools** -- Complete toolset exposed via MCP protocol

## Why SENTINEL vs. other security MCPs

Most security MCP servers are thin wrappers around a CLI -- they give an agent
`subprocess` power but no discipline. SENTINEL inverts this: every network-reaching
action passes through a safety, evidence, and correctness layer first. The table
below maps the gaps commonly found in existing bug-bounty / pentest / CTF MCPs to
the SENTINEL counterpart.

### Safety & consent

| Shortcoming in typical security MCPs | SENTINEL solution |
|---|---|
| No scope enforcement -- the agent can hit any target it can reach | **Deny-by-default scope gating** on every live-target entry point (MCP, executor, orchestrated scans, REST/UI). No in-scope rule, no request. |
| No SSRF defense -- the agent will happily scan localhost/cloud metadata | **URL scheme + SSRF defenses** in `normalize_target_url`; IPv4/IPv6/private-host/DNS rebinding rules enforced before any request. |
| No rate limiting -- agents fire bursts that can take a target down | **Per-target token buckets + global worker pool** (normal / aggressive / stealth policies). No DoS/stress tooling ships. |
| No audit trail -- every action is invisible | **JSONL audit log + SQLite `authorizations` ledger**; every check, action, and denial is recorded with an attestation id. |
| No concept of consent per-tool -- one blanket approval unlocks everything | Per-engagement **mode** (`bug_bounty`, `ctf`, `local_lab`, `analysis_only`, `lab`), per-rule include/exclude patterns, `analysis_only` enforces passive-only tools. |

### Evidence & rigour

| Shortcoming in typical security MCPs | SENTINEL solution |
|---|---|
| Findings live only in the agent's chat context and vanish | **Immutable evidence records** (`EvidenceEngine`) with dedup, stored in SQLite, queryable later. |
| Raw tool spew is dumped on the agent with no structure | **Auto-triage pipeline**: nuclei / nikto results are mapped to `Finding` records with severity, CVE/OSVDB refs, scope stamping, and dedup. |
| No reporting -- results can't be handed to a human | **Markdown / HTML / JSON reports** generated from findings + evidence + authorization section. |
| No reproducibility -- each run re-does everything | **Recon cache** + engagement-scoped history; the platform stores what was tested, when, and why. |
| Unbounded scans hang the agent (dozens of sequential probes, no deadline) | **Bounded concurrency + deadlines**: `infer_endpoints` caps 96 probes under a 60s overall limit; every component is isolated so one failure never kills a scan. |
| Secrets (JWTs, tokens) leak back into the agent transcript | **`token_preview` redaction** -- full credentials are never serialized to MCP output. |

### Operations

| Shortcoming in typical security MCPs | SENTINEL solution |
|---|---|
| Missing binary == crash or cryptic traceback | **Structured `BINARY_MISSING` responses**; `sentinel_tools_list`, `sentinel_doctor`, `sentinel_health_check` report per-tool availability. |
| Unknown state -- is the server even healthy? | **`sentinel_health_check`** (DB/registry/cache/worker-pool → `ready|degraded`) + `sentinel /api/health` dashboard probe. |
| No structure for CTF work -- flags, hints, hypotheses get lost | **CTF module**: challenges, hypothesis ledger, flag confirm/submit, ledger replay per challenge. |
| No engagement/scoping model shared across tools | Every tool accepts `engagement_id`; one scope model gates recon, web, API, and orchestrated scans consistently. |
| No cross-checking of target lists -- agent passes mixed targets | `ToolExecutor` authorizes **every** target in a list, not just the primary. |
| Silent partial failures that corrupt results | `full_scan` returns `scan_errors` + `success` instead of all-or-nothing partial dicts. |

**In one line:** existing MCPs give agents *hands*; SENTINEL gives them *hands, a
perimeter fence, a notepad, and a flight recorder* -- so they can do the work of a
pentest/CTF/bug-bounty engagement without the destruction, the memory loss, or the
legal exposure.

## Security Authorization Model

SENTINEL enforces **deny-by-default scope gating** at every live-target (network-reaching) entry point. There are **no autonomous-exploitation workflows**: no tool, agent, or API route will send payloads, brute-force credentials, or launch load against a host that is not explicitly authorized by the engagement scope (§ in-scope rules, CTF/lab modes) and its execution mode.

**Where scope is enforced:**

| Surface | Enforcement point |
|---|---|
| MCP tools (`sentinel_*`) | Every handler calls `_scope_denial()` before touching a target; `analysis_only` engagements allow only *passive* tools without scope rules |
| Tool executor (agents/`targets` lists) | `ToolExecutor.execute` authorizes **every** target in `parameters["targets"]`, not just the primary |
| Orchestrated scans (`sentinel_scan`) | Handler-level `_scope_denial()` gate, active unless `scan_type="recon"` |
| REST/UI REST API (`/api/*`) | `_gate()` on all web, API-security, HTTP, and auth differential-test routes |

**Posture rules:**

- **No autonomous exploitation** -- findings are *validated* (reproduced) or *hypothesized*, never auto-exploited. The orchestrator's `validate_finding` only issues benign read-style requests.
- **No credential brute-forcing of live targets** -- no tool attempts login brute-force or password spraying against in-scope production targets.
- **No DoS/stress tooling** -- nothing runs drainable floods; rate limits (per-target token buckets + a global worker pool) cap request volume.
- **Authorization metadata** -- every finding is stamped with `authorization_status` (`authorized` / `not_in_scope` / `unverified`), the matched scope rule, engagement mode, and attestation id. Reports surface a "Scope & Authorization" section and per-finding authorization lines.
- **Audit trail** -- every scope check, action, and denial is written to the JSONL audit log and the SQLite `authorizations` ledger.

## Quick Start

```bash
git clone <repository-url>
cd sentinel
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
sentinel serve
```

That's it. The MCP server starts in stdio mode by default.

## Installation

### From source

```bash
git clone <repository-url>
cd sentinel

# Create virtual environment (Python 3.11+ required)
python3 -m venv .venv
source .venv/bin/activate

# Upgrade pip and install
pip install --upgrade pip setuptools wheel
pip install -e ".[dev]"

# For browser automation support
pip install -e ".[browser]"
```

### Install security tools (recommended)

```bash
# Recon tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Web fuzzing
go install -v github.com/ffuf/ffuf/v2@latest

# Directory brute-force
go install -v github.com/OJ/gobuster/v3@latest

# Port scanning (package manager)
apt install nmap          # Debian/Ubuntu
brew install nmap         # macOS

# Tech fingerprinting
apt install whatweb        # or brew install whatweb
```

### External binaries matrix

| Binary | SENTINEL adapter (`sentinel_*` tool) | Risk | Purpose | Availability probe |
|---|---|---|---|---|
| `subfinder` | recon · `sentinel_recon_subdomains` | passive | Passive subdomain enumeration | `sentinel_tools_list` |
| `httpx` | recon · `sentinel_recon_probe` | passive | Live-host probing, tech detection, titles | `sentinel_tools_list` |
| `katana` | recon · `sentinel_recon_crawl` | passive | Web crawling + JS endpoint discovery | `sentinel_tools_list` |
| `gospider` | recon · `sentinel_recon_webcrawl` | passive | Fast crawling, link/js/js_forms discovery | `sentinel_tools_list` |
| `whatweb` | recon · `sentinel_recon_tech` | passive | Technology fingerprinting | `sentinel_tools_list` |
| `wafw00f` | recon · `sentinel_recon_waf_detect` | passive | WAF / firewall fingerprinting | `sentinel_tools_list` |
| `dnsx` | recon · `sentinel_recon_dns_lookup` | passive | DNS resolution & record enumeration | `sentinel_tools_list` |
| `nmap` | recon · `sentinel_recon_portscan` | active | Port scanning, service + OS detection | `sentinel_tools_list` |
| `naabu` | recon · `sentinel_recon_fastportscan` | active | Fast SYN port scanning | `sentinel_tools_list` |
| `masscan` | recon · `sentinel_recon_port_rapid` | active | Internet-scale port scanning | `sentinel_tools_list` |
| `ffuf` | recon · `sentinel_recon_fuzz` | active | Directory/endpoint fuzzing | `sentinel_tools_list` |
| `gobuster` | recon · `sentinel_recon_dirbrute` | active | Directory + DNS brute-force | `sentinel_tools_list` |
| `nuclei` | recon · `sentinel_recon_vuln_scan` | active | Template-based vulnerability scanning | `sentinel_tools_list` |
| `nikto` | recon · `sentinel_recon_server_audit` | active | Web server vulnerability auditing | `sentinel_tools_list` |

Behavior: missing binaries never crash the server — affected tools return a structured `BINARY_MISSING` response. `sentinel_doctor` and `sentinel_health_check` surface which binaries are present; `sentinel_tools_list` reports per-tool availability.

## Configuration

Copy `.env.example` to `.env` and configure:

```bash
cp .env.example .env
```

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `SENTINEL_BASE_DIR` | `~/.sentinel` | Data directory for database and workspaces |
| `SENTINEL_RATE_POLICY` | `normal` | Rate limit policy: `normal`, `aggressive`, `stealth` |
| `SENTINEL_GLOBAL_RPS` | `10` | Global requests per second |
| `SENTINEL_TARGET_RPS` | `5` | Per-target requests per second |
| `SENTINEL_SANDBOX` | `true` | Enable sandboxed execution |
| `SENTINEL_REQUIRE_SCOPE` | `true` | Require scope validation before actions |
| `SENTINEL_CTF_SKIP_SCOPE` | `true` | Skip scope checks in CTF mode |
| `SENTINEL_HOST` | `127.0.0.1` | Server bind address |
| `SENTINEL_PORT` | `8443` | Server port (HTTP mode) |
| `SENTINEL_AUTH_ENABLED` | `false` | Enable bearer token authentication |
| `SENTINEL_AUTH_TOKEN` | (empty) | Bearer token (required if auth enabled) |
| `SENTINEL_BROWSER_ENABLED` | `false` | Enable Playwright browser automation |
| `SENTINEL_BROWSER_HEADLESS` | `true` | Run browser in headless mode |
| `SENTINEL_LOG_LEVEL` | `INFO` | Log level |

## Starting the Server

### Via CLI (recommended)

```bash
# Start in stdio mode (for MCP clients like OpenCode)
sentinel serve

# Start in HTTP mode
sentinel serve --transport http --host 127.0.0.1 --port 8443
```

### Via Python module

```bash
# stdio mode
python -m sentinel.mcp

# HTTP mode
python -m sentinel.mcp --transport http --host 127.0.0.1 --port 8443
```

### CLI commands

```bash
sentinel --help          # Show all commands
sentinel doctor          # Check system dependencies
sentinel tools           # List available security tools
sentinel inspect         # Inspect current configuration
sentinel serve           # Start MCP server
sentinel serve --help    # Server options
```

## OpenCode Configuration

Register the MCP server in your OpenCode config (`~/.config/opencode/opencode.json`):

```json
{
  "mcpServers": {
    "sentinel": {
      "command": "python",
      "args": ["-m", "sentinel.mcp"],
      "cwd": "/path/to/sentinel",
      "env": {
        "SENTINEL_BASE_DIR": "~/.sentinel",
        "SENTINEL_RATE_POLICY": "normal",
        "SENTINEL_LOG_LEVEL": "INFO"
      }
    }
  }
}
```

## First CTF Example

Step-by-step walkthrough for solving a web CTF challenge:

```
# 1. Create a CTF engagement
> Use sentinel_engagement_create with name="CTF Round 1", mode="ctf"

# 2. Add the challenge
> Use sentinel_ctf_challenge_create with:
    engagement_id=<id from step 1>
    name="Login Bypass"
    category="web"
    target="challenge.ctf.local"
    port=8080

# 3. Analyze the target
> Use sentinel_web_headers with url="http://challenge.ctf.local:8080"
> Use sentinel_web_cors with url="http://challenge.ctf.local:8080"
> Use sentinel_recon_crawl with target="http://challenge.ctf.local:8080", depth=2

# 4. Form a hypothesis
> Use sentinel_ctf_hypothesis with:
    challenge_id=<id from step 2>
    hypothesis="SQL injection on login form via username parameter"
    test_plan="Try ' OR 1=1 -- on /login endpoint"

# 5. Test the hypothesis
> Use sentinel_http_request with:
    method="POST"
    url="http://challenge.ctf.local:8080/login"
    json_body='{"username":"admin'\'' OR 1=1 --","password":"x"}'

# 6. Submit the flag
> Use sentinel_ctf_submit_flag with challenge_id=<id>, flag="flag{sql1_inj3ct3d}"

# 7. Confirm and check ledger
> Use sentinel_ctf_confirm_flag with challenge_id=<id>, flag="flag{sql1_inj3ct3d}"
> Use sentinel_ctf_ledger with challenge_id=<id>
```

## First Local Lab Example

Setting up a local security testing lab:

```
# 1. Create a local lab engagement
> Use sentinel_engagement_create with name="Home Lab", mode="local_lab"

# 2. Add scope rules (optional in local_lab, but good practice)
> Use sentinel_scope_add_rule with:
    engagement_id=<id>
    rule_type="include"
    target_type="cidr"
    pattern="192.168.1.0/24"

# 3. Run reconnaissance
> Use sentinel_recon_subdomains with target="lab.internal", engagement_id=<id>
> Use sentinel_recon_portscan with target="192.168.1.0/24", ports="1-1000", engagement_id=<id>

# 4. Probe live hosts
> Use sentinel_recon_probe with target="192.168.1.10", engagement_id=<id>

# 5. Full web scan
> Use sentinel_web_full_scan with target="192.168.1.10", engagement_id=<id>

# 6. Generate report
> Use sentinel_report_generate with engagement_id=<id>, format="markdown"
```

## First Authorized Bug Bounty Example

```
# 1. Create engagement
> Use sentinel_engagement_create with:
    name="TargetCo Bug Bounty"
    mode="bug_bounty"
    description="Authorized via HackerOne scope"

# 2. Define scope (REQUIRED -- bug_bounty mode denies all by default)
> Use sentinel_scope_add_rule with:
    engagement_id=<id>, rule_type="include", target_type="wildcard",
    pattern="*.target.com", description="Program scope"
> Use sentinel_scope_add_rule with:
    engagement_id=<id>, rule_type="exclude", target_type="domain",
    pattern="staging.target.com", description="Out of scope"

# 3. Verify scope
> Use sentinel_scope_check with engagement_id=<id>, target="api.target.com"   # allowed
> Use sentinel_scope_check with engagement_id=<id>, target="evil.com"         # denied

# 4. Passive recon (always safe)
> Use sentinel_recon_subdomains with target="target.com", engagement_id=<id>

# 5. Active testing (scope-validated)
> Use sentinel_recon_portscan with target="api.target.com", engagement_id=<id>
> Use sentinel_web_full_scan with target="https://api.target.com", engagement_id=<id>

# 6. Track findings
> Use sentinel_hypothesis_create with:
    engagement_id=<id>, category="idor", target="api.target.com",
    hypothesis="IDOR on /api/v1/users/{id} -- sequential IDs exposed"
> Use sentinel_finding_create with:
    engagement_id=<id>, title="IDOR on User Profiles", severity="high",
    affected_asset="api.target.com", affected_endpoint="/api/v1/users/{id}",
    cwe_id="CWE-639"

# 7. Generate report
> Use sentinel_report_generate with engagement_id=<id>, format="markdown"
```

## Troubleshooting

### Server won't start

```bash
# Check Python version (must be 3.11+)
python --version

# Verify installation
pip install -e ".[dev]"

# Check MCP SDK
pip show mcp  # Must be >= 2.0.0

# Run doctor
sentinel doctor
```

### Tests won't run

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests from project root
pytest -q
```

### Tools not found

```bash
# Check which tools are installed
sentinel tools

# Or via MCP
> Use sentinel_tools_list

# Install missing tools (see installation section above)
```

### Scope errors in CTF mode

CTF mode allows all targets by default. If you get scope errors:

```
# Make sure engagement mode is "ctf", not "analysis_only"
> Use sentinel_engagement_create with name="CTF", mode="ctf"
```

### Database errors

```bash
# Delete and recreate database
rm ~/.sentinel/sentinel.db

# Or set a fresh base directory
SENTINEL_BASE_DIR=/tmp/sentinel-fresh python -m sentinel.mcp
```

### Permission denied on tools

Some tools (nmap SYN scan) require root. Either:

- Run the server with appropriate privileges
- Use TCP connect scan: `sentinel_recon_portscan` with `scan_type="tcp"`
- Use `sentinel_recon_subdomains` (passive, no root needed)

### Rate limiting too aggressive

Adjust via environment variables:

```bash
SENTINEL_RATE_POLICY=relaxed SENTINEL_GLOBAL_RPS=50 SENTINEL_TARGET_RPS=20 python -m sentinel.mcp
```

## Documentation

- [`docs/TECHSTACK.md`](docs/TECHSTACK.md) -- every technology used, explained from scratch and why it was chosen
- [`docs/COMPARISON.md`](docs/COMPARISON.md) -- SENTINEL vs. every known pentest / bug-bounty / web-security / CTF MCP (named comparison)
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) -- system architecture and module map
- [`docs/SECURITY.md`](docs/SECURITY.md) -- security & authorization model
- [`docs/TESTING.md`](docs/TESTING.md) -- test guide
