# OMEGA-CYBER-MCP

**Agentic Security Research Platform** -- An MCP server for CTF solving, authorized bug bounty research, penetration testing, web/API security testing, reverse engineering, and reconnaissance.

Version 0.1.0 | Python 3.11+ | MCP SDK 2.0+

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

## Security Authorization Model

OMEGA enforces **deny-by-default scope gating** at every live-target (network-reaching) entry point. There are **no autonomous-exploitation workflows**: no tool, agent, or API route will send payloads, brute-force credentials, or launch load against a host that is not explicitly authorized by the engagement scope (§ in-scope rules, CTF/lab modes) and its execution mode.

**Where scope is enforced:**

| Surface | Enforcement point |
|---|---|
| MCP tools (`omega_*`) | Every handler calls `_scope_denial()` before touching a target; `analysis_only` engagements allow only *passive* tools without scope rules |
| Tool executor (agents/`targets` lists) | `ToolExecutor.execute` authorizes **every** target in `parameters["targets"]`, not just the primary |
| Orchestrated scans (`omega_scan`) | Handler-level `_scope_denial()` gate, active unless `scan_type="recon"` |
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
cd omega-cyber-mcp
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
omega serve
```

That's it. The MCP server starts in stdio mode by default.

## Installation

### From source

```bash
git clone <repository-url>
cd omega-cyber-mcp

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

| Binary | OMEGA adapter (`omega_*` tool) | Risk | Purpose | Availability probe |
|---|---|---|---|---|
| `subfinder` | recon · `omega_recon_subdomains` | passive | Passive subdomain enumeration | `omega_tools_list` |
| `httpx` | recon · `omega_recon_probe` | passive | Live-host probing, tech detection, titles | `omega_tools_list` |
| `katana` | recon · `omega_recon_crawl` | passive | Web crawling + JS endpoint discovery | `omega_tools_list` |
| `gospider` | recon · `omega_recon_webcrawl` | passive | Fast crawling, link/js/js_forms discovery | `omega_tools_list` |
| `whatweb` | recon · `omega_recon_tech` | passive | Technology fingerprinting | `omega_tools_list` |
| `wafw00f` | recon · `omega_recon_waf_detect` | passive | WAF / firewall fingerprinting | `omega_tools_list` |
| `dnsx` | recon · `omega_recon_dns_lookup` | passive | DNS resolution & record enumeration | `omega_tools_list` |
| `nmap` | recon · `omega_recon_portscan` | active | Port scanning, service + OS detection | `omega_tools_list` |
| `naabu` | recon · `omega_recon_fastportscan` | active | Fast SYN port scanning | `omega_tools_list` |
| `masscan` | recon · `omega_recon_port_rapid` | active | Internet-scale port scanning | `omega_tools_list` |
| `ffuf` | recon · `omega_recon_fuzz` | active | Directory/endpoint fuzzing | `omega_tools_list` |
| `gobuster` | recon · `omega_recon_dirbrute` | active | Directory + DNS brute-force | `omega_tools_list` |
| `nuclei` | recon · `omega_recon_vuln_scan` | active | Template-based vulnerability scanning | `omega_tools_list` |
| `nikto` | recon · `omega_recon_server_audit` | active | Web server vulnerability auditing | `omega_tools_list` |

Behavior: missing binaries never crash the server — affected tools return a structured `BINARY_MISSING` response. `omega_doctor` and `omega_health_check` surface which binaries are present; `omega_tools_list` reports per-tool availability.

## Configuration

Copy `.env.example` to `.env` and configure:

```bash
cp .env.example .env
```

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `OMEGA_BASE_DIR` | `~/.omega` | Data directory for database and workspaces |
| `OMEGA_RATE_POLICY` | `normal` | Rate limit policy: `normal`, `aggressive`, `stealth` |
| `OMEGA_GLOBAL_RPS` | `10` | Global requests per second |
| `OMEGA_TARGET_RPS` | `5` | Per-target requests per second |
| `OMEGA_SANDBOX` | `true` | Enable sandboxed execution |
| `OMEGA_REQUIRE_SCOPE` | `true` | Require scope validation before actions |
| `OMEGA_CTF_SKIP_SCOPE` | `true` | Skip scope checks in CTF mode |
| `OMEGA_HOST` | `127.0.0.1` | Server bind address |
| `OMEGA_PORT` | `8443` | Server port (HTTP mode) |
| `OMEGA_AUTH_ENABLED` | `false` | Enable bearer token authentication |
| `OMEGA_AUTH_TOKEN` | (empty) | Bearer token (required if auth enabled) |
| `OMEGA_BROWSER_ENABLED` | `false` | Enable Playwright browser automation |
| `OMEGA_BROWSER_HEADLESS` | `true` | Run browser in headless mode |
| `OMEGA_LOG_LEVEL` | `INFO` | Log level |

## Starting the Server

### Via CLI (recommended)

```bash
# Start in stdio mode (for MCP clients like OpenCode)
omega serve

# Start in HTTP mode
omega serve --transport http --host 127.0.0.1 --port 8443
```

### Via Python module

```bash
# stdio mode
python -m omega.mcp

# HTTP mode
python -m omega.mcp --transport http --host 127.0.0.1 --port 8443
```

### CLI commands

```bash
omega --help          # Show all commands
omega doctor          # Check system dependencies
omega tools           # List available security tools
omega inspect         # Inspect current configuration
omega serve           # Start MCP server
omega serve --help    # Server options
```

## OpenCode Configuration

Register the MCP server in your OpenCode config (`~/.config/opencode/opencode.json`):

```json
{
  "mcpServers": {
    "omega-cyber-mcp": {
      "command": "python",
      "args": ["-m", "omega.mcp"],
      "cwd": "/path/to/omega-cyber-mcp",
      "env": {
        "OMEGA_BASE_DIR": "~/.omega",
        "OMEGA_RATE_POLICY": "normal",
        "OMEGA_LOG_LEVEL": "INFO"
      }
    }
  }
}
```

## First CTF Example

Step-by-step walkthrough for solving a web CTF challenge:

```
# 1. Create a CTF engagement
> Use omega_engagement_create with name="CTF Round 1", mode="ctf"

# 2. Add the challenge
> Use omega_ctf_challenge_create with:
    engagement_id=<id from step 1>
    name="Login Bypass"
    category="web"
    target="challenge.ctf.local"
    port=8080

# 3. Analyze the target
> Use omega_web_headers with url="http://challenge.ctf.local:8080"
> Use omega_web_cors with url="http://challenge.ctf.local:8080"
> Use omega_recon_crawl with target="http://challenge.ctf.local:8080", depth=2

# 4. Form a hypothesis
> Use omega_ctf_hypothesis with:
    challenge_id=<id from step 2>
    hypothesis="SQL injection on login form via username parameter"
    test_plan="Try ' OR 1=1 -- on /login endpoint"

# 5. Test the hypothesis
> Use omega_http_request with:
    method="POST"
    url="http://challenge.ctf.local:8080/login"
    json_body='{"username":"admin'\'' OR 1=1 --","password":"x"}'

# 6. Submit the flag
> Use omega_ctf_submit_flag with challenge_id=<id>, flag="flag{sql1_inj3ct3d}"

# 7. Confirm and check ledger
> Use omega_ctf_confirm_flag with challenge_id=<id>, flag="flag{sql1_inj3ct3d}"
> Use omega_ctf_ledger with challenge_id=<id>
```

## First Local Lab Example

Setting up a local security testing lab:

```
# 1. Create a local lab engagement
> Use omega_engagement_create with name="Home Lab", mode="local_lab"

# 2. Add scope rules (optional in local_lab, but good practice)
> Use omega_scope_add_rule with:
    engagement_id=<id>
    rule_type="include"
    target_type="cidr"
    pattern="192.168.1.0/24"

# 3. Run reconnaissance
> Use omega_recon_subdomains with target="lab.internal", engagement_id=<id>
> Use omega_recon_portscan with target="192.168.1.0/24", ports="1-1000", engagement_id=<id>

# 4. Probe live hosts
> Use omega_recon_probe with target="192.168.1.10", engagement_id=<id>

# 5. Full web scan
> Use omega_web_full_scan with target="192.168.1.10", engagement_id=<id>

# 6. Generate report
> Use omega_report_generate with engagement_id=<id>, format="markdown"
```

## First Authorized Bug Bounty Example

```
# 1. Create engagement
> Use omega_engagement_create with:
    name="TargetCo Bug Bounty"
    mode="bug_bounty"
    description="Authorized via HackerOne scope"

# 2. Define scope (REQUIRED -- bug_bounty mode denies all by default)
> Use omega_scope_add_rule with:
    engagement_id=<id>, rule_type="include", target_type="wildcard",
    pattern="*.target.com", description="Program scope"
> Use omega_scope_add_rule with:
    engagement_id=<id>, rule_type="exclude", target_type="domain",
    pattern="staging.target.com", description="Out of scope"

# 3. Verify scope
> Use omega_scope_check with engagement_id=<id>, target="api.target.com"   # allowed
> Use omega_scope_check with engagement_id=<id>, target="evil.com"         # denied

# 4. Passive recon (always safe)
> Use omega_recon_subdomains with target="target.com", engagement_id=<id>

# 5. Active testing (scope-validated)
> Use omega_recon_portscan with target="api.target.com", engagement_id=<id>
> Use omega_web_full_scan with target="https://api.target.com", engagement_id=<id>

# 6. Track findings
> Use omega_hypothesis_create with:
    engagement_id=<id>, category="idor", target="api.target.com",
    hypothesis="IDOR on /api/v1/users/{id} -- sequential IDs exposed"
> Use omega_finding_create with:
    engagement_id=<id>, title="IDOR on User Profiles", severity="high",
    affected_asset="api.target.com", affected_endpoint="/api/v1/users/{id}",
    cwe_id="CWE-639"

# 7. Generate report
> Use omega_report_generate with engagement_id=<id>, format="markdown"
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
omega doctor
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
omega tools

# Or via MCP
> Use omega_tools_list

# Install missing tools (see installation section above)
```

### Scope errors in CTF mode

CTF mode allows all targets by default. If you get scope errors:

```
# Make sure engagement mode is "ctf", not "analysis_only"
> Use omega_engagement_create with name="CTF", mode="ctf"
```

### Database errors

```bash
# Delete and recreate database
rm ~/.omega/omega.db

# Or set a fresh base directory
OMEGA_BASE_DIR=/tmp/omega-fresh python -m omega.mcp
```

### Permission denied on tools

Some tools (nmap SYN scan) require root. Either:

- Run the server with appropriate privileges
- Use TCP connect scan: `omega_recon_portscan` with `scan_type="tcp"`
- Use `omega_recon_subdomains` (passive, no root needed)

### Rate limiting too aggressive

Adjust via environment variables:

```bash
OMEGA_RATE_POLICY=relaxed OMEGA_GLOBAL_RPS=50 OMEGA_TARGET_RPS=20 python -m omega.mcp
```
