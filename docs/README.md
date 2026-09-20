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
- **Reporting** -- Markdown, HTML, and JSON report generation with findings and evidence
- **62 MCP Tools** -- Complete toolset exposed via MCP protocol

## Installation

### From source

```bash
git clone <repository-url>
cd sentinel

# Create virtual environment
python3.11 -m venv .venv
source .venv/bin/activate

# Install in development mode
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

### MCP stdio mode (for MCP clients like OpenCode)

```bash
python -m sentinel.mcp
```

### HTTP mode

```bash
python -m sentinel.mcp --transport http --host 127.0.0.1 --port 8443
```

### CLI

```bash
# Check system dependencies
sentinel doctor

# List available tools
sentinel tools

# Inspect configuration
sentinel inspect

# Start server
sentinel serve --transport stdio
sentinel serve --transport http --port 9000
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
# Check Python version
python --version  # Must be 3.11+

# Check MCP SDK
pip show mcp  # Must be >= 2.0.0

# Run doctor
python -m sentinel.mcp  # Then call sentinel_doctor tool
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
