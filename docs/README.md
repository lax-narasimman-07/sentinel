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
- **Reporting** -- Markdown, HTML, and JSON report generation with findings and evidence
- **30+ MCP Tools** -- Complete toolset exposed via MCP protocol

## Installation

### From source

```bash
git clone <repository-url>
cd omega-cyber-mcp

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

### MCP stdio mode (for MCP clients like OpenCode)

```bash
python -m omega.mcp
```

### HTTP mode

```bash
python -m omega.mcp --transport http --host 127.0.0.1 --port 8443
```

### CLI

```bash
# Check system dependencies
omega doctor

# List available tools
omega tools

# Inspect configuration
omega inspect

# Start server
omega serve --transport stdio
omega serve --transport http --port 9000
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
# Check Python version
python --version  # Must be 3.11+

# Check MCP SDK
pip show mcp  # Must be >= 2.0.0

# Run doctor
python -m omega.mcp  # Then call omega_doctor tool
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
