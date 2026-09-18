# SENTINEL Security

## Security Model

SENTINEL is a security research tool that must itself be secure. The system enforces defense-in-depth through multiple layers:

1. **Scope enforcement** -- Every action is validated against engagement scope rules
2. **SSRF protection** -- Network destinations are validated before outbound requests
3. **Rate limiting** -- Per-target token-bucket rate limiting prevents abuse
4. **Audit logging** -- Every scope check, tool execution, and authorization decision is logged
5. **Subprocess isolation** -- External tools run with timeouts, output limits, and no shell injection vectors
6. **Secret handling** -- Credentials and tokens are never logged or included in reports

## Scope Modes and Permissions

Each engagement mode defines a different security posture:

### `ctf` -- Capture The Flag
- **Target scope**: Allow all targets unless explicitly excluded
- **Active testing**: Allowed
- **SSRF**: Localhost/metadata endpoints allowed only with explicit include
- **Use case**: CTF competitions, authorized hacking games

### `local_lab` -- Local Lab
- **Target scope**: Allow all targets (including localhost)
- **Active testing**: Allowed
- **SSRF**: Localhost allowed (for local service testing)
- **Use case**: Personal lab, vulnerable-by-design environments (DVWA, HackTheBox)

### `bug_bounty` -- Bug Bounty
- **Target scope**: Deny by default -- MUST add explicit include rules
- **Active testing**: Allowed (only on in-scope targets)
- **SSRF**: Cloud metadata and localhost always blocked
- **Use case**: HackerOne, Bugcrowd, Intigriti programs

### `pentest` -- Penetration Test
- **Target scope**: Deny by default -- MUST add explicit include rules
- **Active testing**: Allowed (only on in-scope targets)
- **SSRF**: Blocked
- **Use case**: Authorized penetration tests with defined scope

### `analysis_only` -- Analysis Only
- **Target scope**: Allow target checks
- **Active testing**: Blocked -- passive analysis only
- **SSRF**: Blocked
- **Use case**: Passive reconnaissance, code review, report analysis

### Other Modes (`reversing`, `api_security`, `web_security`, `network_security`)
- **Target scope**: Require include rules
- **Active testing**: Varies by mode
- **SSRF**: Blocked

## SSRF Protection

The `authorize_network_destination` method in `sentinel/scope/__init__.py:181` blocks requests to:

| Blocked Destination | Reason |
|---|---|
| `169.254.169.254` | AWS/GCP/Azure metadata endpoint |
| `metadata.google.internal` | GCP metadata endpoint |
| `localhost` | Local machine (except `local_lab` mode) |
| `127.0.0.1` | Loopback (except `local_lab` mode) |
| `0.0.0.0` | Unspecified address (except `local_lab` mode) |

```python
ssrf_blocked = ["169.254.169.254", "metadata.google.internal", "localhost", "127.0.0.1", "0.0.0.0"]
```

**Exception**: In `local_lab` mode, localhost/127.0.0.1/0.0.0.0 are allowed for testing local services.

All SSRF check results are audit-logged.

## Rate Limiting

Implemented as a per-target token-bucket algorithm in `sentinel/scope/__init__.py:35`.

### Rate Limit Policies

| Policy | RPS | Burst | Use Case |
|---|---|---|---|
| `stealth` | 1.0 | 3 | Stealthy recon, avoid detection |
| `normal` | 5.0 | 10 | Standard testing |
| `aggressive` | 20.0 | 50 | Fast scanning (authorized targets) |

### Configuration

Set via environment variables or engagement settings:

```bash
SENTINEL_RATE_POLICY=normal
SENTINEL_GLOBAL_RPS=10
SENTINEL_TARGET_RPS=5
```

Per-engagement rate limits can be set via the `rate_limit_policy` field on engagements.

Rate limit violations are audit-logged with the target and reason.

## Secret Handling

### No Secrets in Logs
- The server never logs authentication tokens, passwords, or API keys
- `SENTINEL_AUTH_TOKEN` is never included in tool output or reports
- Environment variable values are not exposed through any tool

### No Secrets in Reports
- `sentinel_report_generate` generates reports from findings and evidence
- Findings may contain descriptions of secret exposures (e.g., "API key found in JS") but never contain the actual secret values in the report content
- Evidence records store content hashes, not raw secrets

### Authorization Storage
- Credentials stored in the `authorizations` table are serialized as JSON
- They are only accessible within the engagement context
- Cross-engagement data isolation prevents leakage

## Subprocess Security

All external tool adapters (`sentinel/tools/__init__.py:70`) execute subprocesses with:

### No Shell Injection
```python
proc = await asyncio.create_subprocess_exec(
    *cmd,                    # List of arguments, NOT a shell string
    stdout=asyncio.subprocess.PIPE,
    stderr=asyncio.subprocess.PIPE,
    env=env,
)
```

- Commands are always passed as a list of strings to `create_subprocess_exec`
- `shell=True` is never used
- User-supplied parameters are passed as list elements, not interpolated into shell commands

### Timeouts
- Every subprocess has a configurable timeout (default: 300 seconds)
- Timeout violations kill the process and return an error
- No orphaned processes remain after timeout

### Output Limits
- Raw output is truncated to `max_output_bytes` (default: 2MB)
- Output stored in the database is further truncated (50KB for tool runs, 500KB for HTTP responses)
- Prevents memory exhaustion from large tool outputs

### Binary Validation
- Tool binaries are located via `shutil.which()` -- PATH-based lookup only
- No arbitrary binary execution
- Missing tools return clear error messages, never fall back to unsafe alternatives

## Audit Logging

Every security-relevant event is recorded in the `audit_log` table:

### Logged Event Types
| Event Type | Description |
|---|---|
| `scope_check` | Target authorization check |
| `action_check` | Action permission check |
| `mode_check` | Execution mode validation |
| `rate_limit` | Rate limit enforcement |
| `ssrf_check` | SSRF destination validation |
| `scope_denied` | Scope authorization failure |
| `tool_execution` | External tool invocation |
| `finding` | Finding creation/update |
| `evidence` | Evidence storage |
| `error` | Error conditions |

### Audit Record Structure
```json
{
  "id": "hex16",
  "engagement_id": "engagement_id",
  "event_type": "scope_check",
  "target": "example.com",
  "action": "authorize_target",
  "result": "Target authorized (matches: *.example.com)",
  "allowed": true,
  "metadata": {},
  "created_at": "ISO8601"
}
```

### Querying Audit Logs
```bash
# Via MCP
> Use sentinel_audit_log with engagement_id=<id>
```

Audit logs are append-only and cannot be modified or deleted through the API.

## Cross-Engagement Data Isolation

Each engagement's data is isolated:
- Findings, evidence, assets, and graph nodes are scoped to their engagement
- Queries always filter by `engagement_id`
- UUID-based IDs (16 hex chars) are not guessable
- Cross-engagement access is not possible through normal tool operations

## Known Limitations

1. **No TLS by default** -- The HTTP transport runs on localhost without TLS. Use a reverse proxy for remote access.

2. **No authentication by default** -- Bearer token auth is available but disabled by default. Enable with `SENTINEL_AUTH_ENABLED=true`.

3. **Local database** -- SQLite is used by default. For production deployments with concurrent access, consider the PostgreSQL adapter (configurable via `DatabaseConfig`).

4. **Tool binary trust** -- External tools (nmap, subfinder, etc.) must be trusted. The system cannot verify binary integrity.

5. **No encrypted evidence storage** -- Evidence content is stored in plaintext in the database. Encrypt the database file at rest for sensitive engagements.

6. **Rate limiter is in-memory** -- Rate limit state is per-process. Restarting the server resets rate limit buckets.

7. **CTF mode is permissive** -- CTF mode allows all targets by default. Only add exclusion rules for truly out-of-scope targets.

8. **SSRF protection is IP-based** -- DNS rebinding attacks that resolve to blocked IPs after the initial check could potentially bypass SSRF protection. Network-level controls are recommended for high-security environments.

9. **No built-in VPN/proxy** -- The HTTP client supports proxy configuration but does not manage VPN connections.

10. **Report content is not sanitized for HTML** -- HTML reports may contain raw user input. Do not serve HTML reports on public-facing servers without additional sanitization.
