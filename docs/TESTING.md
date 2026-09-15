# OMEGA-CYBER-MCP Testing Guide

## Running All Tests

```bash
# From project root with venv activated
pytest -v

# Or with explicit path
pytest tests/ -v

# Run with output for failed tests
pytest -v --tb=short

# Run with coverage
pytest --cov=omega --cov-report=term-missing
```

## Test Categories

### Unit Tests (`tests/test_core.py`)

Fast tests that validate individual components without network calls or MCP server startup.

**Test classes:**
| Class | Tests | Description |
|---|---|---|
| `TestSchemas` | 5 | Pydantic model creation, enums, helper functions |
| `TestDatabase` | 5 | SQLite CRUD operations (connect, insert, upsert, query, delete, count) |
| `TestScopeEngine` | 11 | Scope authorization, CTF/bug_bounty/local_lab modes, SSRF, rate limiting |
| `TestAssetGraph` | 7 | Graph nodes, edges, dedup, neighbors, pathfinding |
| `TestEvidenceEngine` | 5 | Evidence storage, deduplication, HTTP pairs, tool output |
| `TestFindingEngine` | 7 | Finding lifecycle, dedup, validation, rejection, hypothesis tracking |
| `TestCTFEngine` | 5 | Challenge creation, hypothesis ledger, flag submission/confirmation |
| `TestToolRegistry` | 3 | Tool registration, discovery |
| `TestToolExecutor` | 2 | Tool execution, unknown tool handling |
| `TestReportEngine` | 2 | Markdown and JSON report generation |
| `TestWorkspace` | 3 | Workspace creation, subdirectories, file I/O |
| `TestOrchestrator` | 2 | Engagement creation, scan execution |
| `TestMCPServer` | 2 | Server import, tool registration |

### Integration Tests (`tests/test_integration.py`)

End-to-end tests that spin up a real MCP server subprocess, connect via the MCP client SDK, and exercise real tool calls. Uses a local test fixture server (`tests/fixtures.py`).

**Test groups:**
| Group | Tests | Description |
|---|---|---|
| Scope Pipeline | 1 | Scope -> engagement -> graph nodes -> query -> persistence |
| Web Security | 6 | Headers, CORS, cookies, endpoints, JS analysis, full scan |
| HTTP Client | 4 | GET, POST, 404, request history |
| Evidence Engine | 1 | Hypothesis -> evidence pipeline |
| Finding Lifecycle | 3 | Full lifecycle (hypothesis -> validated), rejection, deduplication |
| CTF Workflow | 2 | Create -> hypothesis -> flag -> confirm, failed attempts |
| Asset Graph | 2 | Full chain, persistence across server restarts |
| Orchestrator | 1 | Multi-step scan with analysis_only mode |
| Reports | 2 | Markdown and JSON report generation |
| Recon Tools | 3 | Tools list, doctor checks, scope enforcement (bug_bounty and CTF) |
| API Security | 3 | Endpoint discovery, auth differential, IDOR hypothesis |

### MCP Protocol Tests (`tests/test_mcp_protocol.py`)

Validates the MCP protocol layer -- handshake, tool listing, and individual tool calls over the wire.

**Tests:**
| Test | Description |
|---|---|
| `test_initialize_handshake` | MCP ping after initialization |
| `test_list_tools_returns_expected` | All 30+ expected tools are registered |
| `test_list_tools_not_empty` | Server reports > 0 tools |
| `test_omega_doctor_returns_structured_output` | Doctor returns Python version, platform, tools |
| `test_omega_engagement_create` | Engagement creation via MCP |
| `test_omega_engagement_list` | Engagement listing via MCP |
| `test_omega_scope_check_in_and_out_of_scope` | Scope check for in-scope and out-of-scope targets |
| `test_omega_scope_add_rule_and_list` | Add and list scope rules |
| `test_omega_tools_list` | Tool discovery listing |
| `test_omega_hypothesis_create` | Hypothesis creation via MCP |
| `test_omega_finding_create_and_list` | Finding create and list |
| `test_omega_finding_summary` | Finding summary by severity |
| `test_omega_graph_workflow` | Graph add node, edge, query |
| `test_omega_ctf_challenge_workflow` | CTF challenge -> hypothesis -> flag -> confirm -> ledger |
| `test_omega_audit_log` | Audit log retrieval |
| `test_omega_report_generate` | Report generation via MCP |
| `test_server_rejects_bad_tool_name` | Unknown tool returns error |

### Security Tests (`tests/test_security.py`)

Validates that security controls are enforced correctly.

**Test groups:**
| Group | Tests | Description |
|---|---|---|
| Scope Bypass | 4 | No-engagement deny, bug_bounty no-rules, wildcard scope, redirect to OOS |
| SSRF Protection | 2 | Localhost blocking, cloud metadata endpoint blocking |
| Command Injection | 1 | Tool output treated as data, not code |
| Secret Handling | 3 | No auth tokens in output, no env vars exposed, no DB path leak |
| Rate Limiting | 1 | Rapid calls don't crash server |
| Input Validation | 5 | Invalid JSON, empty args, long input, unicode, null bytes |
| Data Isolation | 2 | Cross-engagement isolation, wrong engagement finding validation |
| Server Resilience | 3 | Invalid tool calls, concurrent operations, error recovery |

## Running Specific Test Groups

```bash
# Run only unit tests
pytest tests/test_core.py -v

# Run only integration tests
pytest tests/test_integration.py -v

# Run only MCP protocol tests
pytest tests/test_mcp_protocol.py -v

# Run only security tests
pytest tests/test_security.py -v

# Run a specific test class
pytest tests/test_core.py::TestScopeEngine -v

# Run a specific test
pytest tests/test_core.py::TestScopeEngine::test_ssrf_protection -v

# Run tests matching a keyword
pytest -k "scope" -v
pytest -k "ctf" -v
pytest -k "finding" -v
pytest -v

# Run tests and stop on first failure
pytest -x -v

# Run tests in parallel (requires pytest-xdist)
pytest -n auto -v
```

## Local Test Fixture Server

The integration tests use a built-in vulnerable web application (`tests/fixtures.py`) for testing web security tools.

### `TestServer`
- Threaded HTTP server on `127.0.0.1:0` (random available port)
- Provides realistic endpoints for testing

### Available Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | HTML page with navigation links |
| `/login` | GET/POST | Login form + credential check |
| `/api/users` | GET | JSON user list (requires auth header for full access) |
| `/api/secret` | GET | Returns 403 (forbidden) |
| `/api/config` | GET | Config with embedded secrets (for JS analysis testing) |
| `/api/v1/items` | GET | Item list |
| `/api/v1/items/{id}` | GET | Single item (for IDOR testing) |
| `/search` | GET | Reflected query parameter (for XSS testing) |
| `/admin` | GET | Returns 401 (unauthorized) |
| `/static/app.js` | GET | JavaScript with hardcoded API keys (for secret scanning) |
| `/health` | GET | Health check |
| `/cookies` | GET | Sets cookies with various security properties |
| `/cors-test` | GET | Reflects Origin header (for CORS testing) |
| `/redirect-out` | GET | 302 redirect to external domain |

### Using the Fixture Server

The fixture server is auto-managed by integration tests:

```python
from tests.fixtures import TestServer

server = TestServer(port=0)
port = server.start()
# Use http://127.0.0.1:{port} as target
server.stop()
```

## Test Environment Variables

Tests use isolated temporary directories for each server instance:

```python
env={"OMEGA_BASE_DIR": tmpdir}
```

This ensures:
- Fresh database schema for each test
- No cross-test contamination
- Automatic cleanup

**No external environment variables are required for tests.**

## CI/CD Considerations

### Required Dependencies

```bash
pip install -e ".[dev]"
# Installs: pytest, pytest-asyncio, ruff, mypy
```

### CI Configuration

```yaml
# Example GitHub Actions
- name: Install dependencies
  run: pip install -e ".[dev]"

- name: Lint
  run: ruff check omega/ tests/

- name: Type check
  run: mypy omega/

- name: Run tests
  run: pytest -v --tb=short
```

### Important Notes

1. **MCP protocol tests require the venv Python** -- Tests reference `.venv/bin/python` for subprocess startup. Ensure the venv is created before running tests.

2. **Integration tests take longer** -- Each test spins up a fresh MCP server subprocess. Expect 30-60 seconds for the full integration suite.

3. **Security tools are optional** -- Tests that depend on external tools (nmap, subfinder, etc.) will skip gracefully if tools are not installed. The test suite passes without any security tools installed.

4. **Port conflicts** -- Tests use random available ports (`port=0`). No port conflicts should occur.

5. **Concurrent test execution** -- Tests are not designed for parallel execution within the same file. Use `pytest-xdist` with `-n auto` for parallel file-level execution.

6. **Database cleanup** -- Each test creates a temporary directory that is automatically cleaned up by `tempfile.TemporaryDirectory`. No manual cleanup is needed.

7. **Linting** -- Run `ruff check omega/ tests/` before committing. The project uses:
   - Line length: 120
   - Target: Python 3.11
   - Rules: E, F, W, I, N, UP, S, B, A, C4, SIM, TCH

8. **Type checking** -- Run `mypy omega/` with strict mode enabled.
