"""Phase 1.4 — subprocess wrapper hardening regression tests.

Covers the shared subprocess utility contract:
- missing binary -> structured BINARY_MISSING result with install hint (never a raw OSError)
- nonzero exit -> structured INTERNAL failure with stderr surfaced
- timeout -> structured TIMEOUT failure (rc -1)
- output size capping
- no shell-string subprocess invocation anywhere in the adapter layer
"""

from __future__ import annotations

import asyncio
import inspect
import os
import sys

import sentinel.recon
import sentinel.tools
from sentinel.core.errors import ErrorCode, ToolError
from sentinel.core.schemas import (
    ToolCapability,
    ToolExecutionRequest,
    ToolRiskLevel,
    new_id,
    now_utc,
)

ADAPTER_NAMES = [
    "subfinder", "httpx", "nmap", "ffuf", "whatweb", "gobuster", "katana",
    "nuclei", "nikto", "naabu", "wafw00f", "gospider", "dnsx", "masscan",
]

WHOLE_PACKAGE = [
    os.path.join(os.path.dirname(sentinel.recon.__file__), "__init__.py"),
    os.path.join(os.path.dirname(sentinel.tools.__file__), "__init__.py"),
]


class ProbeAdapter(sentinel.tools.ToolAdapter):
    """Minimal adapter used to exercise the shared ToolAdapter helpers."""

    def name(self) -> str:
        return "definitely-not-a-real-binary-xyz"

    def version(self) -> str:
        return "1.0"

    def capabilities(self) -> ToolCapability:
        return ToolCapability(
            id=new_id(), name=self.name(), version="1.0", description="Probe",
            risk_level=ToolRiskLevel.READ_ONLY, is_available=False,
            created_at=now_utc(), updated_at=now_utc(),
        )

    async def execute(self, request: ToolExecutionRequest):
        raise NotImplementedError


# ═══════════════════════════════════════════════════════════════════════════
# Missing binary handling
# ═══════════════════════════════════════════════════════════════════════════

def test_missing_binary_result_includes_install_hint():
    adapter = ProbeAdapter()
    result = adapter._missing_binary_result()
    assert not result.success
    assert result.error.startswith("BINARY_MISSING:")
    assert "README" in result.error
    assert adapter.name() in result.error


def test_require_binary_raises_structured_toolerror():
    adapter = ProbeAdapter()
    try:
        adapter._require_binary()
    except ToolError as exc:
        assert exc.code == ErrorCode.BINARY_MISSING
        assert "README" in exc.message
    else:  # pragma: no cover - name is guaranteed absent
        raise AssertionError("_require_binary should raise for a missing binary")


def test_base_runner_missing_binary_returns_rc127_hint():
    async def _run():
        adapter = ProbeAdapter()
        stdout, stderr, rc, duration = await adapter._run_subprocess(
            ["definitely-not-a-real-binary-xyz", "-flag"])
        return stdout, stderr, rc, duration

    stdout, stderr, rc, duration = asyncio.run(_run())
    assert rc == 127
    assert stdout == ""
    assert "Command not found" in stderr
    assert "README" in stderr


def test_base_runner_missing_binary_abs_path_returns_rc127():
    async def _run():
        adapter = ProbeAdapter()
        return await adapter._run_subprocess_with_input(
            ["/nonexistent/definitely-not-here"], input_data=b"x")

    stdout, stderr, rc, duration = asyncio.run(_run())
    assert rc == 127
    assert "Command not found" in stderr


def test_binary_missing_run_detects_executable():
    adapter = ProbeAdapter()
    assert adapter._binary_missing_run([sys.executable]) is None
    missing = adapter._binary_missing_run(["/nonexistent/definitely-not-here"])
    assert missing is not None
    assert missing[2] == 127


# ═══════════════════════════════════════════════════════════════════════════
# _run_failure normalization
# ═══════════════════════════════════════════════════════════════════════════

def test_run_failure_success_is_none():
    adapter = ProbeAdapter()
    assert adapter._run_failure("out", "", 0, 12.5) is None


def test_run_failure_nonzero_rc_surfaces_stderr():
    adapter = ProbeAdapter()
    failure = adapter._run_failure("", "boom: something broke\n", 1, 33.0)
    assert failure is not None
    assert not failure.success
    assert failure.error.startswith("INTERNAL:")
    assert "something broke" in failure.error
    assert failure.duration_ms == 33.0


def test_run_failure_timeout_is_flagged():
    adapter = ProbeAdapter()
    failure = adapter._run_failure("", "Command timed out after 5s", -1, 5000.0)
    assert failure is not None
    assert failure.error.startswith("TIMEOUT:")
    assert "timed out" in failure.error.lower()


def test_run_failure_missing_binary_rc127_maps_to_binary_missing():
    adapter = ProbeAdapter()
    failure = adapter._run_failure("", "Command not found: 'ffuf'", 127, 0.0)
    assert failure is not None
    assert failure.error.startswith("BINARY_MISSING:")
    assert "'ffuf'" in failure.error


# ═══════════════════════════════════════════════════════════════════════════
# Output size capping (real spawn, real truncation)
# ═══════════════════════════════════════════════════════════════════════════

def test_base_runner_caps_large_output():
    async def _run():
        adapter = ProbeAdapter()
        stdout, _stderr, rc, _duration = await adapter._run_subprocess(
            [sys.executable, "-c", "print('x' * 1_000_000)"],
            timeout=30,
            max_output_bytes=200,
        )
        return stdout, rc

    stdout, rc = asyncio.run(_run())
    assert rc == 0
    assert len(stdout) <= 200
    assert stdout.strip().startswith("x" * 200) or len(stdout.strip()) == 200


def test_max_output_bytes_defaults_to_2mb():
    adapter = ProbeAdapter()
    assert adapter._max_output_bytes() == 2_000_000


# ═══════════════════════════════════════════════════════════════════════════
# Adapter integration: execute() must normalize subprocess failure (not raise)
# ═══════════════════════════════════════════════════════════════════════════

def test_adapter_execute_returns_structured_failure_on_timeout(monkeypatch):
    async def fake_run(self, cmd, timeout=..., max_output_bytes=..., **kwargs):
        return "", "Command timed out after 5s", -1, 5012.0

    monkeypatch.setattr(sentinel.recon.SubfinderAdapter, "_run_subprocess", fake_run)
    adapter = sentinel.recon.SubfinderAdapter()
    adapter._find_binary = lambda: "/usr/bin/subfinder"  # pretend installed
    request = ToolExecutionRequest(tool_name="subfinder", target="example.com")

    result = asyncio.run(adapter.execute(request))
    assert not result.success
    assert "TIMEOUT" in result.error
    assert result.duration_ms == 5012.0


def test_adapter_execute_returns_missing_binary_result(monkeypatch):
    monkeypatch.setattr(sentinel.recon.NaabuAdapter, "_find_binary", lambda self: None)
    adapter = sentinel.recon.NaabuAdapter()
    request = ToolExecutionRequest(tool_name="naabu", target="example.com")
    result = asyncio.run(adapter.execute(request))
    assert not result.success
    assert result.error.startswith("BINARY_MISSING:")
    assert "README" in result.error


# ═══════════════════════════════════════════════════════════════════════════
# Migration completeness + no shell-string subprocess anywhere
# ═══════════════════════════════════════════════════════════════════════════

def test_every_recon_adapter_uses_shared_hardened_helpers():
    src = inspect.getsource(sentinel.recon)
    assert src.count("self._missing_binary_result()") >= len(ADAPTER_NAMES)
    assert src.count("self._run_failure(") >= len(ADAPTER_NAMES)
    assert src.count("self._max_output_bytes()") >= len(ADAPTER_NAMES)
    assert '" not found"' not in src


def test_no_shell_string_subprocess_invocation():
    """Subprocesses must always go through exec (arg array), never a shell."""
    for path in WHOLE_PACKAGE:
        with open(path) as f:
            src = f.read()
        assert "create_subprocess_shell" not in src
        assert "shell=True" not in src
        assert "subprocess.run(" not in src or _shell_exec_arg_absent(src)


def _shell_exec_arg_absent(src: str) -> bool:
    # Ensure any subprocess() usage never builds commands via string concat into
    # a shell string; the adapter layer should only use exec-style arg lists.
    return "cmd = \"" not in src and "cmd = '" not in src
