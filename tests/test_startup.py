"""Regression tests for omega start, CLI imports, and tool loading."""

import importlib
import subprocess
import sys

import pytest


class TestCLIImports:
    def test_import_omega_cli(self):
        import omega.cli
        assert hasattr(omega.cli, "main")

    def test_import_omega_tools(self):
        from omega.tools import ToolAdapter, ToolRegistry, ToolExecutor, load_adapters
        assert callable(load_adapters)

    def test_load_adapters_populates_registry(self):
        from omega.tools import ToolRegistry, load_adapters
        registry = ToolRegistry()
        load_adapters(registry)
        assert len(registry._adapters) > 0

    def test_tool_adapter_has_input_schema(self):
        from omega.tools import ToolAdapter
        from omega.recon import SubfinderAdapter
        adapter = SubfinderAdapter()
        schema = adapter.input_schema()
        assert isinstance(schema, dict)

    def test_all_recon_adapters_discovered(self):
        from omega.tools import ToolRegistry, load_adapters
        registry = ToolRegistry()
        load_adapters(registry)
        expected = [
            "subfinder", "httpx", "nmap", "ffuf", "whatweb",
            "gobuster", "katana", "nuclei", "nikto", "naabu",
            "wafw00f", "gospider", "dnsx", "masscan",
        ]
        for name in expected:
            assert name in registry._adapters, f"{name} not loaded"


class TestOmegaStart:
    def test_omega_cli_module_invocation(self):
        result = subprocess.run(
            [sys.executable, "-c", "from omega.cli import main; main(['--help'])"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert result.returncode == 0
        assert "OMEGA" in result.stdout

    def test_omega_cli_start_help(self):
        result = subprocess.run(
            [sys.executable, "-c", "from omega.cli import main; main(['start', '--help'])"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert result.returncode == 0
        assert "dashboard" in result.stdout.lower() or "mcp" in result.stdout.lower()

    def test_omega_cli_doctor(self):
        result = subprocess.run(
            [sys.executable, "-c", "from omega.cli import main; main(['doctor'])"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0
        assert "Core" in result.stdout or "Tools" in result.stdout

    def test_omega_cli_tools(self):
        result = subprocess.run(
            [sys.executable, "-c", "from omega.cli import main; main(['tools'])"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0
        assert "subfinder" in result.stdout or "nmap" in result.stdout
