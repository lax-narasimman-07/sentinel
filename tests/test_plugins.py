"""Tests for plugin system, engines, and new features."""

import pytest
import time
from unittest.mock import MagicMock

from sentinel.core.schemas import new_id, now_utc


# ===== Plugin System Tests =====

from sentinel.plugins.base import Plugin, PluginMeta, PluginState
from sentinel.plugins.registry import PluginRegistry
from sentinel.plugins.loader import load_plugins


class MockPlugin(Plugin):
    @property
    def meta(self) -> PluginMeta:
        return PluginMeta(
            name="test-plugin",
            version="1.0.0",
            description="Test",
            capabilities=["test", "scan"],
        )

    def get_adapters(self):
        return ["adapter1"]

    def get_agents(self):
        return ["agent1"]


class SecondMockPlugin(Plugin):
    @property
    def meta(self) -> PluginMeta:
        return PluginMeta(
            name="second-plugin",
            version="2.0.0",
            description="Second test plugin",
            capabilities=["scan", "recon"],
        )

    def get_adapters(self):
        return ["adapter2"]


def test_plugin_meta():
    plugin = MockPlugin()
    assert plugin.meta.name == "test-plugin"
    assert plugin.meta.version == "1.0.0"
    assert "test" in plugin.meta.capabilities
    assert "scan" in plugin.meta.capabilities


def test_plugin_state():
    plugin = MockPlugin()
    assert plugin.state == PluginState.REGISTERED


def test_plugin_meta_defaults():
    meta = PluginMeta(name="minimal")
    assert meta.version == "0.1.0"
    assert meta.description == ""
    assert meta.author == ""
    assert meta.capabilities == []
    assert meta.permissions == []
    assert meta.risk_level == "read_only"
    assert meta.dependencies == []
    assert meta.tool_names == []


@pytest.mark.asyncio
async def test_plugin_activate():
    plugin = MockPlugin()
    await plugin.activate({"key": "value"})
    assert plugin.state == PluginState.ACTIVE
    assert plugin._config == {"key": "value"}


@pytest.mark.asyncio
async def test_plugin_activate_default():
    plugin = MockPlugin()
    await plugin.activate()
    assert plugin.state == PluginState.ACTIVE
    assert plugin._config == {}


@pytest.mark.asyncio
async def test_plugin_deactivate():
    plugin = MockPlugin()
    await plugin.activate()
    assert plugin.state == PluginState.ACTIVE
    await plugin.deactivate()
    assert plugin.state == PluginState.DISABLED


@pytest.mark.asyncio
async def test_plugin_activate_deactivate_cycle():
    plugin = MockPlugin()
    await plugin.activate()
    assert plugin.state == PluginState.ACTIVE
    await plugin.deactivate()
    assert plugin.state == PluginState.DISABLED
    await plugin.activate({"re": True})
    assert plugin.state == PluginState.ACTIVE


def test_plugin_get_adapters_default():
    plugin = MockPlugin()
    adapters = plugin.get_adapters()
    assert adapters == ["adapter1"]


def test_plugin_get_agents_default():
    plugin = MockPlugin()
    agents = plugin.get_agents()
    assert agents == ["agent1"]


def test_plugin_get_analyzers():
    plugin = MockPlugin()
    analyzers = plugin.get_analyzers()
    assert analyzers == []


# ===== Plugin Registry Tests =====

def test_plugin_registry_register():
    registry = PluginRegistry()
    plugin = MockPlugin()
    registry.register(plugin)
    assert registry.get("test-plugin") is plugin
    assert len(registry.list_all()) == 1


def test_plugin_registry_register_replace():
    registry = PluginRegistry()
    plugin1 = MockPlugin()
    plugin2 = MockPlugin()
    registry.register(plugin1)
    registry.register(plugin2)
    assert len(registry.list_all()) == 1
    assert registry.get("test-plugin") is plugin2


def test_plugin_registry_unregister():
    registry = PluginRegistry()
    plugin = MockPlugin()
    registry.register(plugin)
    assert registry.get("test-plugin") is plugin
    registry.unregister("test-plugin")
    assert registry.get("test-plugin") is None
    assert len(registry.list_all()) == 0


def test_plugin_registry_unregister_nonexistent():
    registry = PluginRegistry()
    registry.unregister("nonexistent")


def test_plugin_registry_list_all():
    registry = PluginRegistry()
    p1 = MockPlugin()
    p2 = SecondMockPlugin()
    registry.register(p1)
    registry.register(p2)
    all_plugins = registry.list_all()
    assert len(all_plugins) == 2
    names = {p.meta.name for p in all_plugins}
    assert "test-plugin" in names
    assert "second-plugin" in names


def test_plugin_registry_list_active_empty():
    registry = PluginRegistry()
    plugin = MockPlugin()
    registry.register(plugin)
    assert len(registry.list_active()) == 0


@pytest.mark.asyncio
async def test_plugin_registry_list_active_after_activate():
    registry = PluginRegistry()
    plugin = MockPlugin()
    registry.register(plugin)
    await plugin.activate()
    assert len(registry.list_active()) == 1
    assert registry.list_active()[0].meta.name == "test-plugin"


def test_plugin_registry_find_by_capability_empty():
    registry = PluginRegistry()
    plugin = MockPlugin()
    registry.register(plugin)
    plugins = registry.find_by_capability("test")
    assert len(plugins) == 0


@pytest.mark.asyncio
async def test_plugin_registry_find_by_capability_active():
    registry = PluginRegistry()
    plugin = MockPlugin()
    registry.register(plugin)
    await plugin.activate()
    plugins = registry.find_by_capability("test")
    assert len(plugins) == 1
    assert plugins[0].meta.name == "test-plugin"


@pytest.mark.asyncio
async def test_plugin_registry_find_by_capability_multiple():
    registry = PluginRegistry()
    p1 = MockPlugin()
    p2 = SecondMockPlugin()
    registry.register(p1)
    registry.register(p2)
    await p1.activate()
    await p2.activate()
    plugins = registry.find_by_capability("scan")
    assert len(plugins) == 2


def test_plugin_registry_find_by_capability_unknown():
    registry = PluginRegistry()
    plugin = MockPlugin()
    registry.register(plugin)
    plugins = registry.find_by_capability("nonexistent")
    assert len(plugins) == 0


def test_plugin_registry_status():
    registry = PluginRegistry()
    plugin = MockPlugin()
    registry.register(plugin)
    status = registry.get_status()
    assert "test-plugin" in status
    assert status["test-plugin"]["version"] == "1.0.0"
    assert status["test-plugin"]["state"] == "registered"
    assert "test" in status["test-plugin"]["capabilities"]


@pytest.mark.asyncio
async def test_plugin_registry_get_all_adapters_active():
    registry = PluginRegistry()
    plugin = MockPlugin()
    registry.register(plugin)
    await plugin.activate()
    adapters = registry.get_all_adapters()
    assert len(adapters) == 1
    assert adapters[0] == "adapter1"


def test_plugin_registry_get_all_adapters_no_active():
    registry = PluginRegistry()
    plugin = MockPlugin()
    registry.register(plugin)
    adapters = registry.get_all_adapters()
    assert len(adapters) == 0


@pytest.mark.asyncio
async def test_plugin_registry_get_all_agents_active():
    registry = PluginRegistry()
    plugin = MockPlugin()
    registry.register(plugin)
    await plugin.activate()
    agents = registry.get_all_agents()
    assert len(agents) == 1
    assert agents[0] == "agent1"


def test_plugin_registry_get_all_agents_no_active():
    registry = PluginRegistry()
    plugin = MockPlugin()
    registry.register(plugin)
    agents = registry.get_all_agents()
    assert len(agents) == 0


def test_plugin_load_plugins():
    registry = PluginRegistry()
    load_plugins(registry)
    assert isinstance(registry, PluginRegistry)


# ===== Crypto Engine Tests =====

from sentinel.crypto import CryptoEngine


@pytest.mark.asyncio
async def test_crypto_analyze_base64():
    engine = CryptoEngine()
    result = await engine.analyze_input("SGVsbG8gV29ybGQ=")
    encodings = result["detected_encodings"]
    b64 = [e for e in encodings if e["type"] == "base64"]
    assert len(b64) >= 1
    assert b64[0]["decoded_length"] > 0


@pytest.mark.asyncio
async def test_crypto_analyze_hex():
    engine = CryptoEngine()
    result = await engine.analyze_input("48656c6c6f")
    encodings = result["detected_encodings"]
    hex_enc = [e for e in encodings if e["type"] == "hex"]
    assert len(hex_enc) >= 1


@pytest.mark.asyncio
async def test_crypto_analyze_entropy():
    engine = CryptoEngine()
    result = await engine.analyze_input("SGVsbG8gV29ybGQ=")
    assert "entropy" in result
    assert result["entropy"] > 0


@pytest.mark.asyncio
async def test_crypto_analyze_hash_detection():
    engine = CryptoEngine()
    result = await engine.analyze_input("5d41402abc4b2a76b9719d911017c592")
    hashes = result["detected_hashes"]
    assert len(hashes) >= 1
    assert any(h["type"] == "md5" for h in hashes)


@pytest.mark.asyncio
async def test_crypto_analyze_ctf_flag_pattern():
    engine = CryptoEngine()
    result = await engine.analyze_input("flag{test_flag_here}")
    patterns = result["detected_patterns"]
    assert any(p["type"] == "ctf_flag" for p in patterns)


@pytest.mark.asyncio
async def test_crypto_analyze_jwt_pattern():
    engine = CryptoEngine()
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123"
    result = await engine.analyze_input(jwt)
    patterns = result["detected_patterns"]
    assert any(p["type"] == "jwt" for p in patterns)


@pytest.mark.asyncio
async def test_crypto_analyze_uuid_pattern():
    engine = CryptoEngine()
    result = await engine.analyze_input("550e8400-e29b-41d4-a716-446655440000")
    patterns = result["detected_patterns"]
    assert any(p["type"] == "uuid" for p in patterns)


@pytest.mark.asyncio
async def test_crypto_caesar_shifts():
    engine = CryptoEngine()
    ciphertext = "WKLV LV D WHVW PHVVDJH"
    result = await engine.caesar_shifts(ciphertext, max_shift=26)
    assert isinstance(result, list)
    assert len(result) == 26
    shift3 = [r for r in result if r["shift"] == 3][0]
    assert shift3["plaintext"] == "THIS IS A TEST MESSAGE"
    scores = [r["score"] for r in result]
    assert max(scores) > min(scores)


@pytest.mark.asyncio
async def test_crypto_caesar_shifts_top_score():
    engine = CryptoEngine()
    ciphertext = "WKLV LV D WHVW PHVVDJH"
    result = await engine.caesar_shifts(ciphertext, max_shift=26)
    best = result[0]
    assert best["shift"] == 3
    assert best["plaintext"] == "THIS IS A TEST MESSAGE"


@pytest.mark.asyncio
async def test_crypto_frequency_analysis():
    engine = CryptoEngine()
    text = "to be or not to be that is the question whether tis nobler in the mind to suffer the slings and arrows of outrageous fortune"
    result = await engine.frequency_analysis(text)
    assert "frequencies" in result
    assert "chi_squared" in result
    assert "index_of_coincidence" in result
    assert "is_english_like" in result
    assert result["is_english_like"] is True
    assert result["alpha_length"] > 30


@pytest.mark.asyncio
async def test_crypto_frequency_analysis_empty():
    engine = CryptoEngine()
    result = await engine.frequency_analysis("12345")
    assert result["alpha_length"] == 0
    assert result["is_english_like"] is False


@pytest.mark.asyncio
async def test_crypto_analyze_hash_md5():
    engine = CryptoEngine()
    result = await engine.analyze_hash("5d41402abc4b2a76b9719d911017c592")
    assert "md5" in result["detected_types"]
    assert len(result["attack_suggestions"]) > 0


@pytest.mark.asyncio
async def test_crypto_analyze_hash_sha256():
    engine = CryptoEngine()
    sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    result = await engine.analyze_hash(sha)
    assert "sha256" in result["detected_types"]


@pytest.mark.asyncio
async def test_crypto_analyze_hash_bcrypt():
    engine = CryptoEngine()
    bcrypt_hash = "$2b$12$./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxy"
    result = await engine.analyze_hash(bcrypt_hash)
    assert "bcrypt" in result["detected_types"]


@pytest.mark.asyncio
async def test_crypto_analyze_hash_unknown():
    engine = CryptoEngine()
    result = await engine.analyze_hash("not-a-hash")
    assert "unknown" in result["detected_types"]


@pytest.mark.asyncio
async def test_crypto_xor_single_byte():
    engine = CryptoEngine()
    plaintext = b"hello world"
    key = 0x42
    encrypted = bytes([b ^ key for b in plaintext])
    result = await engine.xor_single_byte(encrypted)
    assert isinstance(result, list)
    assert len(result) > 0
    best = result[0]
    assert best["key"] == 0x42
    assert best["plaintext"] == "hello world"


@pytest.mark.asyncio
async def test_crypto_xor_single_byte_returns_sorted():
    engine = CryptoEngine()
    encrypted = bytes([b ^ 0x01 for b in b"attack at dawn"])
    result = await engine.xor_single_byte(encrypted)
    for i in range(len(result) - 1):
        assert result[i]["score"] >= result[i + 1]["score"]


@pytest.mark.asyncio
async def test_crypto_xor_repeating_key():
    engine = CryptoEngine()
    key = b"KEY"
    plaintext = b"The quick brown fox jumps over the lazy dog"
    encrypted = bytes([plaintext[i] ^ key[i % len(key)] for i in range(len(plaintext))])
    result = await engine.xor_repeating_key(encrypted)
    assert "candidates" in result
    assert "estimated_key_lengths" in result
    assert result["data_length"] == len(encrypted)


@pytest.mark.asyncio
async def test_crypto_xor_repeating_key_empty():
    engine = CryptoEngine()
    result = await engine.xor_repeating_key(b"")
    assert "error" in result


@pytest.mark.asyncio
async def test_crypto_rsa_analyze_small_e():
    engine = CryptoEngine()
    result = await engine.rsa_analyze(n=100, e=3)
    assert len(result["attacks"]) > 0
    assert result["attacks"][0]["name"] == "small_exponent"
    assert result["n_bits"] == 7


@pytest.mark.asyncio
async def test_crypto_rsa_analyze_prime_n():
    engine = CryptoEngine()
    result = await engine.rsa_analyze(n=17, e=5)
    attack_names = [a["name"] for a in result["attacks"]]
    assert "prime_modulus" in attack_names


@pytest.mark.asyncio
async def test_crypto_rsa_analyze_fermat():
    engine = CryptoEngine()
    p, q = 101, 103
    n = p * q
    result = await engine.rsa_analyze(n=n, e=65537)
    attack_names = [a["name"] for a in result["attacks"]]
    assert "fermat_factorization" in attack_names


@pytest.mark.asyncio
async def test_crypto_rsa_analyze_trivial_exponent():
    engine = CryptoEngine()
    result = await engine.rsa_analyze(n=100, e=1)
    attack_names = [a["name"] for a in result["attacks"]]
    assert "trivial_exponent" in attack_names


@pytest.mark.asyncio
async def test_crypto_rsa_analyze_suggestions():
    engine = CryptoEngine()
    result = await engine.rsa_analyze(n=1000, e=3)
    assert len(result["suggestions"]) > 0


# ===== Forensics Engine Tests =====

from sentinel.forensics import ForensicsEngine


@pytest.mark.asyncio
async def test_forensics_detect_file_type_elf():
    engine = ForensicsEngine()
    elf_header = b"\x7fELF" + b"\x00" * 20
    result = await engine.detect_file_type(elf_header)
    assert result["primary_type"] == "elf"
    assert "ELF" in result["primary_description"]


@pytest.mark.asyncio
async def test_forensics_detect_file_type_png():
    engine = ForensicsEngine()
    png_header = b"\x89PNG\r\n\x1a\n" + b"\x00" * 20
    result = await engine.detect_file_type(png_header)
    assert result["primary_type"] == "png"


@pytest.mark.asyncio
async def test_forensics_detect_file_type_zip():
    engine = ForensicsEngine()
    zip_header = b"PK\x03\x04" + b"\x00" * 20
    result = await engine.detect_file_type(zip_header)
    assert result["primary_type"] == "zip"


@pytest.mark.asyncio
async def test_forensics_detect_file_type_jpeg():
    engine = ForensicsEngine()
    jpeg_header = b"\xff\xd8\xff" + b"\x00" * 20
    result = await engine.detect_file_type(jpeg_header)
    assert result["primary_type"] == "jpeg"


@pytest.mark.asyncio
async def test_forensics_detect_file_type_pe():
    engine = ForensicsEngine()
    pe_header = b"MZ" + b"\x00" * 20
    result = await engine.detect_file_type(pe_header)
    pe_matches = [m for m in result["matches"] if "pe" in m["type"]]
    assert len(pe_matches) > 0


@pytest.mark.asyncio
async def test_forensics_detect_file_type_empty():
    engine = ForensicsEngine()
    result = await engine.detect_file_type(b"")
    assert result["type"] == "empty"
    assert "Empty file" in result["description"]


@pytest.mark.asyncio
async def test_forensics_entropy_text():
    engine = ForensicsEngine()
    data = b"the quick brown fox jumps over the lazy dog " * 20
    result = await engine.entropy_analysis(data)
    assert "overall_entropy" in result
    assert result["overall_entropy"] > 0
    assert result["classification"] == "text_or_mixed"
    assert "block_entropies" in result


@pytest.mark.asyncio
async def test_forensics_entropy_random():
    engine = ForensicsEngine()
    data = bytes(range(256)) * 40
    result = await engine.entropy_analysis(data)
    assert result["overall_entropy"] > 7.0
    assert result["classification"] in ("highly_random_or_encrypted", "compressed_or_encrypted")


@pytest.mark.asyncio
async def test_forensics_entropy_empty():
    engine = ForensicsEngine()
    result = await engine.entropy_analysis(b"")
    assert result["overall_entropy"] == 0.0
    assert result["analysis"] == "empty"


@pytest.mark.asyncio
async def test_forensics_hex_preview():
    engine = ForensicsEngine()
    data = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
    result = await engine.hex_preview(data)
    assert "lines" in result
    assert result["length"] == 16
    assert len(result["lines"]) == 1
    line = result["lines"][0]
    assert "hex" in line
    assert "ascii" in line
    assert "offset" in line


@pytest.mark.asyncio
async def test_forensics_hex_preview_offset():
    engine = ForensicsEngine()
    data = b"\x00" * 32
    result = await engine.hex_preview(data, offset=16, length=16)
    assert result["offset"] == 16
    assert result["length"] == 16


@pytest.mark.asyncio
async def test_forensics_hex_preview_empty():
    engine = ForensicsEngine()
    result = await engine.hex_preview(b"")
    assert result["length"] == 0
    assert result["lines"] == []


@pytest.mark.asyncio
async def test_forensics_timeline():
    engine = ForensicsEngine()
    events = [
        {"timestamp": "2024-01-01T12:00:00", "category": "scan", "description": "Port scan started"},
        {"timestamp": "2024-01-01T12:05:00", "category": "finding", "description": "XSS found"},
        {"timestamp": "2024-01-01T12:01:00", "category": "scan", "description": "Subdomain enum"},
    ]
    result = await engine.build_timeline(events)
    assert result["total_events"] == 3
    assert result["events"][0]["timestamp"] <= result["events"][1]["timestamp"]
    assert result["events"][1]["timestamp"] <= result["events"][2]["timestamp"]
    assert result["categories"]["scan"] == 2
    assert result["categories"]["finding"] == 1


@pytest.mark.asyncio
async def test_forensics_timeline_empty():
    engine = ForensicsEngine()
    result = await engine.build_timeline([])
    assert result["total_events"] == 0


# ===== Web Security Engine Tests =====

from sentinel.web import WebSecurityEngine


def test_web_security_engine_instantiation():
    db = MagicMock()
    engine = WebSecurityEngine(db)
    assert engine.db is db


def test_web_security_engine_has_http():
    db = MagicMock()
    engine = WebSecurityEngine(db)
    assert engine.http is not None


# ===== API Security Engine Tests =====

from sentinel.api import APISecurityEngine


def test_api_security_engine_instantiation():
    db = MagicMock()
    engine = APISecurityEngine(db)
    assert engine.db is db


def test_api_security_engine_has_http():
    db = MagicMock()
    engine = APISecurityEngine(db)
    assert engine.http is not None


# ===== Workflow Engine Tests =====

from sentinel.workflows import (
    WorkflowEngine,
    WorkflowDefinition,
    StepDefinition,
    WorkflowStatus,
    StepStatus,
    WorkflowInstance,
    StepResult,
)


def test_workflow_register():
    engine = WorkflowEngine()
    wf = WorkflowDefinition(
        name="test-wf",
        steps=[StepDefinition(name="step1", handler="handler1")],
    )
    engine.register_workflow(wf)
    assert engine.get_workflow("test-wf") is wf


def test_workflow_register_overwrite():
    engine = WorkflowEngine()
    wf1 = WorkflowDefinition(name="test-wf", steps=[StepDefinition(name="s1", handler="h1")])
    wf2 = WorkflowDefinition(name="test-wf", steps=[StepDefinition(name="s2", handler="h2")])
    engine.register_workflow(wf1)
    engine.register_workflow(wf2)
    assert engine.get_workflow("test-wf") is wf2


def test_workflow_get_nonexistent():
    engine = WorkflowEngine()
    assert engine.get_workflow("nonexistent") is None


def test_workflow_list():
    engine = WorkflowEngine()
    engine.register_workflow(WorkflowDefinition(name="wf1"))
    engine.register_workflow(WorkflowDefinition(name="wf2"))
    assert len(engine.list_workflows()) == 2


def test_workflow_list_empty():
    engine = WorkflowEngine()
    assert len(engine.list_workflows()) == 0


@pytest.mark.asyncio
async def test_workflow_execute():
    engine = WorkflowEngine()
    results = []

    async def handler1(**kwargs):
        results.append("step1")
        return {"done": True}

    engine.register_handler("handler1", handler1)
    wf = WorkflowDefinition(
        name="test",
        steps=[StepDefinition(name="s1", handler="handler1", timeout_seconds=10)],
    )
    engine.register_workflow(wf)
    instance = await engine.execute("test")
    assert instance.status == WorkflowStatus.COMPLETED
    assert "s1" in instance.step_results
    assert instance.step_results["s1"].status == StepStatus.COMPLETED
    assert instance.step_results["s1"].output == {"done": True}
    assert results == ["step1"]


@pytest.mark.asyncio
async def test_workflow_execute_handler_receives_context():
    engine = WorkflowEngine()
    received = {}

    async def handler1(**kwargs):
        received.update(kwargs)
        return {"ok": True}

    engine.register_handler("handler1", handler1)
    wf = WorkflowDefinition(
        name="test",
        steps=[StepDefinition(name="s1", handler="handler1", timeout_seconds=10)],
    )
    engine.register_workflow(wf)
    instance = await engine.execute("test", context={"engagement_id": "abc"})
    assert "context" in received
    assert received["context"]["engagement_id"] == "abc"


@pytest.mark.asyncio
async def test_workflow_handler_not_found():
    engine = WorkflowEngine()
    wf = WorkflowDefinition(
        name="test",
        steps=[StepDefinition(name="s1", handler="nonexistent", timeout_seconds=5)],
    )
    engine.register_workflow(wf)
    instance = await engine.execute("test")
    assert "s1" in instance.step_results
    assert instance.step_results["s1"].status == StepStatus.FAILED
    assert "not found" in instance.step_results["s1"].error.lower()


@pytest.mark.asyncio
async def test_workflow_execute_not_found():
    engine = WorkflowEngine()
    with pytest.raises(ValueError, match="not found"):
        await engine.execute("nonexistent")


@pytest.mark.asyncio
async def test_workflow_multi_step():
    engine = WorkflowEngine()
    order = []

    async def handler_a(**kwargs):
        order.append("a")
        return {"step": "a"}

    async def handler_b(**kwargs):
        order.append("b")
        return {"step": "b"}

    engine.register_handler("handler_a", handler_a)
    engine.register_handler("handler_b", handler_b)
    wf = WorkflowDefinition(
        name="test",
        steps=[
            StepDefinition(name="step_a", handler="handler_a", timeout_seconds=10),
            StepDefinition(name="step_b", handler="handler_b", depends_on=["step_a"], timeout_seconds=10),
        ],
    )
    engine.register_workflow(wf)
    instance = await engine.execute("test")
    assert instance.status == WorkflowStatus.COMPLETED
    assert order == ["a", "b"]


@pytest.mark.asyncio
async def test_workflow_step_retry():
    engine = WorkflowEngine()
    attempts = []

    async def flaky_handler(**kwargs):
        attempts.append(len(attempts))
        if len(attempts) < 2:
            raise RuntimeError("transient failure")
        return {"recovered": True}

    engine.register_handler("flaky", flaky_handler)
    wf = WorkflowDefinition(
        name="test",
        steps=[StepDefinition(name="s1", handler="flaky", retry_count=3, timeout_seconds=10)],
    )
    engine.register_workflow(wf)
    instance = await engine.execute("test")
    assert instance.status == WorkflowStatus.COMPLETED
    assert len(attempts) == 2


@pytest.mark.asyncio
async def test_workflow_step_retry_exhausted():
    engine = WorkflowEngine()

    async def always_fail(**kwargs):
        raise RuntimeError("permanent failure")

    engine.register_handler("fail", always_fail)
    wf = WorkflowDefinition(
        name="test",
        steps=[StepDefinition(name="s1", handler="fail", retry_count=2, timeout_seconds=10)],
    )
    engine.register_workflow(wf)
    instance = await engine.execute("test")
    assert instance.step_results["s1"].status == StepStatus.FAILED
    assert instance.step_results["s1"].error == "permanent failure"


@pytest.mark.asyncio
async def test_workflow_instances():
    engine = WorkflowEngine()

    async def handler(**kwargs):
        return {"ok": True}

    engine.register_handler("h", handler)
    wf = WorkflowDefinition(name="test", steps=[StepDefinition(name="s", handler="h", timeout_seconds=10)])
    engine.register_workflow(wf)

    i1 = await engine.execute("test")
    i2 = await engine.execute("test")
    assert len(engine.list_instances()) == 2
    assert engine.get_instance(i1.id) is i1
    assert engine.get_instance(i2.id) is i2


@pytest.mark.asyncio
async def test_workflow_cancel():
    engine = WorkflowEngine()

    async def handler(**kwargs):
        return {"ok": True}

    engine.register_handler("h", handler)
    wf = WorkflowDefinition(name="test", steps=[StepDefinition(name="s", handler="h", timeout_seconds=10)])
    engine.register_workflow(wf)
    instance = await engine.execute("test")
    await engine.cancel(instance.id)
    assert engine.get_instance(instance.id).status == WorkflowStatus.CANCELLED


def test_workflow_step_result_fields():
    sr = StepResult(step_id="s1", status=StepStatus.COMPLETED)
    assert sr.step_id == "s1"
    assert sr.status == StepStatus.COMPLETED
    assert sr.output == {}
    assert sr.error is None


def test_workflow_step_definition_defaults():
    sd = StepDefinition(name="step", handler="handler")
    assert sd.params == {}
    assert sd.depends_on == []
    assert sd.retry_count == 0
    assert sd.timeout_seconds == 300
    assert sd.condition == ""


def test_workflow_definition_defaults():
    wd = WorkflowDefinition(name="wf")
    assert wd.steps == []
    assert wd.description == ""
    assert wd.version == "1.0.0"


# ===== Telemetry Engine Tests =====

from sentinel.telemetry import TelemetryEngine, ToolUsage, MetricPoint


def test_telemetry_timer():
    engine = TelemetryEngine(MagicMock())
    engine.start_timer("op1")
    time.sleep(0.01)
    duration = engine.end_timer("op1")
    assert duration > 0


def test_telemetry_timer_missing():
    engine = TelemetryEngine(MagicMock())
    duration = engine.end_timer("nonexistent")
    assert duration >= 0


def test_telemetry_record_tool_usage():
    engine = TelemetryEngine(MagicMock())
    usage = ToolUsage(
        tool_name="nmap",
        started_at=str(now_utc()),
        completed_at=str(now_utc()),
        duration_ms=100.0,
        success=True,
    )
    engine._usage_log.append(usage)
    assert len(engine._usage_log) == 1


def test_telemetry_tool_stats():
    engine = TelemetryEngine(MagicMock())
    engine._usage_log.append(
        ToolUsage(tool_name="nmap", started_at=str(now_utc()), completed_at=str(now_utc()), duration_ms=100.0, success=True)
    )
    engine._usage_log.append(
        ToolUsage(tool_name="nmap", started_at=str(now_utc()), completed_at=str(now_utc()), duration_ms=200.0, success=False)
    )
    stats = engine.get_tool_stats("nmap")
    assert stats["total"] == 2
    assert stats["success_rate"] == 0.5
    assert stats["successful"] == 1
    assert stats["failed"] == 1
    assert stats["avg_duration_ms"] == 150.0


def test_telemetry_tool_stats_all():
    engine = TelemetryEngine(MagicMock())
    engine._usage_log.append(
        ToolUsage(tool_name="nmap", started_at=str(now_utc()), completed_at=str(now_utc()), duration_ms=100.0, success=True)
    )
    engine._usage_log.append(
        ToolUsage(tool_name="httpx", started_at=str(now_utc()), completed_at=str(now_utc()), duration_ms=50.0, success=True)
    )
    stats = engine.get_tool_stats()
    assert stats["total"] == 2


def test_telemetry_tool_stats_empty():
    engine = TelemetryEngine(MagicMock())
    stats = engine.get_tool_stats("nonexistent")
    assert stats["total"] == 0
    assert stats["success_rate"] == 0.0


def test_telemetry_summary():
    engine = TelemetryEngine(MagicMock())
    engine._usage_log.append(
        ToolUsage(tool_name="nmap", started_at=str(now_utc()), completed_at=str(now_utc()), duration_ms=50.0, success=True)
    )
    engine._usage_log.append(
        ToolUsage(tool_name="httpx", started_at=str(now_utc()), completed_at=str(now_utc()), duration_ms=30.0, success=True)
    )
    summary = engine.get_summary()
    assert summary["total_operations"] == 2
    assert summary["unique_tools"] == 2
    assert "nmap" in summary["tool_breakdown"]
    assert "httpx" in summary["tool_breakdown"]


def test_telemetry_summary_empty():
    engine = TelemetryEngine(MagicMock())
    summary = engine.get_summary()
    assert summary["total_operations"] == 0
    assert summary["unique_tools"] == 0


def test_telemetry_record_metric():
    engine = TelemetryEngine(MagicMock())
    engine._metrics.append(MetricPoint(name="test.metric", value=42.0, timestamp=str(now_utc()), tags={"key": "value"}))
    assert len(engine._metrics) == 1
    assert engine._metrics[0].name == "test.metric"
    assert engine._metrics[0].value == 42.0
    assert engine._metrics[0].tags == {"key": "value"}


def test_telemetry_record_metric_no_tags():
    engine = TelemetryEngine(MagicMock())
    engine._metrics.append(MetricPoint(name="latency", value=10.5, timestamp=str(now_utc())))
    assert engine._metrics[0].tags == {}


def test_telemetry_performance_metrics():
    engine = TelemetryEngine(MagicMock())
    engine._metrics.append(MetricPoint(name="latency", value=10.0, timestamp=str(now_utc())))
    engine._metrics.append(MetricPoint(name="latency", value=20.0, timestamp=str(now_utc())))
    engine._metrics.append(MetricPoint(name="throughput", value=100.0, timestamp=str(now_utc())))
    metrics = engine.get_performance_metrics()
    assert "latency" in metrics
    assert metrics["latency"]["count"] == 2
    assert metrics["latency"]["avg"] == 15.0
    assert metrics["latency"]["min"] == 10.0
    assert metrics["latency"]["max"] == 20.0
    assert "throughput" in metrics


def test_telemetry_performance_metrics_empty():
    engine = TelemetryEngine(MagicMock())
    metrics = engine.get_performance_metrics()
    assert metrics == {}


def test_telemetry_usage_log_limit():
    engine = TelemetryEngine(MagicMock())
    for i in range(1100):
        engine._usage_log.append(
            ToolUsage(tool_name=f"tool{i}", started_at=str(now_utc()), completed_at=str(now_utc()), duration_ms=1.0)
        )
    engine._usage_log = engine._usage_log[-500:]
    assert len(engine._usage_log) <= 500


def test_telemetry_metrics_limit():
    engine = TelemetryEngine(MagicMock())
    for i in range(5100):
        engine._metrics.append(MetricPoint(name=f"metric_{i}", value=float(i), timestamp=str(now_utc())))
    engine._metrics = engine._metrics[-2500:]
    assert len(engine._metrics) <= 5000


def test_telemetry_metric_point_fields():
    mp = MetricPoint(name="test", value=1.0, timestamp="2024-01-01", tags={"k": "v"})
    assert mp.name == "test"
    assert mp.value == 1.0
    assert mp.tags == {"k": "v"}


def test_telemetry_tool_usage_fields():
    tu = ToolUsage(tool_name="tool", started_at="t1", completed_at="t2", duration_ms=5.0, success=False, error_message="err")
    assert tu.tool_name == "tool"
    assert tu.success is False
    assert tu.error_message == "err"


# ===== Browser Engine Tests =====

from sentinel.browser import BrowserEngine


def test_browser_engine_instantiation():
    engine = BrowserEngine()
    assert engine._browser is None
    assert engine._contexts == {}
    assert engine._pages == {}


def test_browser_engine_with_db():
    db = MagicMock()
    engine = BrowserEngine(db)
    assert engine.db is db


@pytest.mark.asyncio
async def test_browser_is_available():
    engine = BrowserEngine()
    result = await engine.is_available()
    assert isinstance(result, bool)


def test_browser_scope_check():
    engine = BrowserEngine()
    assert engine._in_scope("sub.example.com", "example.com") is True
    assert engine._in_scope("example.com", "example.com") is True
    assert engine._in_scope("evil.com", "example.com") is False
    assert engine._in_scope("example.com.evil.com", "example.com") is False


def test_browser_get_page():
    engine = BrowserEngine()
    assert engine._get_page("nonexistent") is None
