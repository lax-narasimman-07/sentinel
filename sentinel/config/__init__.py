"""Configuration management for SENTINEL."""

from __future__ import annotations

import os
from pathlib import Path

from pydantic import BaseModel, Field

from sentinel.core.schemas import EngagementMode, RateLimitPolicy


class ToolConfig(BaseModel):
    name: str
    binary_path: str | None = None
    enabled: bool = True
    timeout_seconds: float = 300
    max_output_bytes: int = 2_000_000
    cache_ttl_seconds: float = 0
    custom_args: list[str] = Field(default_factory=list)


class RateLimitConfig(BaseModel):
    enabled: bool = True
    global_rps: float = 10.0
    per_target_rps: float = 5.0
    per_tool_rps: float = 3.0
    max_concurrent: int = 10
    burst_size: int = 20
    wait_seconds: float = 30.0
    policy: RateLimitPolicy = RateLimitPolicy.NORMAL


class ExecutionConfig(BaseModel):
    sandbox_enabled: bool = True
    network_egress_allowed: bool = True
    filesystem_sandbox_path: str = "/tmp/sentinel-sandbox"
    max_cpu_seconds: float = 600
    max_memory_mb: int = 512
    allowed_subprocess_users: list[str] = Field(default_factory=lambda: ["root"])
    require_scope_validation: bool = True
    high_risk_requires_confirmation: bool = True
    ctf_mode_skip_scope: bool = False


class DatabaseConfig(BaseModel):
    path: str = "sentinel.db"
    use_postgres: bool = False
    postgres_url: str = ""


class ServerConfig(BaseModel):
    host: str = "127.0.0.1"
    port: int = 8443
    auth_enabled: bool = False
    auth_token: str = ""
    cors_origins: list[str] = Field(default_factory=list)


class BrowserConfig(BaseModel):
    enabled: bool = False
    headless: bool = True
    browser_type: str = "chromium"
    timeout_ms: int = 30000
    screenshot_dir: str = ""


class LoggingConfig(BaseModel):
    level: str = "INFO"
    file: str = "sentinel.log"
    json_format: bool = True
    audit_enabled: bool = True


class SentinelConfig(BaseModel):
    project_name: str = "SENTINEL"
    version: str = "1.0.0"
    default_mode: EngagementMode = EngagementMode.ANALYSIS_ONLY
    base_dir: str = ""
    tools: dict[str, ToolConfig] = Field(default_factory=dict)
    rate_limits: RateLimitConfig = Field(default_factory=RateLimitConfig)
    execution: ExecutionConfig = Field(default_factory=ExecutionConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    server: ServerConfig = Field(default_factory=ServerConfig)
    browser: BrowserConfig = Field(default_factory=BrowserConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)

    def tool_config(self, name: str) -> ToolConfig:
        if name in self.tools:
            return self.tools[name]
        return ToolConfig(name=name)

    @classmethod
    def from_env(cls, base_dir: str = "") -> SentinelConfig:
        base = base_dir or os.environ.get("SENTINEL_BASE_DIR", str(Path.home() / ".sentinel"))
        return cls(
            base_dir=base,
            rate_limits=RateLimitConfig(
                enabled=os.environ.get("SENTINEL_RATE_LIMIT", "true").lower() != "false",
                policy=RateLimitPolicy(os.environ.get("SENTINEL_RATE_POLICY", "normal")),
                global_rps=float(os.environ.get("SENTINEL_GLOBAL_RPS", "10")),
                per_target_rps=float(os.environ.get("SENTINEL_TARGET_RPS", "5")),
                per_tool_rps=float(os.environ.get("SENTINEL_TOOL_RPS", "3")),
                max_concurrent=int(os.environ.get("SENTINEL_MAX_CONCURRENT", "10")),
                burst_size=int(os.environ.get("SENTINEL_BURST", "20")),
                wait_seconds=float(os.environ.get("SENTINEL_RATE_WAIT", "30")),
            ),
            execution=ExecutionConfig(
                sandbox_enabled=os.environ.get("SENTINEL_SANDBOX", "true").lower() == "true",
                require_scope_validation=os.environ.get("SENTINEL_REQUIRE_SCOPE", "true").lower() == "true",
                ctf_mode_skip_scope=os.environ.get("SENTINEL_CTF_SKIP_SCOPE", "true").lower() == "true",
            ),
            database=DatabaseConfig(
                path=os.path.join(base, "sentinel.db"),
            ),
            server=ServerConfig(
                host=os.environ.get("SENTINEL_HOST", "127.0.0.1"),
                port=int(os.environ.get("SENTINEL_PORT", "8443")),
                auth_enabled=os.environ.get("SENTINEL_AUTH_ENABLED", "false").lower() == "true",
                auth_token=os.environ.get("SENTINEL_AUTH_TOKEN", ""),
            ),
            browser=BrowserConfig(
                enabled=os.environ.get("SENTINEL_BROWSER_ENABLED", "false").lower() == "true",
                headless=os.environ.get("SENTINEL_BROWSER_HEADLESS", "true").lower() == "true",
            ),
            logging=LoggingConfig(
                level=os.environ.get("SENTINEL_LOG_LEVEL", "INFO"),
            ),
        )


_config: SentinelConfig | None = None


def get_config() -> SentinelConfig:
    global _config
    if _config is None:
        _config = SentinelConfig.from_env()
    return _config


def set_config(config: SentinelConfig) -> None:
    global _config
    _config = config
