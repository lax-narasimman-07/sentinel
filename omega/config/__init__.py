"""Configuration management for OMEGA-CYBER-MCP."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from omega.core.schemas import EngagementMode, RateLimitPolicy


class ToolConfig(BaseModel):
    name: str
    binary_path: str | None = None
    enabled: bool = True
    timeout_seconds: float = 300
    max_output_bytes: int = 2_000_000
    custom_args: list[str] = Field(default_factory=list)


class RateLimitConfig(BaseModel):
    global_rps: float = 10.0
    per_target_rps: float = 5.0
    per_tool_rps: float = 3.0
    max_concurrent: int = 10
    burst_size: int = 20
    policy: RateLimitPolicy = RateLimitPolicy.NORMAL


class ExecutionConfig(BaseModel):
    sandbox_enabled: bool = True
    network_egress_allowed: bool = True
    filesystem_sandbox_path: str = "/tmp/omega-sandbox"
    max_cpu_seconds: float = 600
    max_memory_mb: int = 512
    allowed_subprocess_users: list[str] = Field(default_factory=lambda: ["root"])
    require_scope_validation: bool = True
    high_risk_requires_confirmation: bool = True
    ctf_mode_skip_scope: bool = False


class DatabaseConfig(BaseModel):
    path: str = "omega.db"
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
    file: str = "omega.log"
    json_format: bool = True
    audit_enabled: bool = True


class OmegaConfig(BaseModel):
    project_name: str = "OMEGA-CYBER-MCP"
    version: str = "0.1.0"
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
    def from_env(cls, base_dir: str = "") -> OmegaConfig:
        base = base_dir or os.environ.get("OMEGA_BASE_DIR", str(Path.home() / ".omega"))
        return cls(
            base_dir=base,
            rate_limits=RateLimitConfig(
                policy=RateLimitPolicy(os.environ.get("OMEGA_RATE_POLICY", "normal")),
                global_rps=float(os.environ.get("OMEGA_GLOBAL_RPS", "10")),
                per_target_rps=float(os.environ.get("OMEGA_TARGET_RPS", "5")),
            ),
            execution=ExecutionConfig(
                sandbox_enabled=os.environ.get("OMEGA_SANDBOX", "true").lower() == "true",
                require_scope_validation=os.environ.get("OMEGA_REQUIRE_SCOPE", "true").lower() == "true",
                ctf_mode_skip_scope=os.environ.get("OMEGA_CTF_SKIP_SCOPE", "true").lower() == "true",
            ),
            database=DatabaseConfig(
                path=os.path.join(base, "omega.db"),
            ),
            server=ServerConfig(
                host=os.environ.get("OMEGA_HOST", "127.0.0.1"),
                port=int(os.environ.get("OMEGA_PORT", "8443")),
                auth_enabled=os.environ.get("OMEGA_AUTH_ENABLED", "false").lower() == "true",
                auth_token=os.environ.get("OMEGA_AUTH_TOKEN", ""),
            ),
            browser=BrowserConfig(
                enabled=os.environ.get("OMEGA_BROWSER_ENABLED", "false").lower() == "true",
                headless=os.environ.get("OMEGA_BROWSER_HEADLESS", "true").lower() == "true",
            ),
            logging=LoggingConfig(
                level=os.environ.get("OMEGA_LOG_LEVEL", "INFO"),
            ),
        )


_config: OmegaConfig | None = None


def get_config() -> OmegaConfig:
    global _config
    if _config is None:
        _config = OmegaConfig.from_env()
    return _config


def set_config(config: OmegaConfig) -> None:
    global _config
    _config = config
