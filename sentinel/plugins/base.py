"""Base classes for SENTINEL plugins."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

logger = logging.getLogger("sentinel.plugins")


class PluginState(StrEnum):
    REGISTERED = "registered"
    LOADING = "loading"
    ACTIVE = "active"
    FAILED = "failed"
    DISABLED = "disabled"


@dataclass
class PluginMeta:
    name: str
    version: str = "0.1.0"
    description: str = ""
    author: str = ""
    capabilities: list[str] = field(default_factory=list)
    permissions: list[str] = field(default_factory=list)
    risk_level: str = "read_only"
    dependencies: list[str] = field(default_factory=list)
    tool_names: list[str] = field(default_factory=list)
    input_schema: dict[str, Any] = field(default_factory=dict)
    output_schema: dict[str, Any] = field(default_factory=dict)


class Plugin(ABC):

    @property
    @abstractmethod
    def meta(self) -> PluginMeta:
        ...

    @property
    def state(self) -> PluginState:
        return self._state

    def __init__(self) -> None:
        self._state = PluginState.REGISTERED
        self._config: dict[str, Any] = {}

    async def activate(self, config: dict[str, Any] | None = None) -> None:
        self._config = config or {}
        self._state = PluginState.ACTIVE
        logger.info(f"Plugin '{self.meta.name}' activated")

    async def deactivate(self) -> None:
        self._state = PluginState.DISABLED
        logger.info(f"Plugin '{self.meta.name}' deactivated")

    def get_adapters(self) -> list[Any]:
        return []

    def get_agents(self) -> list[Any]:
        return []

    def get_analyzers(self) -> list[Any]:
        return []
