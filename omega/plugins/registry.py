"""Plugin registry — tracks and queries loaded plugins."""

from __future__ import annotations

import logging
from typing import Any

from omega.plugins.base import Plugin, PluginState

logger = logging.getLogger("omega.plugins")


class PluginRegistry:

    def __init__(self) -> None:
        self._plugins: dict[str, Plugin] = {}
        self._capability_index: dict[str, list[str]] = {}

    def register(self, plugin: Plugin) -> None:
        meta = plugin.meta
        if meta.name in self._plugins:
            logger.warning(f"Plugin '{meta.name}' already registered, replacing")
        self._plugins[meta.name] = plugin
        for cap in meta.capabilities:
            self._capability_index.setdefault(cap, []).append(meta.name)
        logger.info(f"Registered plugin: {meta.name} v{meta.version}")

    def unregister(self, name: str) -> None:
        plugin = self._plugins.pop(name, None)
        if plugin:
            for cap in plugin.meta.capabilities:
                plugins = self._capability_index.get(cap, [])
                if name in plugins:
                    plugins.remove(name)

    def get(self, name: str) -> Plugin | None:
        return self._plugins.get(name)

    def list_all(self) -> list[Plugin]:
        return list(self._plugins.values())

    def list_active(self) -> list[Plugin]:
        return [p for p in self._plugins.values() if p.state == PluginState.ACTIVE]

    def find_by_capability(self, capability: str) -> list[Plugin]:
        names = self._capability_index.get(capability, [])
        return [
            self._plugins[n]
            for n in names
            if n in self._plugins and self._plugins[n].state == PluginState.ACTIVE
        ]

    def get_all_adapters(self) -> list[Any]:
        adapters = []
        for plugin in self.list_active():
            adapters.extend(plugin.get_adapters())
        return adapters

    def get_all_agents(self) -> list[Any]:
        agents = []
        for plugin in self.list_active():
            agents.extend(plugin.get_agents())
        return agents

    def get_status(self) -> dict[str, Any]:
        return {
            name: {
                "state": p.state.value,
                "version": p.meta.version,
                "capabilities": p.meta.capabilities,
            }
            for name, p in self._plugins.items()
        }
