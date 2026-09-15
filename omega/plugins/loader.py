"""Plugin loader — discovers and loads plugins."""

from __future__ import annotations

import asyncio
import importlib
import logging
from typing import TYPE_CHECKING, Any

from omega.plugins.base import Plugin, PluginState

if TYPE_CHECKING:
    from omega.plugins.registry import PluginRegistry

logger = logging.getLogger("omega.plugins")

_BUILTIN_PLUGINS: list[str] = [
    "omega.recon",
]


def load_plugins(registry: PluginRegistry, config: dict[str, Any] | None = None) -> None:
    _load_builtin_plugins(registry, config)
    _load_entry_point_plugins(registry, config)
    logger.info(f"Loaded {len(registry.list_active())} plugins")


def _load_builtin_plugins(registry: PluginRegistry, config: dict[str, Any] | None) -> None:
    for module_name in _BUILTIN_PLUGINS:
        try:
            mod = importlib.import_module(module_name)
            if hasattr(mod, "register_plugin"):
                plugin = mod.register_plugin()
                if isinstance(plugin, Plugin):
                    registry.register(plugin)
                    _activate_plugin(plugin, config)
        except Exception as e:
            logger.warning(f"Failed to load built-in plugin '{module_name}': {e}")


def _load_entry_point_plugins(registry: PluginRegistry, config: dict[str, Any] | None) -> None:
    try:
        from importlib.metadata import entry_points

        eps = entry_points()
        omega_eps = eps.select(group="omega.plugins") if hasattr(eps, "select") else list(eps.get("omega.plugins", []))
        for ep in omega_eps:
            try:
                plugin_class = ep.load()
                if isinstance(plugin_class, type) and issubclass(plugin_class, Plugin):
                    plugin = plugin_class()
                    registry.register(plugin)
                    _activate_plugin(plugin, config)
                else:
                    logger.warning(f"Entry point '{ep.name}' did not yield a Plugin subclass")
            except Exception as e:
                logger.warning(f"Failed to load entry point '{ep.name}': {e}")
    except ImportError:
        logger.debug("importlib.metadata.entry_points not available")


def _activate_plugin(plugin: Plugin, config: dict[str, Any] | None) -> None:
    plugin._state = PluginState.LOADING
    try:
        loop = asyncio.get_running_loop()
        loop.run_until_complete(plugin.activate(config))
    except RuntimeError:
        asyncio.run(plugin.activate(config))
