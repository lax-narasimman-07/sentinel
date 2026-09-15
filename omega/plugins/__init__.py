"""Plugin system for OMEGA-CYBER-MCP — extensible security tool integrations."""

from omega.plugins.base import Plugin, PluginMeta, PluginState
from omega.plugins.loader import load_plugins
from omega.plugins.registry import PluginRegistry

__all__ = ["Plugin", "PluginMeta", "PluginState", "PluginRegistry", "load_plugins"]
