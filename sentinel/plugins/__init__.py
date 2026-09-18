"""Plugin system for SENTINEL — extensible security tool integrations."""

from sentinel.plugins.base import Plugin, PluginMeta, PluginState
from sentinel.plugins.loader import load_plugins
from sentinel.plugins.registry import PluginRegistry

__all__ = ["Plugin", "PluginMeta", "PluginState", "PluginRegistry", "load_plugins"]
