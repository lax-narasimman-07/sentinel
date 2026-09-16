"""Read-through recon cache backed by SQLite.

Phase 1.6: expensive subprocess outputs (recon scans) are cached per
``(tool, command, input-hash)`` for a per-tool staleness window. Caching is
opt-in per tool through ``ToolConfig.cache_ttl_seconds`` (``0`` disables).
Only successful runs (``rc == 0``) are stored. Uses short-lived connections so
it is event-loop safe across the MCP stdio server and test suites.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import os
import threading
import time

import aiosqlite

logger = logging.getLogger("omega.cache")

_cache_path: str | None = None
_path_lock = threading.Lock()


def set_cache_path(path: str) -> None:
    global _cache_path
    with _path_lock:
        _cache_path = path


def get_cache_path() -> str:
    global _cache_path
    if _cache_path is None:
        from omega.config import get_config
        base = get_config().base_dir or os.path.join(os.path.expanduser("~"), ".omega")
        with _path_lock:
            if _cache_path is None:
                _cache_path = os.path.join(base, "recon_cache.db")
    return _cache_path


def cache_key(tool: str, cmd: list[str], input_data: bytes | None = None) -> str:
    """Stable content-addressed key for a tool invocation."""
    payload = json.dumps(
        {"tool": tool, "cmd": cmd, "input": hashlib.sha256(input_data or b"").hexdigest()},
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def ttl_for(tool: str) -> float:
    """Per-tool staleness window in seconds; 0 disables caching."""
    from omega.config import get_config
    cfg = get_config().tool_config(tool)
    return float(getattr(cfg, "cache_ttl_seconds", 0) or 0)


class ReconCache:
    """SQLite-backed cache of successful tool runs keyed by :func:`cache_key`."""

    def __init__(self, path: str | None = None) -> None:
        self.path = path or get_cache_path()
        self._lock = asyncio.Lock()

    async def _connect(self) -> aiosqlite.Connection:
        directory = os.path.dirname(os.path.abspath(self.path)) or "."
        os.makedirs(directory, exist_ok=True)
        conn = await aiosqlite.connect(self.path)
        await conn.execute(
            "CREATE TABLE IF NOT EXISTS recon_cache ("
            " key TEXT PRIMARY KEY,"
            " tool TEXT NOT NULL,"
            " cmd TEXT NOT NULL,"
            " input_hash TEXT NOT NULL DEFAULT '',"
            " stdout TEXT NOT NULL DEFAULT '',"
            " stderr TEXT NOT NULL DEFAULT '',"
            " rc INTEGER NOT NULL,"
            " stored_at REAL NOT NULL"
            ")"
        )
        await conn.commit()
        return conn

    async def get(self, key: str, max_age: float) -> tuple[str, str, int, float] | None:
        """Return a fresh cached run tuple, or None if missing/stale."""
        if max_age <= 0:
            return None
        cutoff = time.time() - max_age
        async with self._lock:
            conn = await self._connect()
            try:
                cur = await conn.execute(
                    "SELECT stdout, stderr, rc, stored_at FROM recon_cache WHERE key = ? AND stored_at >= ?",
                    (key, cutoff),
                )
                row = await cur.fetchone()
            finally:
                await conn.close()
        if row is None:
            return None
        stdout, stderr, rc, stored_at = row
        return stdout, stderr, rc, 0.0  # cached run — synthetic duration

    async def put(
        self,
        key: str,
        tool: str,
        cmd: list[str],
        input_data: bytes | None,
        stdout: str,
        stderr: str,
        rc: int,
    ) -> None:
        if rc != 0:
            return
        payload = json.dumps(cmd, sort_keys=True)
        input_hash = hashlib.sha256(input_data or b"").hexdigest()
        async with self._lock:
            conn = await self._connect()
            try:
                await conn.execute(
                    "INSERT OR REPLACE INTO recon_cache (key, tool, cmd, input_hash, stdout, stderr, rc, stored_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (key, tool, payload, input_hash, stdout, stderr, int(rc), time.time()),
                )
                await conn.commit()
            finally:
                await conn.close()

    async def clear(self, tool: str | None = None) -> int:
        """Delete cached entries (optionally for one tool); returns rows removed."""
        async with self._lock:
            conn = await self._connect()
            try:
                if tool:
                    cur = await conn.execute("DELETE FROM recon_cache WHERE tool = ?", (tool,))
                else:
                    cur = await conn.execute("DELETE FROM recon_cache")
                await conn.commit()
                return getattr(cur, "rowcount", 0) or 0
            finally:
                await conn.close()

    async def count(self) -> int:
        async with self._lock:
            conn = await self._connect()
            try:
                cur = await conn.execute("SELECT COUNT(*) FROM recon_cache")
                row = await cur.fetchone()
                return int(row[0]) if row else 0
            finally:
                await conn.close()


async def cache_get(key: str, max_age: float) -> tuple[str, str, int, float] | None:
    with contextlib.suppress(Exception):
        cache = ReconCache()
        return await cache.get(key, max_age)
    return None


async def cache_put(
    cmd: list[str],
    tool: str,
    stdout: str,
    stderr: str,
    rc: int,
    input_data: bytes | None = None,
) -> None:
    if rc != 0 or ttl_for(tool) <= 0:
        return
    with contextlib.suppress(Exception):
        cache = ReconCache()
        await cache.put(cache_key(tool, cmd, input_data), tool, cmd, input_data, stdout, stderr, rc)
