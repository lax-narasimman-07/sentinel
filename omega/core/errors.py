"""Uniform error contract and guarded-tool decorator for OMEGA-CYBER-MCP.

Phase 1.3 + 1.7. Every MCP tool error is surfaced as:

    {"error": {"code": "<ErrorCode>", "message": "<human readable>", "retryable": bool}}

Handlers raise :class:`ToolError` for expected failures (scope denials, missing
resources, missing binaries, timeouts, rate limits). The :func:`guarded_tool`
decorator catches those plus any unexpected exception (-> ``INTERNAL``) and
serializes them. The same decorator appends a structured invocation record to
an append-only JSONL audit file (``<base_dir>/audit.jsonl``).
"""

from __future__ import annotations

import asyncio
import enum
import json
import logging
import os
import time
from collections.abc import Callable  # noqa: TC003 - used at runtime in function signatures
from functools import wraps
from pathlib import Path
from typing import Any, ParamSpec, TypeVar

from omega.config import get_config

logger = logging.getLogger("omega.errors")

P = ParamSpec("P")
T = TypeVar("T")

_ERROR_KEYS = ("code", "message", "retryable")

# Argument names that identify the "target" of an invocation for audit records.
_TARGET_KEYS = ("target", "url", "js_url", "endpoint", "affected_asset", "affected_endpoint")

# Argument names whose values are sensitive and must never land in the audit log.
_SECRET_KEYS = (
    "auth", "token", "password", "cookie", "api_key", "api-key",
    "header", "flag", "secret", "key", "body", "json_body",
)


class ErrorCode(enum.StrEnum):
    """Machine-readable error taxonomy used across every MCP tool."""

    SCOPE_DENIED = "SCOPE_DENIED"
    TOOL_NOT_FOUND = "TOOL_NOT_FOUND"
    NOT_FOUND = "NOT_FOUND"
    BINARY_MISSING = "BINARY_MISSING"
    TIMEOUT = "TIMEOUT"
    RATE_LIMITED = "RATE_LIMITED"
    INVALID_ARGS = "INVALID_ARGS"
    INTERNAL = "INTERNAL"


class ToolError(Exception):
    """Expected, structured failure raised by tool handlers."""

    def __init__(self, code: ErrorCode, message: str, retryable: bool = False) -> None:
        super().__init__(message)
        self.code = ErrorCode(code)
        self.message = str(message)
        self.retryable = bool(retryable)

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code.value, "message": self.message, "retryable": self.retryable}


def err(code: ErrorCode, message: str, retryable: bool = False) -> str:
    """Build the canonical error JSON payload (as returned by the guarded decorator)."""
    return json.dumps({"error": ToolError(code, message, retryable).to_dict()}, default=str)


def _extract_target(args: dict[str, Any]) -> str:
    for key in _TARGET_KEYS:
        value = args.get(key)
        if value:
            return str(value)
    # Fall back to the first non-sensitive positional-ish argument.
    for key, value in args.items():
        if value and key not in _SECRET_KEYS and not key.startswith("engagement"):
            return str(value)
    return ""


def _redact_args(args: dict[str, Any]) -> dict[str, Any]:
    redacted: dict[str, Any] = {}
    for key, value in args.items():
        if any(secret in key.lower() for secret in _SECRET_KEYS):
            redacted[key] = "[REDACTED]"
        else:
            redacted[key] = value
    return redacted


_audit_path: str | None = None


def _audit_log_path() -> str:
    """Resolve the JSONL audit path from config (cached). Defaults to <base>/audit.jsonl."""
    global _audit_path
    if _audit_path:
        return _audit_path
    try:
        base = get_config().base_dir or str(Path.home() / ".omega")
    except Exception:
        base = os.environ.get("OMEGA_BASE_DIR", str(Path.home() / ".omega"))
    path = os.path.join(base, "audit.jsonl")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    _audit_path = path
    return path


def _write_audit_record(kind: str, tool_name: str, args: dict[str, Any], target: str,
                        outcome: str, duration_ms: float, code: str | None = None) -> None:
    """Append one JSONL line to the audit file. Failures to write are non-fatal."""
    try:
        record = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "kind": kind,
            "tool": tool_name,
            "target": target,
            "args": _redact_args(args),
            "outcome": outcome,
            "duration_ms": round(duration_ms, 1),
        }
        if code:
            record["error_code"] = code
        with open(_audit_log_path(), "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, default=str) + "\n")
    except Exception as exc:  # never let auditing break a tool call
        logger.warning("audit write failed for %s: %s", tool_name, exc)


def guarded_tool(tool_name: str | None = None) -> Callable[[Callable[P, T]], Callable[P, T]]:
    """Decorate an MCP tool handler with the uniform error contract + audit log.

    Place this innermost (closest to the handler). ``@mcp.tool`` must sit outside
    it so the MCP SDK's ``inspect.signature()`` still derives the input schema
    from the wrapped function (``functools.wraps`` preserves the signature).
    """

    def decorator(func: Callable[P, T]) -> Callable[P, T]:
        @wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            call_args = dict(zip(func.__code__.co_varnames, args, strict=False))
            call_args.update(kwargs)
            name = tool_name or getattr(func, "__name__", "tool")
            target = _extract_target(call_args)
            start = time.monotonic()
            try:
                result = await func(*args, **kwargs)  # type: ignore[misc]
                _write_audit_record("invocation", name, call_args, target, "success",
                                    (time.monotonic() - start) * 1000)
                return result
            except ToolError as exc:
                _write_audit_record("invocation", name, call_args, target, "error",
                                    (time.monotonic() - start) * 1000, code=exc.code.value)
                return json.dumps({"error": exc.to_dict()}, default=str)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - uniform INTERNAL contract
                logger.exception("Unhandled error in tool %s", name)
                _write_audit_record("invocation", name, call_args, target, "error",
                                    (time.monotonic() - start) * 1000, code=ErrorCode.INTERNAL.value)
                payload = ToolError(ErrorCode.INTERNAL, f"{type(exc).__name__}: {exc}").to_dict()
                return json.dumps({"error": payload}, default=str)

        return wrapper  # type: ignore[return-value]

    return decorator
