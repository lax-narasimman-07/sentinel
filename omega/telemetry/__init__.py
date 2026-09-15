"""Telemetry engine — tool usage tracking, performance metrics, outcome recording."""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any

from omega.core.schemas import new_id, now_utc
from omega.storage import Database

logger = logging.getLogger("omega.telemetry")


@dataclass
class ToolUsage:
    tool_name: str
    started_at: str
    completed_at: str = ""
    duration_ms: float = 0.0
    success: bool = True
    error_message: str = ""
    engagement_id: str = ""
    params: dict[str, Any] = field(default_factory=dict)
    result_size: int = 0


@dataclass
class MetricPoint:
    name: str
    value: float
    timestamp: str
    tags: dict[str, str] = field(default_factory=dict)


class TelemetryEngine:
    """Tracks tool usage and performance metrics."""

    def __init__(self, db: Database) -> None:
        self.db = db
        self._active_timers: dict[str, float] = {}
        self._metrics: list[MetricPoint] = []
        self._usage_log: list[ToolUsage] = []

    def start_timer(self, operation_id: str) -> None:
        self._active_timers[operation_id] = time.time()

    def end_timer(self, operation_id: str) -> float:
        start = self._active_timers.pop(operation_id, time.time())
        return (time.time() - start) * 1000

    async def record_tool_usage(self, usage: ToolUsage) -> None:
        self._usage_log.append(usage)
        if len(self._usage_log) > 1000:
            self._usage_log = self._usage_log[-500:]
        logger.info(f"Tool '{usage.tool_name}' completed in {usage.duration_ms:.0f}ms ({'success' if usage.success else 'failure'})")

    async def record_metric(self, name: str, value: float, tags: dict[str, str] | None = None) -> None:
        metric = MetricPoint(name=name, value=value, timestamp=now_utc(), tags=tags or {})
        self._metrics.append(metric)
        if len(self._metrics) > 5000:
            self._metrics = self._metrics[-2500:]

    def get_tool_stats(self, tool_name: str | None = None) -> dict[str, Any]:
        usages = self._usage_log if not tool_name else [u for u in self._usage_log if u.tool_name == tool_name]
        if not usages:
            return {"total": 0, "success_rate": 0.0, "avg_duration_ms": 0.0}

        total = len(usages)
        successful = sum(1 for u in usages if u.success)
        avg_duration = sum(u.duration_ms for u in usages) / total

        return {
            "total": total,
            "success_rate": successful / total,
            "avg_duration_ms": avg_duration,
            "successful": successful,
            "failed": total - successful,
        }

    def get_performance_metrics(self, last_n: int = 100) -> dict[str, Any]:
        recent = self._metrics[-last_n:]
        if not recent:
            return {}

        by_name: dict[str, list[float]] = {}
        for m in recent:
            by_name.setdefault(m.name, []).append(m.value)

        return {
            name: {
                "count": len(values),
                "avg": sum(values) / len(values),
                "min": min(values),
                "max": max(values),
            }
            for name, values in by_name.items()
        }

    def get_summary(self) -> dict[str, Any]:
        tool_names = set(u.tool_name for u in self._usage_log)
        return {
            "total_operations": len(self._usage_log),
            "unique_tools": len(tool_names),
            "tool_breakdown": {name: self.get_tool_stats(name) for name in tool_names},
            "total_metrics": len(self._metrics),
        }
