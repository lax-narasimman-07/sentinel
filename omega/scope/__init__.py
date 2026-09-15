"""Scope & Authorization Engine — the central safety gate for OMEGA-CYBER-MCP."""

from __future__ import annotations

import fnmatch
import ipaddress
import re
import time
from typing import Any
from urllib.parse import urlparse

from omega.core.schemas import (
    AuditEvent,
    Engagement,
    EngagementMode,
    RateLimitPolicy,
    ScopeRule,
    now_utc,
    new_id,
)
from omega.storage import Database


class ScopeCheckResult:
    """Result of a scope authorization check."""

    def __init__(self, allowed: bool, reason: str = "", matched_rule: str = "") -> None:
        self.allowed = allowed
        self.reason = reason
        self.matched_rule = matched_rule

    def to_dict(self) -> dict[str, Any]:
        return {"allowed": self.allowed, "reason": self.reason, "matched_rule": self.matched_rule}


class RateLimiter:
    """Time-aware token-bucket rate limiter, keyed per target.

    Tokens refill continuously at ``rps`` per second up to ``burst``.
    A bucket freshly seen on a target starts full, so the first ``burst``
    requests pass immediately and subsequent requests are throttled.
    """

    def __init__(self, rps: float = 5.0, burst: int = 10) -> None:
        self.rps = float(rps)
        self.burst = int(burst)
        # target -> [tokens, last_update_epoch]
        self._buckets: dict[str, list[float]] = {}

    def _tokens(self, target: str, now: float) -> float:
        entry = self._buckets.get(target)
        if entry is None:
            return float(self.burst)
        tokens, last = entry
        return min(float(self.burst), tokens + (now - last) * self.rps)

    def allow(self, target: str) -> bool:
        now = time.time()
        tokens = self._tokens(target, now)
        if tokens < 1.0:
            self._buckets[target] = [tokens, now]
            return False
        self._buckets[target] = [tokens - 1.0, now]
        return True


class ScopeEngine:
    """Centralized scope & authorization engine.

    Every active tool call must pass through this engine.
    Deny-by-default. No active testing without explicit scope.
    """

    def __init__(self, db: Database) -> None:
        self.db = db
        self._rate_limiters: dict[str, RateLimiter] = {}
        self._engagement_cache: dict[str, Engagement] = {}

    async def _get_engagement(self, engagement_id: str) -> Engagement | None:
        if engagement_id in self._engagement_cache:
            return self._engagement_cache[engagement_id]
        data = await self.db.get_engagement(engagement_id)
        if data:
            eng = Engagement(**data)
            self._engagement_cache[engagement_id] = eng
            return eng
        return None

    async def _get_rules(self, engagement_id: str) -> list[ScopeRule]:
        rules_data = await self.db.get_scope_rules(engagement_id)
        return [ScopeRule(**r) for r in rules_data]

    async def _audit(self, engagement_id: str, event_type: str, target: str, action: str, allowed: bool, reason: str) -> None:
        event = AuditEvent(
            id=new_id(),
            engagement_id=engagement_id,
            event_type=event_type,
            target=target,
            action=action,
            result=reason,
            allowed=allowed,
            created_at=now_utc(),
            updated_at=now_utc(),
        )
        await self.db.log_audit(event.model_dump())

    # ── Primary authorization methods ──────────────────────────────────────

    async def authorize_target(self, engagement_id: str, target: str) -> ScopeCheckResult:
        """Check if a target is within scope."""
        engagement = await self._get_engagement(engagement_id)
        if not engagement:
            result = ScopeCheckResult(False, "Engagement not found")
            await self._audit(engagement_id, "scope_check", target, "authorize_target", False, result.reason)
            return result

        # CTF mode uses relaxed scope with explicit exclusions only
        mode = engagement.mode
        if mode == EngagementMode.CTF:
            # CTF mode: allow if no explicit exclusion
            rules = await self._get_rules(engagement_id)
            for rule in rules:
                if rule.rule_type == "exclude" and self._match_rule(rule, target):
                    result = ScopeCheckResult(False, f"Target excluded by rule: {rule.pattern}")
                    await self._audit(engagement_id, "scope_check", target, "authorize_target", False, result.reason)
                    return result
            result = ScopeCheckResult(True, "CTF mode: target not excluded")
            await self._audit(engagement_id, "scope_check", target, "authorize_target", True, result.reason)
            return result

        # LOCAL_LAB and ANALYSIS_ONLY modes still require scope enforcement
        # (fall through to the bug-bounty-style check below)

        # For bug bounty / pentest: must have at least one matching include rule
        rules = await self._get_rules(engagement_id)
        if not rules:
            result = ScopeCheckResult(False, "No scope rules configured — deny by default")
            await self._audit(engagement_id, "scope_check", target, "authorize_target", False, result.reason)
            return result

        included = False
        excluded = False
        matched_rule = ""

        for rule in rules:
            if rule.rule_type == "include" and self._match_rule(rule, target):
                included = True
                matched_rule = rule.pattern
            elif rule.rule_type == "exclude" and self._match_rule(rule, target):
                excluded = True

        if excluded:
            result = ScopeCheckResult(False, "Target matches exclusion rule")
            await self._audit(engagement_id, "scope_check", target, "authorize_target", False, result.reason)
            return result

        if not included:
            result = ScopeCheckResult(False, "Target does not match any inclusion rule — deny by default")
            await self._audit(engagement_id, "scope_check", target, "authorize_target", False, result.reason)
            return result

        result = ScopeCheckResult(True, f"Target authorized (matches: {matched_rule})", matched_rule)
        await self._audit(engagement_id, "scope_check", target, "authorize_target", True, result.reason)
        return result

    async def authorize_action(self, engagement_id: str, target: str, action: str) -> ScopeCheckResult:
        """Check if an action is permitted on a target."""
        target_check = await self.authorize_target(engagement_id, target)
        if not target_check.allowed:
            return target_check

        rules = await self._get_rules(engagement_id)
        for rule in rules:
            if not self._match_rule(rule, target):
                continue
            if rule.methods:
                allowed_methods = [m.upper() for m in rule.methods]
                if action.upper() not in allowed_methods:
                    result = ScopeCheckResult(False, f"Action '{action}' not allowed for this target")
                    await self._audit(engagement_id, "action_check", target, action, False, result.reason)
                    return result

        result = ScopeCheckResult(True, "Action authorized")
        await self._audit(engagement_id, "action_check", target, action, True, result.reason)
        return result

    async def authorize_network_destination(self, engagement_id: str, destination: str) -> ScopeCheckResult:
        """SSRF protection — validate network destination is in scope."""
        # Parse destination
        parsed = urlparse(destination) if "://" in destination else None
        host = parsed.hostname if parsed else destination.split(":")[0]

        # Block SSRF attempts
        ssrf_blocked = ["169.254.169.254", "metadata.google.internal", "localhost", "127.0.0.1", "0.0.0.0"]
        if host in ssrf_blocked:
            # Allow localhost only for local_lab mode
            engagement = await self._get_engagement(engagement_id)
            if not engagement or engagement.mode != EngagementMode.LOCAL_LAB:
                result = ScopeCheckResult(False, f"SSRF blocked: {host} is a restricted address")
                await self._audit(engagement_id, "ssrf_check", destination, "network_destination", False, result.reason)
                return result

        return await self.authorize_target(engagement_id, destination)

    async def authorize_execution_mode(self, engagement_id: str, risk_level: str) -> ScopeCheckResult:
        """Check if the execution mode allows this risk level."""
        engagement = await self._get_engagement(engagement_id)
        if not engagement:
            return ScopeCheckResult(False, "Engagement not found")

        if engagement.mode == EngagementMode.ANALYSIS_ONLY and risk_level in ("active", "destructive"):
            result = ScopeCheckResult(False, "Analysis-only mode does not allow active testing")
            await self._audit(engagement_id, "mode_check", "", risk_level, False, result.reason)
            return result

        result = ScopeCheckResult(True, "Execution mode authorized")
        await self._audit(engagement_id, "mode_check", "", risk_level, True, result.reason)
        return result

    async def enforce_rate_limit(self, engagement_id: str, target: str) -> ScopeCheckResult:
        """Check rate limit for a target."""
        engagement = await self._get_engagement(engagement_id)
        if not engagement:
            return ScopeCheckResult(True, "No engagement — allowing")

        policy = engagement.rate_limit_policy
        if policy == RateLimitPolicy.AGGRESSIVE:
            rps, burst = 20.0, 50
        elif policy == RateLimitPolicy.STEALTH:
            rps, burst = 1.0, 3
        else:
            rps, burst = 5.0, 10

        if engagement_id not in self._rate_limiters:
            self._rate_limiters[engagement_id] = RateLimiter(rps=rps, burst=burst)

        limiter = self._rate_limiters[engagement_id]
        if not limiter.allow(target):
            result = ScopeCheckResult(False, f"Rate limit exceeded for {target}")
            await self._audit(engagement_id, "rate_limit", target, "request", False, result.reason)
            return result

        return ScopeCheckResult(True, "Rate limit OK")

    # ── Full authorization pipeline ────────────────────────────────────────

    async def authorize(self, engagement_id: str, target: str, action: str, risk_level: str = "active") -> ScopeCheckResult:
        """Full authorization pipeline. Must pass all checks."""
        # 1. Target scope
        check = await self.authorize_target(engagement_id, target)
        if not check.allowed:
            return check

        # 2. Action permission
        check = await self.authorize_action(engagement_id, target, action)
        if not check.allowed:
            return check

        # 3. Execution mode
        check = await self.authorize_execution_mode(engagement_id, risk_level)
        if not check.allowed:
            return check

        # 4. Rate limit
        check = await self.enforce_rate_limit(engagement_id, target)
        if not check.allowed:
            return check

        return ScopeCheckResult(True, "All authorization checks passed")

    # ── Pattern matching ───────────────────────────────────────────────────

    def _match_rule(self, rule: ScopeRule, target: str) -> bool:
        pattern = rule.pattern
        t = target.lower().strip()

        if rule.target_type == "domain":
            return fnmatch.fnmatch(t, pattern.lower()) or t == pattern.lower()
        elif rule.target_type == "wildcard":
            # *.example.com matches sub.example.com
            return fnmatch.fnmatch(t, pattern.lower())
        elif rule.target_type == "ip":
            return t == pattern
        elif rule.target_type == "cidr":
            try:
                net = ipaddress.ip_network(pattern, strict=False)
                addr = ipaddress.ip_address(t.split("/")[0].split(":")[0])
                return addr in net
            except ValueError:
                return False
        elif rule.target_type == "url":
            parsed_url = urlparse(t)
            parsed_pattern = urlparse(pattern)
            if parsed_pattern.hostname and parsed_url.hostname:
                return fnmatch.fnmatch(parsed_url.hostname, parsed_pattern.hostname)
            return fnmatch.fnmatch(t, pattern)
        elif rule.target_type == "port":
            # Extract port from target
            port_match = re.search(r":(\d+)$", t)
            if port_match:
                port = int(port_match.group(1))
                try:
                    port_range = pattern.replace("*", "0-65535")
                    if "-" in port_range:
                        lo, hi = port_range.split("-", 1)
                        return int(lo) <= port <= int(hi)
                    return port == int(port_range)
                except ValueError:
                    return False
        return False
