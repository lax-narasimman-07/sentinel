"""Finding Engine — vulnerability lifecycle, correlation, and deduplication."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from sentinel.core.schemas import (
    Confidence,
    Evidence,
    Finding,
    Hypothesis,
    Severity,
    ValidationStatus,
    new_id,
    now_utc,
)
from sentinel.storage import Database

if TYPE_CHECKING:
    from sentinel.scope import ScopeEngine


class FindingEngine:
    """Manages the vulnerability finding lifecycle."""

    def __init__(self, db: Database, scope: ScopeEngine | None = None) -> None:
        self.db = db
        self.scope = scope

    # ── Hypotheses ─────────────────────────────────────────────────────────

    async def create_hypothesis(self, hypothesis: Hypothesis) -> Hypothesis:
        saved = await self.db.save_hypothesis(hypothesis.model_dump())
        return Hypothesis(**saved)

    async def update_hypothesis(self, hypothesis_id: str, updates: dict[str, Any]) -> Hypothesis | None:
        data = await self.db.get_by_id("hypotheses", hypothesis_id)
        if not data:
            return None
        data.update(updates)
        data["updated_at"] = now_utc().isoformat()
        saved = await self.db.save_hypothesis(data)
        return Hypothesis(**saved)

    async def list_hypotheses(self, engagement_id: str, status: str | None = None) -> list[Hypothesis]:
        rows = await self.db.get_hypotheses(engagement_id, status)
        return [Hypothesis(**r) for r in rows]

    async def get_hypothesis(self, hypothesis_id: str) -> Hypothesis | None:
        data = await self.db.get_by_id("hypotheses", hypothesis_id)
        if data:
            return Hypothesis(**data)
        return None

    # ── Findings ───────────────────────────────────────────────────────────

    async def create_finding(self, finding: Finding) -> Finding:
        # Deduplication check
        existing = await self._check_duplicate(finding)
        if existing:
            finding.duplicate_group = existing.id
            finding.validation_status = ValidationStatus.DUPLICATE
        # Authorization attestation: stamp which scope rule authorized the
        # affected asset at creation time (when a scope engine is available).
        if self.scope is not None and finding.engagement_id and finding.affected_asset:
            eng = await self.db.get_engagement(finding.engagement_id)
            result = await self.scope.authorize_target(finding.engagement_id, finding.affected_asset)
            finding.authorization_status = "authorized" if result.allowed else "not_in_scope"
            finding.authorization_basis = result.matched_rule
            finding.authorization_mode = eng.get("mode", "") if eng else ""
            finding.authorization_id = new_id()
        saved = await self.db.save_finding(finding.model_dump())
        return Finding(**saved)

    async def update_finding(self, finding_id: str, updates: dict[str, Any]) -> Finding | None:
        data = await self.db.get_by_id("findings", finding_id)
        if not data:
            return None
        data.update(updates)
        data["updated_at"] = now_utc().isoformat()
        saved = await self.db.save_finding(data)
        return Finding(**saved)

    async def list_findings(self, engagement_id: str, severity: str | None = None) -> list[Finding]:
        rows = await self.db.get_findings(engagement_id, severity)
        return [Finding(**r) for r in rows]

    async def get_finding(self, finding_id: str) -> Finding | None:
        data = await self.db.get_by_id("findings", finding_id)
        if data:
            return Finding(**data)
        return None

    async def validate_finding(self, finding_id: str, evidence_ids: list[str] | None = None) -> Finding | None:
        updates: dict[str, Any] = {"validation_status": ValidationStatus.VALIDATED}
        if evidence_ids:
            existing = await self.db.get_by_id("findings", finding_id)
            if existing:
                current_ids = json.loads(existing.get("evidence_ids", "[]")) if isinstance(existing.get("evidence_ids"), str) else existing.get("evidence_ids", [])
                updates["evidence_ids"] = list(set(current_ids + evidence_ids))
        return await self.update_finding(finding_id, updates)

    async def reject_finding(self, finding_id: str, reason: str = "") -> Finding | None:
        updates = {"validation_status": ValidationStatus.REJECTED}
        if reason:
            updates["technical_details"] = json.dumps({"rejection_reason": reason})
        return await self.update_finding(finding_id, updates)

    async def _check_duplicate(self, finding: Finding) -> Finding | None:
        """Check if a similar finding already exists."""
        existing = await self.db.get_findings(finding.engagement_id)
        for e in existing:
            e_obj = Finding(**e)
            if e_obj.validation_status == ValidationStatus.DUPLICATE:
                continue
            if (e_obj.affected_endpoint == finding.affected_endpoint and
                e_obj.title.lower().replace(" ", "") == finding.title.lower().replace(" ", "")):
                return e_obj
            if (e_obj.affected_asset == finding.affected_asset and
                e_obj.cwe_id and e_obj.cwe_id == finding.cwe_id and
                e_obj.affected_endpoint == finding.affected_endpoint):
                return e_obj
        return None

    async def cluster_findings(self, engagement_id: str) -> dict[str, list[str]]:
        """Cluster findings by similarity. Returns {group_id: [finding_ids]}."""
        findings = await self.list_findings(engagement_id)
        clusters: dict[str, list[str]] = {}
        for f in findings:
            if f.duplicate_group:
                gid = f.duplicate_group
                if gid not in clusters:
                    clusters[gid] = []
                clusters[gid].append(f.id)
        return clusters

    async def get_summary(self, engagement_id: str) -> dict[str, Any]:
        findings = await self.list_findings(engagement_id)
        by_severity: dict[str, int] = {}
        by_status: dict[str, int] = {}
        for f in findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
            by_status[f.validation_status] = by_status.get(f.validation_status, 0) + 1
        return {
            "total": len(findings),
            "by_severity": by_severity,
            "by_status": by_status,
        }
