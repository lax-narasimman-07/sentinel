"""Reporting engine — markdown, HTML, JSON report generation."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from omega.core.schemas import Report, Finding, Evidence, new_id, now_utc
from omega.storage import Database


class ReportEngine:
    """Generates structured reports from findings and evidence."""

    def __init__(self, db: Database) -> None:
        self.db = db

    async def generate(self, engagement_id: str, title: str = "", fmt: str = "markdown", include_evidence: bool = True, include_timeline: bool = True) -> Report:
        findings = await self.db.get_findings(engagement_id)
        evidence_rows = await self.db.get_evidence(engagement_id) if include_evidence else []
        engagement = await self.db.get_engagement(engagement_id)

        if not title:
            title = f"Security Assessment Report — {engagement.get('name', 'Unknown') if engagement else 'Unknown'}"

        if fmt == "json":
            content = self._gen_json(engagement, findings, evidence_rows)
        elif fmt == "html":
            content = self._gen_html(engagement, findings, evidence_rows, title)
        else:
            content = self._gen_markdown(engagement, findings, evidence_rows, title, include_timeline)

        report = Report(
            id=new_id(), engagement_id=engagement_id, title=title,
            format=fmt, content=content,
            finding_ids=[f.get("id", "") for f in findings],
            evidence_ids=[e.get("id", "") for e in evidence_rows],
            created_at=now_utc(), updated_at=now_utc(),
        )
        saved = await self.db.save_report(report.model_dump())
        saved["content"] = content
        return Report(**saved)

    def _gen_markdown(self, engagement: dict[str, Any] | None, findings: list[dict[str, Any]], evidence: list[dict[str, Any]], title: str, include_timeline: bool) -> str:
        lines = [f"# {title}", ""]
        mode = engagement.get("mode", "unknown") if engagement else "unknown"
        lines.extend([
            "## Executive Summary",
            f"**Engagement Mode:** {mode}",
            f"**Total Findings:** {len(findings)}",
            self._severity_summary(findings),
            "",
            "## Methodology",
            "Testing was conducted using an agentic security research platform with hypothesis-driven testing methodology.",
            "All tools were executed through a scope-validated execution pipeline with audit logging.",
            "",
        ])

        if findings:
            lines.append("## Findings\n")
            for i, f in enumerate(sorted(findings, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}.get(x.get("severity", "informational"), 5)), 1):
                severity = f.get("severity", "informational").upper()
                lines.extend([
                    f"### {i}. {f.get('title', 'Untitled')} [{severity}]",
                    f"- **Affected Asset:** {f.get('affected_asset', 'N/A')}",
                    f"- **Endpoint:** {f.get('affected_endpoint', 'N/A')}",
                    f"- **Confidence:** {f.get('confidence', 'none')}",
                    f"- **Status:** {f.get('validation_status', 'candidate')}",
                    f"- **CWE:** {f.get('cwe_id', 'N/A')}",
                    "",
                    f"**Description:** {f.get('description', 'N/A')}",
                    "",
                    f"**Impact:** {f.get('impact', 'N/A')}",
                    "",
                ])
                steps = f.get("steps_to_reproduce", [])
                if steps:
                    lines.append("**Steps to Reproduce:**")
                    for j, step in enumerate(steps, 1):
                        lines.append(f"{j}. {step}")
                    lines.append("")
                remediation = f.get("remediation", "")
                if remediation:
                    lines.append(f"**Remediation:** {remediation}\n")
                lines.append("---\n")

        if evidence and include_timeline:
            lines.extend(["## Evidence Summary", f"Total evidence records: {len(evidence)}", ""])
            type_counts: dict[str, int] = {}
            for e in evidence:
                t = e.get("evidence_type", "unknown")
                type_counts[t] = type_counts.get(t, 0) + 1
            for t, c in sorted(type_counts.items()):
                lines.append(f"- {t}: {c}")

        lines.extend(["## Testing Timeline", f"Report generated: {datetime.now(timezone.utc).isoformat()}", ""])
        return "\n".join(lines)

    def _severity_summary(self, findings: list[dict[str, Any]]) -> str:
        counts: dict[str, int] = {}
        for f in findings:
            s = f.get("severity", "informational")
            counts[s] = counts.get(s, 0) + 1
        parts = [f"**{s.upper()}:** {c}" for s, c in sorted(counts.items(), key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}.get(x[0], 5))]
        return " | ".join(parts) if parts else "No findings"

    def _gen_html(self, engagement: dict[str, Any] | None, findings: list[dict[str, Any]], evidence: list[dict[str, Any]], title: str) -> str:
        md = self._gen_markdown(engagement, findings, evidence, title, True)
        return f"""<!DOCTYPE html><html><head><title>{title}</title>
<style>body{{font-family:sans-serif;max-width:900px;margin:0 auto;padding:20px}}
h1{{border-bottom:2px solid #333}}h2{{color:#1a5276}}
table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ddd;padding:8px}}</style></head>
<body><pre style="white-space:pre-wrap">{md}</pre></body></html>"""

    def _gen_json(self, engagement: dict[str, Any] | None, findings: list[dict[str, Any]], evidence: list[dict[str, Any]]) -> str:
        import json
        return json.dumps({
            "engagement": engagement,
            "findings": findings,
            "evidence_count": len(evidence),
            "generated_at": now_utc().isoformat(),
        }, indent=2, default=str)
