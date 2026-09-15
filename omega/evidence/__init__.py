"""Evidence Engine — immutable evidence management and deduplication."""

from __future__ import annotations

import json
from typing import Any

from omega.core.schemas import Evidence, EvidenceType, content_hash, new_id, now_utc
from omega.storage import Database


class EvidenceEngine:
    """Manages immutable evidence records with deduplication."""

    def __init__(self, db: Database) -> None:
        self.db = db

    async def store(self, evidence: Evidence) -> Evidence:
        """Store evidence with deduplication check."""
        if not evidence.content_hash:
            evidence.content_hash = content_hash(json.dumps(evidence.content, sort_keys=True, default=str))

        # Check for duplicate
        existing = await self.db.query(
            "evidence",
            where="engagement_id = ? AND content_hash = ?",
            params=[evidence.engagement_id, evidence.content_hash],
            limit=1,
        )
        if existing:
            # Return existing evidence instead of duplicating
            return Evidence(**existing[0])

        saved = await self.db.save_evidence(evidence.model_dump())
        return Evidence(**saved)

    async def get(self, evidence_id: str) -> Evidence | None:
        data = await self.db.get_by_id("evidence", evidence_id)
        if data:
            return Evidence(**data)
        return None

    async def list_by_engagement(self, engagement_id: str, evidence_type: str | None = None, limit: int = 500) -> list[Evidence]:
        rows = await self.db.get_evidence(engagement_id, evidence_type, limit)
        return [Evidence(**r) for r in rows]

    async def store_http_pair(self, engagement_id: str, request: dict[str, Any], response: dict[str, Any], target: str = "", source_tool: str = "http_client") -> tuple[Evidence, Evidence]:
        req_ev = Evidence(
            id=new_id(),
            engagement_id=engagement_id,
            evidence_type=EvidenceType.HTTP_REQUEST,
            source_tool=source_tool,
            target=target,
            content=request,
            content_hash=content_hash(json.dumps(request, sort_keys=True, default=str)),
            created_at=now_utc(),
            updated_at=now_utc(),
        )
        req_saved = await self.store(req_ev)

        resp_ev = Evidence(
            id=new_id(),
            engagement_id=engagement_id,
            evidence_type=EvidenceType.HTTP_RESPONSE,
            source_tool=source_tool,
            target=target,
            content=response,
            content_hash=content_hash(json.dumps(response, sort_keys=True, default=str)),
            parent_event_id=req_saved.id,
            created_at=now_utc(),
            updated_at=now_utc(),
        )
        resp_saved = await self.store(resp_ev)
        return req_saved, resp_saved

    async def store_screenshot(self, engagement_id: str, url: str, screenshot_path: str, metadata: dict[str, Any] | None = None) -> Evidence:
        ev = Evidence(
            id=new_id(),
            engagement_id=engagement_id,
            evidence_type=EvidenceType.SCREENSHOT,
            target=url,
            content={"path": screenshot_path, "url": url, **(metadata or {})},
            content_hash=content_hash(screenshot_path),
            created_at=now_utc(),
            updated_at=now_utc(),
        )
        return await self.store(ev)

    async def store_tool_output(self, engagement_id: str, tool_name: str, tool_version: str, target: str, output: dict[str, Any], raw: str = "") -> Evidence:
        ev = Evidence(
            id=new_id(),
            engagement_id=engagement_id,
            evidence_type=EvidenceType.TOOL_OUTPUT,
            source_tool=tool_name,
            source_version=tool_version,
            target=target,
            content=output,
            content_hash=content_hash(raw[:5000] if raw else json.dumps(output, sort_keys=True, default=str)),
            created_at=now_utc(),
            updated_at=now_utc(),
        )
        return await self.store(ev)

    async def store_code_snippet(self, engagement_id: str, file_path: str, language: str, snippet: str, line_start: int = 0, line_end: int = 0) -> Evidence:
        ev = Evidence(
            id=new_id(),
            engagement_id=engagement_id,
            evidence_type=EvidenceType.CODE_SNIPPET,
            target=file_path,
            content={
                "file": file_path,
                "language": language,
                "snippet": snippet[:10000],
                "line_start": line_start,
                "line_end": line_end,
            },
            content_hash=content_hash(snippet),
            created_at=now_utc(),
            updated_at=now_utc(),
        )
        return await self.store(ev)

    async def store_command_execution(self, engagement_id: str, command: list[str], stdout: str, stderr: str, returncode: int, duration_ms: float) -> Evidence:
        ev = Evidence(
            id=new_id(),
            engagement_id=engagement_id,
            evidence_type=EvidenceType.COMMAND_EXECUTION,
            content={
                "command": command,
                "stdout": stdout[:50000],
                "stderr": stderr[:10000],
                "returncode": returncode,
                "duration_ms": duration_ms,
            },
            content_hash=content_hash(stdout[:5000]),
            created_at=now_utc(),
            updated_at=now_utc(),
        )
        return await self.store(ev)

    async def deduplicate(self, engagement_id: str) -> int:
        """Find and merge duplicate evidence. Returns count of removed duplicates."""
        all_ev = await self.list_by_engagement(engagement_id)
        seen_hashes: dict[str, list[str]] = {}
        for ev in all_ev:
            if ev.content_hash:
                if ev.content_hash not in seen_hashes:
                    seen_hashes[ev.content_hash] = []
                seen_hashes[ev.content_hash].append(ev.id)

        removed = 0
        for h, ids in seen_hashes.items():
            if len(ids) > 1:
                keep = ids[0]
                for dup_id in ids[1:]:
                    await self.db.delete("evidence", "id = ?", [dup_id])
                    removed += 1
        return removed
