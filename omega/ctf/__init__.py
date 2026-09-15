"""CTF Engine — challenge management, hypothesis ledger, flag tracking."""

from __future__ import annotations

import json
from typing import Any

from omega.core.schemas import (
    CTFCategory,
    Finding,
    Hypothesis,
    Severity,
    Confidence,
    ValidationStatus,
    new_id,
    now_utc,
)
from omega.storage import Database


class CTFChallenge:
    """In-memory representation of a CTF challenge."""

    def __init__(self, data: dict[str, Any]) -> None:
        self.id = data.get("id", new_id())
        self.name = data.get("name", "")
        self.category = data.get("category", "misc")
        self.target = data.get("target", "")
        self.port = data.get("port")
        self.protocol = data.get("protocol", "")
        self.description = data.get("description", "")
        self.attachments: list[str] = data.get("attachments", [])
        self.known_artifacts: list[str] = data.get("known_artifacts", [])
        self.candidate_flags: list[str] = data.get("candidate_flags", [])
        self.confirmed_flag: str | None = data.get("confirmed_flag")
        self.notes: str = data.get("notes", "")
        self.hypotheses: list[dict[str, Any]] = data.get("hypotheses", [])
        self.failed_attempts: list[str] = data.get("failed_attempts", [])
        self.timeline: list[dict[str, Any]] = data.get("timeline", [])

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "name": self.name, "category": self.category,
            "target": self.target, "port": self.port, "protocol": self.protocol,
            "description": self.description, "attachments": self.attachments,
            "known_artifacts": self.known_artifacts,
            "candidate_flags": self.candidate_flags,
            "confirmed_flag": self.confirmed_flag,
            "notes": self.notes, "hypotheses": self.hypotheses,
            "failed_attempts": self.failed_attempts, "timeline": self.timeline,
        }


class CTFEngine:
    """CTF-specific engine with challenge management and hypothesis tracking."""

    def __init__(self, db: Database) -> None:
        self.db = db
        self._challenges: dict[str, CTFChallenge] = {}

    async def create_challenge(self, engagement_id: str, name: str, category: str, target: str = "", port: int | None = None, protocol: str = "", description: str = "", attachments: list[str] | None = None) -> CTFChallenge:
        data = {
            "id": new_id(), "engagement_id": engagement_id, "name": name,
            "category": category, "target": target, "port": port,
            "protocol": protocol, "description": description,
            "attachments": attachments or [], "known_artifacts": [],
            "candidate_flags": [], "confirmed_flag": None,
            "notes": "", "hypotheses": [], "failed_attempts": [],
            "timeline": [{"time": now_utc().isoformat(), "event": "Challenge created"}],
            "status": "active", "created_at": now_utc().isoformat(), "updated_at": now_utc().isoformat(),
        }
        await self.db.save_ctf_challenge(data)
        challenge = CTFChallenge(data)
        self._challenges[challenge.id] = challenge
        return challenge

    async def get_challenge(self, challenge_id: str) -> CTFChallenge | None:
        if challenge_id in self._challenges:
            return self._challenges[challenge_id]
        data = await self.db.get_by_id("ctf_challenges", challenge_id)
        if data:
            challenge = CTFChallenge(data)
            self._challenges[challenge.id] = challenge
            return challenge
        return None

    async def list_challenges(self, engagement_id: str) -> list[CTFChallenge]:
        rows = await self.db.get_ctf_challenges(engagement_id)
        challenges = []
        for r in rows:
            c = CTFChallenge(r)
            self._challenges[c.id] = c
            challenges.append(c)
        return challenges

    async def add_hypothesis(self, challenge_id: str, hypothesis: str, category: str = "general", test_plan: str = "") -> dict[str, Any]:
        challenge = await self.get_challenge(challenge_id)
        if not challenge:
            return {"error": "Challenge not found"}

        hyp = {
            "id": new_id(), "hypothesis": hypothesis, "category": category,
            "test_plan": test_plan, "status": "active",
            "created_at": now_utc().isoformat(), "result": None,
        }
        challenge.hypotheses.append(hyp)
        challenge.timeline.append({"time": now_utc().isoformat(), "event": f"New hypothesis: {hypothesis[:100]}"})
        await self._save_challenge(challenge)
        return hyp

    async def resolve_hypothesis(self, challenge_id: str, hypothesis_id: str, result: str, successful: bool) -> None:
        challenge = await self.get_challenge(challenge_id)
        if not challenge:
            return
        for h in challenge.hypotheses:
            if h["id"] == hypothesis_id:
                h["status"] = "success" if successful else "failed"
                h["result"] = result
                break
        if not successful:
            challenge.failed_attempts.append(f"[{now_utc().isoformat()}] Hypothesis failed: {result[:200]}")
        challenge.timeline.append({"time": now_utc().isoformat(), "event": f"Hypothesis {'resolved' if successful else 'failed'}: {result[:100]}"})
        await self._save_challenge(challenge)

    async def submit_flag(self, challenge_id: str, flag: str) -> bool:
        challenge = await self.get_challenge(challenge_id)
        if not challenge:
            return False
        challenge.candidate_flags.append(flag)
        challenge.timeline.append({"time": now_utc().isoformat(), "event": f"Flag submitted: {flag[:50]}..."})
        await self._save_challenge(challenge)
        return True

    async def confirm_flag(self, challenge_id: str, flag: str) -> bool:
        challenge = await self.get_challenge(challenge_id)
        if not challenge:
            return False
        challenge.confirmed_flag = flag
        challenge.timeline.append({"time": now_utc().isoformat(), "event": f"Flag CONFIRMED: {flag[:50]}..."})
        await self._save_challenge(challenge)
        return True

    async def add_note(self, challenge_id: str, note: str) -> None:
        challenge = await self.get_challenge(challenge_id)
        if not challenge:
            return
        challenge.notes += f"\n[{now_utc().isoformat()}] {note}"
        await self._save_challenge(challenge)

    async def add_artifact(self, challenge_id: str, artifact: str) -> None:
        challenge = await self.get_challenge(challenge_id)
        if not challenge:
            return
        if artifact not in challenge.known_artifacts:
            challenge.known_artifacts.append(artifact)
            challenge.timeline.append({"time": now_utc().isoformat(), "event": f"New artifact: {artifact[:100]}"})
            await self._save_challenge(challenge)

    def get_hypothesis_ledger(self, challenge: CTFChallenge) -> dict[str, Any]:
        active = [h for h in challenge.hypotheses if h["status"] == "active"]
        succeeded = [h for h in challenge.hypotheses if h["status"] == "success"]
        failed = [h for h in challenge.hypotheses if h["status"] == "failed"]
        return {
            "challenge": challenge.name,
            "total_hypotheses": len(challenge.hypotheses),
            "active": active, "succeeded": succeeded, "failed": failed,
            "failed_techniques": challenge.failed_attempts,
            "solved": challenge.confirmed_flag is not None,
        }

    async def _save_challenge(self, challenge: CTFChallenge) -> None:
        data = challenge.to_dict()
        data["updated_at"] = now_utc().isoformat()
        await self.db.save_ctf_challenge(data)
