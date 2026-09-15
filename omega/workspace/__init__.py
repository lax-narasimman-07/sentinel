"""Workspace model — isolated per-engagement working directories."""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any

from omega.core.schemas import Workspace, EngagementMode, new_id, now_utc
from omega.config import get_config
from omega.storage import Database


class WorkspaceManager:
    """Manages isolated workspaces per engagement."""

    def __init__(self, db: Database) -> None:
        self.db = db
        cfg = get_config()
        self.base_dir = cfg.base_dir or os.path.join(str(Path.home()), ".omega", "workspaces")
        os.makedirs(self.base_dir, exist_ok=True)

    async def create_workspace(self, name: str, engagement_id: str, mode: EngagementMode = EngagementMode.ANALYSIS_ONLY) -> Workspace:
        ws_id = new_id()
        ws_path = os.path.join(self.base_dir, ws_id)
        os.makedirs(ws_path, exist_ok=True)

        # Create standard subdirectories
        for subdir in ["scope", "assets", "requests", "responses", "screenshots",
                       "evidence", "findings", "scans", "logs", "notes",
                       "artifacts", "reports", "state"]:
            os.makedirs(os.path.join(ws_path, subdir), exist_ok=True)

        ws = Workspace(
            id=ws_id,
            name=name,
            engagement_id=engagement_id,
            mode=mode,
            base_path=ws_path,
            is_sandboxed=mode in (EngagementMode.LOCAL_LAB, EngagementMode.CTF),
            created_at=now_utc(),
            updated_at=now_utc(),
        )
        await self.db.save_workspace(ws.model_dump())
        return ws

    async def get_workspace(self, ws_id: str) -> Workspace | None:
        data = await self.db.get_by_id("workspaces", ws_id)
        if data:
            return Workspace(**data)
        return None

    async def list_workspaces(self) -> list[dict[str, Any]]:
        return await self.db.query("workspaces", limit=50)

    def get_subdir(self, ws: Workspace, subdir: str) -> str:
        path = os.path.join(ws.base_path, subdir)
        os.makedirs(path, exist_ok=True)
        return path

    async def write_file(self, ws: Workspace, subdir: str, filename: str, content: bytes | str) -> str:
        directory = self.get_subdir(ws, subdir)
        filepath = os.path.join(directory, filename)
        mode = "wb" if isinstance(content, bytes) else "w"
        with open(filepath, mode) as f:
            f.write(content)
        return filepath

    async def read_file(self, ws: Workspace, subdir: str, filename: str) -> bytes | None:
        filepath = os.path.join(ws.base_path, subdir, filename)
        if os.path.exists(filepath):
            with open(filepath, "rb") as f:
                return f.read()
        return None

    async def delete_workspace(self, ws_id: str) -> bool:
        ws = await self.get_workspace(ws_id)
        if ws and os.path.exists(ws.base_path):
            shutil.rmtree(ws.base_path)
            await self.db.delete("workspaces", "id = ?", [ws_id])
            return True
        return False
