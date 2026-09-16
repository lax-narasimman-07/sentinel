"""SQLite database layer for OMEGA-CYBER-MCP."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any

import aiosqlite

from omega.config import get_config

SCHEMA_VERSION = 1

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS engagements (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    mode TEXT NOT NULL,
    description TEXT DEFAULT '',
    status TEXT DEFAULT 'active',
    workspace_id TEXT DEFAULT '',
    rate_limit_policy TEXT DEFAULT 'normal',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scope_rules (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    rule_type TEXT NOT NULL,
    target_type TEXT NOT NULL,
    pattern TEXT NOT NULL,
    description TEXT DEFAULT '',
    ports TEXT DEFAULT '[]',
    protocols TEXT DEFAULT '[]',
    methods TEXT DEFAULT '[]',
    paths TEXT DEFAULT '[]',
    rate_limit_requests_per_second REAL,
    time_window_start TEXT,
    time_window_end TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
);

CREATE TABLE IF NOT EXISTS authorizations (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    credentials TEXT DEFAULT '{}',
    tokens TEXT DEFAULT '[]',
    cookies TEXT DEFAULT '[]',
    notes TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
);

CREATE TABLE IF NOT EXISTS assets (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    asset_type TEXT NOT NULL,
    value TEXT NOT NULL,
    metadata TEXT DEFAULT '{}',
    tags TEXT DEFAULT '[]',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
);
CREATE INDEX IF NOT EXISTS idx_assets_engagement ON assets(engagement_id);
CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(asset_type);

CREATE TABLE IF NOT EXISTS services (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT DEFAULT 'tcp',
    service_name TEXT DEFAULT '',
    version TEXT DEFAULT '',
    banner TEXT DEFAULT '',
    metadata TEXT DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
);
CREATE INDEX IF NOT EXISTS idx_services_host ON services(host);
CREATE INDEX IF NOT EXISTS idx_services_port ON services(port);

CREATE TABLE IF NOT EXISTS endpoints (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    url TEXT NOT NULL,
    method TEXT DEFAULT 'GET',
    parameters TEXT DEFAULT '[]',
    headers TEXT DEFAULT '{}',
    content_type TEXT DEFAULT '',
    status_code INTEGER,
    metadata TEXT DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
);
CREATE INDEX IF NOT EXISTS idx_endpoints_url ON endpoints(url);

CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    workspace_id TEXT DEFAULT '',
    evidence_type TEXT NOT NULL,
    source_tool TEXT DEFAULT '',
    source_version TEXT DEFAULT '',
    target TEXT DEFAULT '',
    content TEXT DEFAULT '{}',
    content_hash TEXT DEFAULT '',
    tags TEXT DEFAULT '[]',
    parent_event_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
);
CREATE INDEX IF NOT EXISTS idx_evidence_engagement ON evidence(engagement_id);
CREATE INDEX IF NOT EXISTS idx_evidence_type ON evidence(evidence_type);
CREATE INDEX IF NOT EXISTS idx_evidence_hash ON evidence(content_hash);

CREATE TABLE IF NOT EXISTS hypotheses (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    category TEXT NOT NULL,
    target TEXT NOT NULL,
    endpoint TEXT DEFAULT '',
    description TEXT DEFAULT '',
    preconditions TEXT DEFAULT '[]',
    observation TEXT DEFAULT '',
    hypothesis TEXT DEFAULT '',
    confidence TEXT DEFAULT 'none',
    impact TEXT DEFAULT '',
    evidence_ids TEXT DEFAULT '[]',
    validation_status TEXT DEFAULT 'hypothesis',
    next_test TEXT DEFAULT '',
    duplicate_group TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
);
CREATE INDEX IF NOT EXISTS idx_hypotheses_status ON hypotheses(validation_status);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT DEFAULT 'informational',
    confidence TEXT DEFAULT 'none',
    affected_asset TEXT DEFAULT '',
    affected_endpoint TEXT DEFAULT '',
    description TEXT DEFAULT '',
    impact TEXT DEFAULT '',
    preconditions TEXT DEFAULT '[]',
    steps_to_reproduce TEXT DEFAULT '[]',
    evidence_ids TEXT DEFAULT '[]',
    remediation TEXT DEFAULT '',
    `references` TEXT DEFAULT '[]',
    cwe_id TEXT,
    owasp_category TEXT,
    cvss_score REAL,
    cvss_vector TEXT,
    validation_status TEXT DEFAULT 'candidate',
    duplicate_group TEXT,
    tool_sources TEXT DEFAULT '[]',
    timeline TEXT DEFAULT '[]',
    technical_details TEXT DEFAULT '{}',
    authorization_status TEXT DEFAULT 'unverified',
    authorization_basis TEXT DEFAULT '',
    authorization_mode TEXT DEFAULT '',
    authorization_id TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
);
CREATE INDEX IF NOT EXISTS idx_findings_engagement ON findings(engagement_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(validation_status);

CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    status TEXT DEFAULT 'queued',
    target TEXT DEFAULT '',
    parameters TEXT DEFAULT '{}',
    result TEXT,
    error TEXT,
    started_at TEXT,
    completed_at TEXT,
    timeout_seconds REAL DEFAULT 300,
    retry_count INTEGER DEFAULT 0,
    max_retries INTEGER DEFAULT 2,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);

CREATE TABLE IF NOT EXISTS tool_runs (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    tool_version TEXT DEFAULT '',
    target TEXT DEFAULT '',
    parameters TEXT DEFAULT '{}',
    success INTEGER DEFAULT 1,
    raw_output TEXT DEFAULT '',
    normalized_output TEXT DEFAULT '{}',
    error TEXT,
    duration_ms REAL DEFAULT 0,
    evidence_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
);
CREATE INDEX IF NOT EXISTS idx_tool_runs_tool ON tool_runs(tool_name);

CREATE TABLE IF NOT EXISTS graph_nodes (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    node_type TEXT NOT NULL,
    label TEXT NOT NULL,
    properties TEXT DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
);
CREATE INDEX IF NOT EXISTS idx_graph_nodes_type ON graph_nodes(node_type);

CREATE TABLE IF NOT EXISTS graph_edges (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    source_node_id TEXT NOT NULL,
    target_node_id TEXT NOT NULL,
    edge_type TEXT NOT NULL,
    properties TEXT DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id),
    FOREIGN KEY (source_node_id) REFERENCES graph_nodes(id),
    FOREIGN KEY (target_node_id) REFERENCES graph_nodes(id)
);
CREATE INDEX IF NOT EXISTS idx_graph_edges_source ON graph_edges(source_node_id);
CREATE INDEX IF NOT EXISTS idx_graph_edges_target ON graph_edges(target_node_id);

CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    workspace_id TEXT DEFAULT '',
    event_type TEXT NOT NULL,
    actor TEXT DEFAULT 'system',
    target TEXT DEFAULT '',
    action TEXT DEFAULT '',
    result TEXT DEFAULT '',
    allowed INTEGER DEFAULT 1,
    metadata TEXT DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_log_engagement ON audit_log(engagement_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_event_type ON audit_log(event_type);

CREATE TABLE IF NOT EXISTS reports (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    title TEXT NOT NULL,
    format TEXT DEFAULT 'markdown',
    content TEXT DEFAULT '',
    finding_ids TEXT DEFAULT '[]',
    evidence_ids TEXT DEFAULT '[]',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
);

CREATE TABLE IF NOT EXISTS ctf_challenges (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    target TEXT DEFAULT '',
    port INTEGER,
    protocol TEXT DEFAULT '',
    description TEXT DEFAULT '',
    attachments TEXT DEFAULT '[]',
    known_artifacts TEXT DEFAULT '[]',
    candidate_flags TEXT DEFAULT '[]',
    confirmed_flag TEXT,
    notes TEXT DEFAULT '',
    hypotheses TEXT DEFAULT '[]',
    failed_attempts TEXT DEFAULT '[]',
    timeline TEXT DEFAULT '[]',
    status TEXT DEFAULT 'active',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
);

CREATE TABLE IF NOT EXISTS workspaces (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    engagement_id TEXT DEFAULT '',
    mode TEXT DEFAULT 'analysis_only',
    base_path TEXT DEFAULT '',
    is_sandboxed INTEGER DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS requests_history (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    headers TEXT DEFAULT '{}',
    body TEXT DEFAULT '',
    response_status INTEGER,
    response_headers TEXT DEFAULT '{}',
    response_body TEXT DEFAULT '',
    response_time_ms REAL DEFAULT 0,
    tags TEXT DEFAULT '[]',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
);
CREATE INDEX IF NOT EXISTS idx_requests_url ON requests_history(url);
"""


class Database:
    def __init__(self, db_path: str | None = None) -> None:
        cfg = get_config()
        self.db_path = db_path or cfg.database.path
        self._db: aiosqlite.Connection | None = None

    async def connect(self) -> None:
        os.makedirs(os.path.dirname(self.db_path) or ".", exist_ok=True)
        self._db = await aiosqlite.connect(self.db_path)
        self._db.row_factory = aiosqlite.Row
        await self._db.executescript(SCHEMA_SQL)
        await self._migrate()
        await self._db.commit()

    async def _migrate(self) -> None:
        # CTF challenges additions
        cursor = await self._db.execute("PRAGMA table_info(ctf_challenges)")
        cols = {row[1] for row in await cursor.fetchall()}
        if "hypotheses" not in cols:
            await self._db.execute("ALTER TABLE ctf_challenges ADD COLUMN hypotheses TEXT DEFAULT '[]'")
        if "failed_attempts" not in cols:
            await self._db.execute("ALTER TABLE ctf_challenges ADD COLUMN failed_attempts TEXT DEFAULT '[]'")
        if "timeline" not in cols:
            await self._db.execute("ALTER TABLE ctf_challenges ADD COLUMN timeline TEXT DEFAULT '[]'")
        # Phase 2: authorization attestation on findings
        cursor = await self._db.execute("PRAGMA table_info(findings)")
        fcols = {row[1] for row in await cursor.fetchall()}
        for col, default in [
            ("authorization_status", "unverified"),
            ("authorization_basis", ""),
            ("authorization_mode", ""),
            ("authorization_id", ""),
        ]:
            if col not in fcols:
                await self._db.execute(f"ALTER TABLE findings ADD COLUMN {col} TEXT DEFAULT '{default}'")

    async def close(self) -> None:
        if self._db:
            await self._db.close()

    @property
    def db(self) -> aiosqlite.Connection:
        assert self._db is not None, "Database not connected"
        return self._db

    # ── Generic helpers ────────────────────────────────────────────────────

    def _serialize(self, v: Any) -> Any:
        if isinstance(v, (list, dict)):
            return json.dumps(v)
        if isinstance(v, datetime):
            return v.isoformat()
        if isinstance(v, bool):
            return int(v)
        return v

    def _row_to_dict(self, row: aiosqlite.Row) -> dict[str, Any]:
        d = dict(row)
        for k, v in d.items():
            if isinstance(v, str) and v.startswith(("[", "{")):
                try:
                    d[k] = json.loads(v)
                except (json.JSONDecodeError, ValueError):
                    pass
        return d

    async def insert(self, table: str, data: dict[str, Any]) -> dict[str, Any]:
        sanitized = {k: self._serialize(v) for k, v in data.items() if v is not None}
        cols = ", ".join(f"`{k}`" for k in sanitized.keys())
        placeholders = ", ".join(["?" for _ in sanitized])
        sql = f"INSERT INTO {table} ({cols}) VALUES ({placeholders})"
        await self.db.execute(sql, list(sanitized.values()))
        await self.db.commit()
        record_id = sanitized.get("id", "")
        if record_id:
            return await self.get_by_id(table, str(record_id)) or sanitized
        return sanitized

    async def upsert(self, table: str, data: dict[str, Any], key: str = "id") -> dict[str, Any]:
        sanitized = {k: self._serialize(v) for k, v in data.items()}
        existing = await self.get_by_id(table, sanitized.get(key, ""))
        if existing:
            sets = ", ".join(f"`{k}` = ?" for k in sanitized if k != key)
            vals = [sanitized[k] for k in sanitized if k != key]
            vals.append(sanitized[key])
            await self.db.execute(f"UPDATE {table} SET {sets} WHERE `{key}` = ?", vals)
            await self.db.commit()
            return await self.get_by_id(table, str(sanitized[key])) or {**existing, **sanitized}
        else:
            return await self.insert(table, sanitized)

    async def get_by_id(self, table: str, record_id: str) -> dict[str, Any] | None:
        cursor = await self.db.execute(f"SELECT * FROM {table} WHERE `id` = ?", (record_id,))
        row = await cursor.fetchone()
        return self._row_to_dict(row) if row else None

    async def query(self, table: str, where: str = "1=1", params: list[Any] | None = None, limit: int = 100, order: str = "created_at DESC") -> list[dict[str, Any]]:
        sql = f"SELECT * FROM {table} WHERE {where} ORDER BY {order} LIMIT ?"
        p = (params or []) + [limit]
        cursor = await self.db.execute(sql, p)
        rows = await cursor.fetchall()
        return [self._row_to_dict(r) for r in rows]

    async def delete(self, table: str, where: str, params: list[Any] | None = None) -> int:
        cursor = await self.db.execute(f"DELETE FROM {table} WHERE {where}", params or [])
        await self.db.commit()
        return cursor.rowcount

    async def count(self, table: str, where: str = "1=1", params: list[Any] | None = None) -> int:
        cursor = await self.db.execute(f"SELECT COUNT(*) as cnt FROM {table} WHERE {where}", params or [])
        row = await cursor.fetchone()
        return row["cnt"] if row else 0

    # ── Engagement shortcuts ──────────────────────────────────────────────

    async def save_engagement(self, engagement: dict[str, Any]) -> dict[str, Any]:
        return await self.upsert("engagements", engagement)

    async def get_engagement(self, eid: str) -> dict[str, Any] | None:
        return await self.get_by_id("engagements", eid)

    async def list_engagements(self, limit: int = 50) -> list[dict[str, Any]]:
        return await self.query("engagements", limit=limit)

    async def save_scope_rule(self, rule: dict[str, Any]) -> dict[str, Any]:
        return await self.upsert("scope_rules", rule)

    async def get_scope_rules(self, engagement_id: str) -> list[dict[str, Any]]:
        return await self.query("scope_rules", where="engagement_id = ?", params=[engagement_id])

    async def save_asset(self, asset: dict[str, Any]) -> dict[str, Any]:
        return await self.upsert("assets", asset)

    async def get_assets(self, engagement_id: str, asset_type: str | None = None, limit: int = 500) -> list[dict[str, Any]]:
        if asset_type:
            return await self.query("assets", where="engagement_id = ? AND asset_type = ?", params=[engagement_id, asset_type], limit=limit)
        return await self.query("assets", where="engagement_id = ?", params=[engagement_id], limit=limit)

    async def save_evidence(self, ev: dict[str, Any]) -> dict[str, Any]:
        return await self.upsert("evidence", ev)

    async def get_evidence(self, engagement_id: str, evidence_type: str | None = None, limit: int = 500) -> list[dict[str, Any]]:
        if evidence_type:
            return await self.query("evidence", where="engagement_id = ? AND evidence_type = ?", params=[engagement_id, evidence_type], limit=limit)
        return await self.query("evidence", where="engagement_id = ?", params=[engagement_id], limit=limit)

    async def save_hypothesis(self, hyp: dict[str, Any]) -> dict[str, Any]:
        return await self.upsert("hypotheses", hyp)

    async def get_hypotheses(self, engagement_id: str, status: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        if status:
            return await self.query("hypotheses", where="engagement_id = ? AND validation_status = ?", params=[engagement_id, status], limit=limit)
        return await self.query("hypotheses", where="engagement_id = ?", params=[engagement_id], limit=limit)

    async def save_finding(self, finding: dict[str, Any]) -> dict[str, Any]:
        return await self.upsert("findings", finding)

    async def get_findings(self, engagement_id: str, severity: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        if severity:
            return await self.query("findings", where="engagement_id = ? AND severity = ?", params=[engagement_id, severity], limit=limit)
        return await self.query("findings", where="engagement_id = ?", params=[engagement_id], limit=limit)

    async def save_job(self, job: dict[str, Any]) -> dict[str, Any]:
        return await self.upsert("jobs", job)

    async def get_job(self, job_id: str) -> dict[str, Any] | None:
        return await self.get_by_id("jobs", job_id)

    async def list_jobs(self, engagement_id: str, status: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        if status:
            return await self.query("jobs", where="engagement_id = ? AND status = ?", params=[engagement_id, status], limit=limit)
        return await self.query("jobs", where="engagement_id = ?", params=[engagement_id], limit=limit)

    async def save_tool_run(self, run: dict[str, Any]) -> dict[str, Any]:
        return await self.upsert("tool_runs", run)

    async def log_audit(self, event: dict[str, Any]) -> dict[str, Any]:
        return await self.insert("audit_log", event)

    async def get_audit_log(self, engagement_id: str, limit: int = 200) -> list[dict[str, Any]]:
        return await self.query("audit_log", where="engagement_id = ?", params=[engagement_id], limit=limit)

    async def save_graph_node(self, node: dict[str, Any]) -> dict[str, Any]:
        return await self.upsert("graph_nodes", node)

    async def get_graph_nodes(self, engagement_id: str, node_type: str | None = None, limit: int = 1000) -> list[dict[str, Any]]:
        if node_type:
            return await self.query("graph_nodes", where="engagement_id = ? AND node_type = ?", params=[engagement_id, node_type], limit=limit)
        return await self.query("graph_nodes", where="engagement_id = ?", params=[engagement_id], limit=limit)

    async def save_graph_edge(self, edge: dict[str, Any]) -> dict[str, Any]:
        return await self.upsert("graph_edges", edge)

    async def get_graph_edges(self, engagement_id: str, source_node_id: str | None = None, limit: int = 1000) -> list[dict[str, Any]]:
        if source_node_id:
            return await self.query("graph_edges", where="engagement_id = ? AND source_node_id = ?", params=[engagement_id, source_node_id], limit=limit)
        return await self.query("graph_edges", where="engagement_id = ?", params=[engagement_id], limit=limit)

    async def save_report(self, report: dict[str, Any]) -> dict[str, Any]:
        return await self.upsert("reports", report)

    async def save_ctf_challenge(self, challenge: dict[str, Any]) -> dict[str, Any]:
        return await self.upsert("ctf_challenges", challenge)

    async def get_ctf_challenges(self, engagement_id: str) -> list[dict[str, Any]]:
        return await self.query("ctf_challenges", where="engagement_id = ?", params=[engagement_id])

    async def save_request_history(self, req: dict[str, Any]) -> dict[str, Any]:
        return await self.insert("requests_history", req)

    async def get_request_history(self, engagement_id: str, limit: int = 200) -> list[dict[str, Any]]:
        return await self.query("requests_history", where="engagement_id = ?", params=[engagement_id], limit=limit)

    async def save_workspace(self, ws: dict[str, Any]) -> dict[str, Any]:
        return await self.upsert("workspaces", ws)
