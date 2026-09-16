"""Core schemas, enums, and data models for OMEGA-CYBER-MCP."""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


# ── Enums ──────────────────────────────────────────────────────────────────

class EngagementMode(str, Enum):
    CTF = "ctf"
    BUG_BOUNTY = "bug_bounty"
    PENTEST = "pentest"
    LOCAL_LAB = "local_lab"
    ANALYSIS_ONLY = "analysis_only"
    REVERSE_ENGINEERING = "reversing"
    API_SECURITY = "api_security"
    WEB_SECURITY = "web_security"
    NETWORK_SECURITY = "network_security"


class RiskLevel(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Severity(str, Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIRMED = "confirmed"


class ValidationStatus(str, Enum):
    HYPOTHESIS = "hypothesis"
    CANDIDATE = "candidate"
    TESTING = "testing"
    VALIDATED = "validated"
    REJECTED = "rejected"
    DUPLICATE = "duplicate"
    INFORMATIONAL = "informational"


class ToolRiskLevel(str, Enum):
    READ_ONLY = "read_only"
    PASSIVE = "passive"
    ACTIVE = "active"
    DESTRUCTIVE = "destructive"


class JobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"


class NodeType(str, Enum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    CIDR = "cidr"
    PORT = "port"
    SERVICE = "service"
    URL = "url"
    ENDPOINT = "endpoint"
    PARAMETER = "parameter"
    JAVASCRIPT = "javascript"
    API = "api"
    TECHNOLOGY = "technology"
    CERTIFICATE = "certificate"
    CLOUD_ASSET = "cloud_asset"
    REPOSITORY = "repository"
    SECRET = "secret"
    FINDING = "finding"
    EVIDENCE = "evidence"
    SCREENSHOT = "screenshot"
    REQUEST = "request"
    RESPONSE = "response"


class EdgeType(str, Enum):
    RESOLVES_TO = "resolves_to"
    HOSTS = "hosts"
    SERVES = "serves"
    REDIRECTS_TO = "redirects_to"
    CONTAINS = "contains"
    REFERENCES = "references"
    CALLS = "calls"
    AUTHENTICATES_TO = "authenticates_to"
    EXPOSES = "exposes"
    SHARES_CERTIFICATE = "shares_certificate"
    USES_TECHNOLOGY = "uses_technology"
    PRODUCES = "produces"
    CONFIRMS = "confirms"
    CONTRADICTS = "contradicts"


class CTFCategory(str, Enum):
    WEB = "web"
    CRYPTO = "crypto"
    PWN = "pwn"
    REV = "rev"
    FORENSICS = "forensics"
    OSINT = "osint"
    MISC = "misc"
    STEGO = "stego"
    MOBILE = "mobile"
    BLOCKCHAIN = "blockchain"


class RateLimitPolicy(str, Enum):
    STEALTH = "stealth"
    NORMAL = "normal"
    AGGRESSIVE = "aggressive"


# ── Helper functions ───────────────────────────────────────────────────────

def new_id() -> str:
    return uuid.uuid4().hex[:16]


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def content_hash(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()[:16]


# ── Base Model ─────────────────────────────────────────────────────────────

class OmegaBase(BaseModel):
    """Base model with common fields."""
    id: str = Field(default_factory=new_id)
    created_at: datetime = Field(default_factory=now_utc)
    updated_at: datetime = Field(default_factory=now_utc)

    model_config = {"use_enum_values": True, "validate_assignment": True}


# ── Engagement & Scope ─────────────────────────────────────────────────────

class Engagement(OmegaBase):
    name: str
    mode: EngagementMode
    description: str = ""
    status: str = "active"
    workspace_id: str = ""
    rate_limit_policy: RateLimitPolicy = RateLimitPolicy.NORMAL


class ScopeRule(OmegaBase):
    engagement_id: str
    rule_type: str  # "include" | "exclude"
    target_type: str  # "domain" | "wildcard" | "ip" | "cidr" | "url" | "port"
    pattern: str
    description: str = ""
    ports: list[int] = Field(default_factory=list)
    protocols: list[str] = Field(default_factory=list)
    methods: list[str] = Field(default_factory=list)
    paths: list[str] = Field(default_factory=list)
    rate_limit_requests_per_second: float | None = None
    time_window_start: str | None = None  # HH:MM
    time_window_end: str | None = None    # HH:MM


class Authorization(OmegaBase):
    engagement_id: str
    credentials: dict[str, Any] = Field(default_factory=dict)
    tokens: list[dict[str, str]] = Field(default_factory=list)
    cookies: list[dict[str, str]] = Field(default_factory=list)
    notes: str = ""


# ── Assets ─────────────────────────────────────────────────────────────────

class Asset(OmegaBase):
    engagement_id: str
    asset_type: str  # NodeType value
    value: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)


class Service(OmegaBase):
    engagement_id: str
    host: str
    port: int
    protocol: str = "tcp"
    service_name: str = ""
    version: str = ""
    banner: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class Endpoint(OmegaBase):
    engagement_id: str
    url: str
    method: str = "GET"
    parameters: list[dict[str, Any]] = Field(default_factory=list)
    headers: dict[str, str] = Field(default_factory=dict)
    content_type: str = ""
    status_code: int | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


# ── Evidence ───────────────────────────────────────────────────────────────

class EvidenceType(str, Enum):
    HTTP_REQUEST = "http_request"
    HTTP_RESPONSE = "http_response"
    SCREENSHOT = "screenshot"
    DNS_RECORD = "dns_record"
    CERTIFICATE = "certificate"
    PORT_SCAN = "port_scan"
    SERVICE_INFO = "service_info"
    FILE = "file"
    CODE_SNIPPET = "code_snippet"
    TOOL_OUTPUT = "tool_output"
    BROWSER_EVENT = "browser_event"
    DIFF = "diff"
    HASH = "hash"
    TIMELINE_EVENT = "timeline_event"
    COMMAND_EXECUTION = "command_execution"


class Evidence(OmegaBase):
    engagement_id: str
    workspace_id: str = ""
    evidence_type: str
    source_tool: str = ""
    source_version: str = ""
    target: str = ""
    content: dict[str, Any] = Field(default_factory=dict)
    content_hash: str = ""
    tags: list[str] = Field(default_factory=list)
    parent_event_id: str | None = None


# ── Hypothesis ─────────────────────────────────────────────────────────────

class Hypothesis(OmegaBase):
    engagement_id: str
    category: str
    target: str
    endpoint: str = ""
    description: str = ""
    preconditions: list[str] = Field(default_factory=list)
    observation: str = ""
    hypothesis: str = ""
    confidence: Confidence = Confidence.NONE
    impact: str = ""
    evidence_ids: list[str] = Field(default_factory=list)
    validation_status: ValidationStatus = ValidationStatus.HYPOTHESIS
    next_test: str = ""
    duplicate_group: str | None = None


# ── Finding ────────────────────────────────────────────────────────────────

class Finding(OmegaBase):
    engagement_id: str
    title: str
    severity: Severity = Severity.INFORMATIONAL
    confidence: Confidence = Confidence.NONE
    affected_asset: str = ""
    affected_endpoint: str = ""
    description: str = ""
    impact: str = ""
    preconditions: list[str] = Field(default_factory=list)
    steps_to_reproduce: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    cwe_id: str | None = None
    owasp_category: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    validation_status: ValidationStatus = ValidationStatus.CANDIDATE
    duplicate_group: str | None = None
    tool_sources: list[str] = Field(default_factory=list)
    timeline: list[dict[str, Any]] = Field(default_factory=list)
    technical_details: dict[str, Any] = Field(default_factory=dict)

    # ── Authorization attestation ────────────────────────────────────────
    authorization_status: str = "unverified"   # authorized | not_in_scope | unverified
    authorization_basis: str = ""               # matched scope-rule pattern
    authorization_mode: str = ""                # engagement mode at creation time
    authorization_id: str = ""                  # unique attestation id


# ── Tool Adapter schemas ───────────────────────────────────────────────────

class ToolCapability(OmegaBase):
    name: str
    version: str = ""
    description: str = ""
    risk_level: ToolRiskLevel = ToolRiskLevel.READ_ONLY
    capabilities: list[str] = Field(default_factory=list)
    input_schema: dict[str, Any] = Field(default_factory=dict)
    output_schema: dict[str, Any] = Field(default_factory=dict)
    supported_platforms: list[str] = Field(default_factory=list)
    required_permissions: list[str] = Field(default_factory=list)
    is_available: bool = False
    binary_path: str | None = None


class ToolResult(OmegaBase):
    tool_name: str
    tool_version: str = ""
    success: bool = True
    raw_output: str = ""
    parsed_output: dict[str, Any] = Field(default_factory=dict)
    normalized_output: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    duration_ms: float = 0
    target: str = ""
    evidence_id: str | None = None


# ── Job ────────────────────────────────────────────────────────────────────

class Job(OmegaBase):
    engagement_id: str
    tool_name: str
    status: JobStatus = JobStatus.QUEUED
    target: str = ""
    parameters: dict[str, Any] = Field(default_factory=dict)
    result: ToolResult | None = None
    error: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    timeout_seconds: float = 300
    retry_count: int = 0
    max_retries: int = 2


# ── Workspace ──────────────────────────────────────────────────────────────

class Workspace(OmegaBase):
    name: str
    engagement_id: str = ""
    mode: EngagementMode = EngagementMode.ANALYSIS_ONLY
    base_path: str = ""
    is_sandboxed: bool = False


# ── Report ─────────────────────────────────────────────────────────────────

class Report(OmegaBase):
    engagement_id: str
    title: str
    format: str = "markdown"  # markdown | html | json
    content: str = ""
    finding_ids: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)


# ── Audit ──────────────────────────────────────────────────────────────────

class AuditEvent(OmegaBase):
    engagement_id: str
    workspace_id: str = ""
    event_type: str  # tool_execution | scope_check | finding | evidence | error
    actor: str = "system"
    target: str = ""
    action: str = ""
    result: str = ""
    allowed: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)


# ── Graph ──────────────────────────────────────────────────────────────────

class GraphNode(OmegaBase):
    engagement_id: str
    node_type: str  # NodeType value
    label: str
    properties: dict[str, Any] = Field(default_factory=dict)


class GraphEdge(OmegaBase):
    engagement_id: str
    source_node_id: str
    target_node_id: str
    edge_type: str  # EdgeType value
    properties: dict[str, Any] = Field(default_factory=dict)


# ── Tool execution request (internal) ─────────────────────────────────────

class ToolExecutionRequest(BaseModel):
    tool_name: str
    target: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    engagement_id: str = ""
    workspace_id: str = ""
    timeout_seconds: float = 300
    risk_level: ToolRiskLevel = ToolRiskLevel.ACTIVE


# ── API models for MCP tools ───────────────────────────────────────────────

class ReconRequest(BaseModel):
    target: str
    tools: list[str] = Field(default_factory=lambda: ["subfinder", "httpx"])
    engagement_id: str = ""
    max_depth: int = 2
    include_apis: bool = False


class WebScanRequest(BaseModel):
    target: str
    engagement_id: str = ""
    include_js_analysis: bool = True
    include_header_analysis: bool = True
    include_cors_analysis: bool = True
    max_pages: int = 50


class PortScanRequest(BaseModel):
    target: str
    ports: str = "1-10000"
    engagement_id: str = ""
    scan_type: str = "syn"  # syn | tcp | udp
    timeout: int = 300


class VulnScanRequest(BaseModel):
    target: str
    engagement_id: str = ""
    scanners: list[str] = Field(default_factory=lambda: ["nuclei"])
    severity_filter: list[str] = Field(default_factory=list)


class CTFChallengeRequest(BaseModel):
    name: str
    category: CTFCategory
    target: str = ""
    port: int | None = None
    protocol: str = ""
    description: str = ""
    attachments: list[str] = Field(default_factory=list)
    workspace_id: str = ""


class APIAnalysisRequest(BaseModel):
    target: str
    engagement_id: str = ""
    discover_openapi: bool = True
    discover_graphql: bool = True
    test_auth: bool = False
    test_idor: bool = False


class FindingCreateRequest(BaseModel):
    engagement_id: str
    title: str
    severity: Severity = Severity.INFORMATIONAL
    confidence: Confidence = Confidence.NONE
    affected_asset: str = ""
    affected_endpoint: str = ""
    description: str = ""
    impact: str = ""
    steps_to_reproduce: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    cwe_id: str | None = None
    remediation: str = ""


class ReportRequest(BaseModel):
    engagement_id: str
    format: str = "markdown"
    include_evidence: bool = True
    include_timeline: bool = True
    title: str = ""
