"""HTTP client engine — controlled HTTP requests with evidence collection."""

from __future__ import annotations

import logging
import time
from typing import Any
from urllib.parse import urlparse

import httpx

from omega.core.schemas import content_hash, new_id, now_utc
from omega.storage import Database

logger = logging.getLogger("omega.http")


class HTTPClient:
    """Controlled HTTP client with proxy support, redirect control, and evidence storage."""

    def __init__(self, db: Database | None = None) -> None:
        self.db = db
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self, timeout: float = 30, follow_redirects: bool = True, proxy: str | None = None) -> httpx.AsyncClient:
        transport_kwargs: dict[str, Any] = {}
        if proxy:
            transport_kwargs["proxy"] = proxy
        return httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=follow_redirects,
            verify=True,
            **transport_kwargs,
        )

    async def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        body: str | bytes | None = None,
        json_body: Any = None,
        timeout: float = 30,
        follow_redirects: bool = True,
        proxy: str | None = None,
    ) -> dict[str, Any]:
        """Execute an HTTP request and return structured response."""
        client = await self._get_client(timeout, follow_redirects, proxy)
        try:
            start = time.monotonic()
            try:
                resp = await client.request(
                    method,
                    url,
                    headers=headers,
                    cookies=cookies,
                    params=params,
                    content=body,
                    json=json_body,
                )
            except httpx.HTTPError as e:
                duration_ms = (time.monotonic() - start) * 1000
                logger.warning("HTTP %s %s failed: %s", method, url, e)
                return {
                    "url": url,
                    "status_code": 0,
                    "reason": str(e),
                    "headers": {},
                    "body": "",
                    "body_length": 0,
                    "duration_ms": duration_ms,
                    "redirect_chain": [],
                    "content_type": "",
                    "cookies": {},
                    "error": f"{type(e).__name__}: {e}",
                }
            except Exception as e:  # noqa: BLE001 - never let a network/parsing error crash a tool
                duration_ms = (time.monotonic() - start) * 1000
                logger.exception("HTTP %s %s failed unexpectedly", method, url)
                return {
                    "url": url,
                    "status_code": 0,
                    "reason": str(e),
                    "headers": {},
                    "body": "",
                    "body_length": 0,
                    "duration_ms": duration_ms,
                    "redirect_chain": [],
                    "content_type": "",
                    "cookies": {},
                    "error": f"{type(e).__name__}: {e}",
                }
            duration_ms = (time.monotonic() - start) * 1000

            result: dict[str, Any] = {
                "url": str(resp.url),
                "status_code": resp.status_code,
                "reason": resp.reason_phrase,
                "headers": dict(resp.headers),
                "body": resp.text[:500_000],
                "body_length": len(resp.content),
                "duration_ms": duration_ms,
                "redirect_chain": [str(r.url) for r in resp.history],
                "content_type": resp.headers.get("content-type", ""),
                "cookies": dict(resp.cookies),
            }
            return result
        finally:
            await client.aclose()

    async def get(self, url: str, **kwargs: Any) -> dict[str, Any]:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> dict[str, Any]:
        return await self.request("POST", url, **kwargs)

    async def store_request(self, engagement_id: str, method: str, url: str, resp: dict[str, Any]) -> None:
        if not self.db:
            return
        await self.db.save_request_history({
            "id": new_id(),
            "engagement_id": engagement_id,
            "method": method,
            "url": url,
            "headers": resp.get("headers", {}),
            "body": resp.get("body", "")[:100000],
            "response_status": resp.get("status_code"),
            "response_headers": resp.get("headers", {}),
            "response_body": resp.get("body", "")[:100000],
            "response_time_ms": resp.get("duration_ms", 0),
            "created_at": now_utc().isoformat(),
            "updated_at": now_utc().isoformat(),
        })
