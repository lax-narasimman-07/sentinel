"""Browser automation engine — Playwright-based web interaction with scope enforcement."""

from __future__ import annotations

import asyncio
import base64
import logging
from typing import Any
from urllib.parse import urlparse

from sentinel.core.schemas import new_id, now_utc
from sentinel.storage import Database

logger = logging.getLogger("sentinel.browser")


class BrowserEngine:
    """Playwright-based browser automation with scope enforcement."""

    def __init__(self, db: Database | None = None) -> None:
        self.db = db
        self._playwright: Any = None
        self._browser: Any = None
        self._contexts: dict[str, Any] = {}
        self._pages: dict[str, Any] = {}
        self._network_logs: dict[str, list[dict[str, Any]]] = {}
        self._scopes: dict[str, str] = {}  # context_id -> scope domain
        self._js_storages: dict[str, dict[str, str]] = {}

    async def launch(self, headless: bool = True, browser_type: str = "chromium") -> dict[str, Any]:
        """Launch browser instance."""
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return {
                "id": new_id(),
                "success": False,
                "error": "Playwright is not installed. Run: pip install playwright && playwright install",
                "timestamp": now_utc().isoformat(),
            }

        try:
            self._playwright = await async_playwright().start()

            launcher = getattr(self._playwright, browser_type, None)
            if launcher is None:
                await self._playwright.stop()
                self._playwright = None
                return {
                    "id": new_id(),
                    "success": False,
                    "error": f"Unsupported browser type: {browser_type}",
                    "timestamp": now_utc().isoformat(),
                }

            self._browser = await launcher.launch(headless=headless)
            return {
                "id": new_id(),
                "success": True,
                "browser_type": browser_type,
                "headless": headless,
                "timestamp": now_utc().isoformat(),
            }
        except Exception as e:
            logger.exception("Failed to launch browser")
            return {
                "id": new_id(),
                "success": False,
                "error": str(e),
                "timestamp": now_utc().isoformat(),
            }

    async def new_context(self, context_id: str = "", engagement_id: str = "") -> str:
        """Create isolated browser context for an engagement."""
        if not self._browser:
            raise RuntimeError("Browser not launched. Call launch() first.")

        cid = context_id or new_id()
        if cid in self._contexts:
            return cid

        context = await self._browser.new_context(
            viewport={"width": 1920, "height": 1080},
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            ignore_https_errors=True,
        )

        self._contexts[cid] = {
            "context": context,
            "engagement_id": engagement_id,
            "created_at": now_utc().isoformat(),
        }
        self._network_logs[cid] = []
        self._js_storages[cid] = {}

        page = await context.new_page()
        self._pages[cid] = page

        # Set up network request logging
        page.on("request", lambda req: self._on_request(cid, req))
        page.on("response", lambda resp: self._on_response(cid, resp))

        logger.info("Created browser context %s (engagement=%s)", cid, engagement_id)
        return cid

    async def navigate(self, context_id: str, url: str) -> dict[str, Any]:
        """Navigate to URL in a context. Returns page info."""
        page = self._get_page(context_id)
        if page is None:
            return {"id": new_id(), "success": False, "error": f"Context {context_id} not found"}

        # Scope enforcement
        scope_domain = self._scopes.get(context_id)
        if scope_domain:
            parsed = urlparse(url)
            if parsed.hostname and not self._in_scope(parsed.hostname, scope_domain):
                return {
                    "id": new_id(),
                    "success": False,
                    "error": f"Out-of-scope navigation blocked: {url} (scope: {scope_domain})",
                    "url": url,
                }

        try:
            response = await page.goto(url, wait_until="domcontentloaded", timeout=30000)
            status = response.status if response else 0
            title = await page.title()
            current_url = page.url

            # Auto-set scope from first navigation if not set
            if context_id not in self._scopes:
                parsed = urlparse(current_url)
                if parsed.hostname:
                    self._scopes[context_id] = parsed.hostname

            return {
                "id": new_id(),
                "success": True,
                "url": current_url,
                "title": title,
                "status": status,
                "timestamp": now_utc().isoformat(),
            }
        except Exception as e:
            logger.exception("Navigation failed: %s", url)
            return {
                "id": new_id(),
                "success": False,
                "error": str(e),
                "url": url,
                "timestamp": now_utc().isoformat(),
            }

    async def fill_form(self, context_id: str, selector: str, value: str) -> dict[str, Any]:
        """Fill a form field identified by CSS selector."""
        page = self._get_page(context_id)
        if page is None:
            return {"id": new_id(), "success": False, "error": f"Context {context_id} not found"}

        try:
            await page.fill(selector, value)
            return {
                "id": new_id(),
                "success": True,
                "selector": selector,
                "timestamp": now_utc().isoformat(),
            }
        except Exception as e:
            return {"id": new_id(), "success": False, "error": str(e)}

    async def screenshot(self, context_id: str, full_page: bool = False) -> dict[str, Any]:
        """Take screenshot, return base64-encoded PNG."""
        page = self._get_page(context_id)
        if page is None:
            return {"id": new_id(), "success": False, "error": f"Context {context_id} not found"}

        try:
            screenshot_bytes = await page.screenshot(full_page=full_page, type="png")
            b64_data = base64.b64encode(screenshot_bytes).decode("ascii")
            return {
                "id": new_id(),
                "success": True,
                "screenshot_base64": b64_data,
                "size_bytes": len(screenshot_bytes),
                "url": page.url,
                "title": await page.title(),
                "timestamp": now_utc().isoformat(),
            }
        except Exception as e:
            return {"id": new_id(), "success": False, "error": str(e)}

    async def execute_js(self, context_id: str, script: str) -> dict[str, Any]:
        """Execute JavaScript and return result."""
        page = self._get_page(context_id)
        if page is None:
            return {"id": new_id(), "success": False, "error": f"Context {context_id} not found"}

        try:
            result = await page.evaluate(script)
            return {
                "id": new_id(),
                "success": True,
                "result": result,
                "timestamp": now_utc().isoformat(),
            }
        except Exception as e:
            return {"id": new_id(), "success": False, "error": str(e)}

    async def get_cookies(self, context_id: str) -> dict[str, Any]:
        """Get all cookies from the browser context."""
        ctx_data = self._contexts.get(context_id)
        if ctx_data is None:
            return {"id": new_id(), "success": False, "error": f"Context {context_id} not found"}

        try:
            context = ctx_data["context"]
            cookies = await context.cookies()
            return {
                "id": new_id(),
                "success": True,
                "cookies": cookies,
                "count": len(cookies),
                "timestamp": now_utc().isoformat(),
            }
        except Exception as e:
            return {"id": new_id(), "success": False, "error": str(e)}

    async def get_storage(self, context_id: str, storage_type: str = "local") -> dict[str, Any]:
        """Get localStorage or sessionStorage contents via JavaScript."""
        page = self._get_page(context_id)
        if page is None:
            return {"id": new_id(), "success": False, "error": f"Context {context_id} not found"}

        if storage_type not in ("local", "session"):
            return {"id": new_id(), "success": False, "error": f"Invalid storage_type: {storage_type}"}

        try:
            storage_name = f"{storage_type}Storage"
            script = f"""() => {{
                const storage = window.{storage_name};
                const items = {{}};
                for (let i = 0; i < storage.length; i++) {{
                    const key = storage.key(i);
                    items[key] = storage.getItem(key);
                }}
                return items;
            }}"""
            result = await page.evaluate(script)
            return {
                "id": new_id(),
                "success": True,
                "storage_type": storage_type,
                "items": result,
                "count": len(result),
                "timestamp": now_utc().isoformat(),
            }
        except Exception as e:
            return {"id": new_id(), "success": False, "error": str(e)}

    async def get_network_requests(self, context_id: str) -> dict[str, Any]:
        """Return captured network requests for a context."""
        if context_id not in self._network_logs:
            return {"id": new_id(), "success": False, "error": f"Context {context_id} not found"}

        logs = self._network_logs.get(context_id, [])
        return {
            "id": new_id(),
            "success": True,
            "requests": logs,
            "count": len(logs),
            "timestamp": now_utc().isoformat(),
        }

    async def get_dom_elements(self, context_id: str, selector: str) -> dict[str, Any]:
        """Extract DOM elements matching a CSS selector."""
        page = self._get_page(context_id)
        if page is None:
            return {"id": new_id(), "success": False, "error": f"Context {context_id} not found"}

        try:
            elements = await page.evaluate(f"""() => {{
                const els = document.querySelectorAll('{selector}');
                return Array.from(els).map(el => ({{
                    tag: el.tagName,
                    id: el.id,
                    classes: Array.from(el.classList),
                    text: el.textContent?.substring(0, 500) || '',
                    attributes: Object.fromEntries(Array.from(el.attributes).map(a => [a.name, a.value])),
                    innerHTML: el.innerHTML?.substring(0, 1000) || '',
                }}));
            }}""")
            return {
                "id": new_id(),
                "success": True,
                "selector": selector,
                "elements": elements,
                "count": len(elements),
                "timestamp": now_utc().isoformat(),
            }
        except Exception as e:
            return {"id": new_id(), "success": False, "error": str(e)}

    async def close_context(self, context_id: str) -> None:
        """Close and cleanup a browser context."""
        ctx_data = self._contexts.pop(context_id, None)
        if ctx_data:
            try:
                await ctx_data["context"].close()
            except Exception:
                pass
        self._pages.pop(context_id, None)
        self._network_logs.pop(context_id, None)
        self._js_storages.pop(context_id, None)
        self._scopes.pop(context_id, None)
        logger.info("Closed browser context %s", context_id)

    async def close(self) -> None:
        """Close browser and playwright."""
        for cid in list(self._contexts.keys()):
            await self.close_context(cid)

        if self._browser:
            try:
                await self._browser.close()
            except Exception:
                pass
            self._browser = None

        if self._playwright:
            try:
                await self._playwright.stop()
            except Exception:
                pass
            self._playwright = None

        logger.info("Browser engine closed")

    async def is_available(self) -> bool:
        """Check if Playwright is installed."""
        try:
            from playwright.async_api import async_playwright  # noqa: F401
            return True
        except ImportError:
            return False

    # ── Internal helpers ────────────────────────────────────────────────────

    def _get_page(self, context_id: str) -> Any | None:
        """Get the page for a given context, or None."""
        return self._pages.get(context_id)

    def _in_scope(self, hostname: str, scope_domain: str) -> bool:
        """Check if a hostname is within the scope domain."""
        hostname = hostname.lower().strip(".")
        scope_domain = scope_domain.lower().strip(".")
        return hostname == scope_domain or hostname.endswith("." + scope_domain)

    def _on_request(self, context_id: str, request: Any) -> None:
        """Callback for network requests."""
        try:
            log_entry = {
                "timestamp": now_utc().isoformat(),
                "method": request.method,
                "url": request.url,
                "resource_type": request.resource_type,
                "headers": dict(request.headers) if hasattr(request, "headers") else {},
            }
            self._network_logs.setdefault(context_id, []).append(log_entry)
        except Exception:
            pass

    def _on_response(self, context_id: str, response: Any) -> None:
        """Callback for network responses — enriches the last matching request."""
        try:
            logs = self._network_logs.get(context_id, [])
            url = response.url
            for entry in reversed(logs):
                if entry.get("url") == url and "status" not in entry:
                    entry["status"] = response.status
                    entry["status_text"] = response.status_text
                    entry["response_headers"] = dict(response.headers) if hasattr(response, "headers") else {}
                    break
        except Exception:
            pass
