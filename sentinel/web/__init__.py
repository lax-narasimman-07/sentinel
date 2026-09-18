"""Advanced web security engine — deep analysis of web applications."""

from __future__ import annotations

import base64
import json
import logging
import re
import time
from typing import Any
from urllib.parse import urlparse, urljoin, parse_qs

from sentinel.http import HTTPClient
from sentinel.storage import Database
from sentinel.core.schemas import new_id, now_utc

logger = logging.getLogger("sentinel.web")


_SAFE_URL_SCHEMES = re.compile(r"^(?:https?|wss?)://", re.IGNORECASE)
_ANY_SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
_DANGEROUS_SCHEMES = re.compile(
    r"^(?:javascript|vbscript|data|file|about|chrome|chrome-extension):", re.IGNORECASE
)


def normalize_target_url(target: str) -> str:
    """Normalize a bare host/domain/IP to a full URL, defaulting to http:// (local-first).

    Rejects non-http(s)/ws(s) schemes (``javascript:``, ``data:``, ``file:``, ...).
    """
    target = (target or "").strip()
    if not target:
        return target
    if _SAFE_URL_SCHEMES.match(target):
        return target
    if _DANGEROUS_SCHEMES.match(target) or _ANY_SCHEME.match(target):
        raise ValueError(f"Unsupported URL scheme in target: {target[:64]!r}")
    return f"http://{target}"


def _redact_token(token: str) -> str:
    """Short preview of a credential for output — never leak the full token."""
    if len(token) <= 16:
        return token[:4] + "…"
    return token[:16] + "…"


class WebSecurityEngine:
    """Comprehensive web security analysis engine."""

    def __init__(self, db: Database) -> None:
        self.db = db
        self.http = HTTPClient(db)

    async def analyze_headers(self, url: str, engagement_id: str = "") -> dict[str, Any]:
        """Deep HTTP security header analysis."""
        url = normalize_target_url(url)
        resp = await self.http.get(url)
        headers = resp.get("headers", {})
        lower_headers = {k.lower(): v for k, v in headers.items()}

        findings = []
        security_headers = {
            "strict-transport-security": {"severity": "medium", "desc": "Missing HSTS", "present_desc": "HSTS present"},
            "content-security-policy": {"severity": "high", "desc": "Missing CSP", "present_desc": "CSP present"},
            "x-frame-options": {"severity": "medium", "desc": "Missing X-Frame-Options (clickjacking risk)", "present_desc": "X-Frame-Options present"},
            "x-content-type-options": {"severity": "low", "desc": "Missing X-Content-Type-Options (MIME sniffing)", "present_desc": "X-Content-Type-Options present"},
            "x-xss-protection": {"severity": "low", "desc": "Missing X-XSS-Protection", "present_desc": "X-XSS-Protection present"},
            "referrer-policy": {"severity": "low", "desc": "Missing Referrer-Policy", "present_desc": "Referrer-Policy present"},
            "permissions-policy": {"severity": "low", "desc": "Missing Permissions-Policy", "present_desc": "Permissions-Policy present"},
            "cross-origin-opener-policy": {"severity": "medium", "desc": "Missing COOP", "present_desc": "COOP present"},
            "cross-origin-resource-policy": {"severity": "medium", "desc": "Missing CORP", "present_desc": "CORP present"},
            "cross-origin-embedder-policy": {"severity": "low", "desc": "Missing COEP", "present_desc": "COEP present"},
        }

        for header, info in security_headers.items():
            if header not in lower_headers:
                findings.append({"header": header, "severity": info["severity"], "description": info["desc"], "present": False})
            else:
                value = lower_headers[header]
                findings.append({"header": header, "severity": "informational", "value": value, "present": True, "description": info["present_desc"]})
                if header == "content-security-policy":
                    if "unsafe-inline" in value.lower():
                        findings.append({"header": header, "severity": "medium", "description": "CSP allows unsafe-inline", "present": True})
                    if "unsafe-eval" in value.lower():
                        findings.append({"header": header, "severity": "high", "description": "CSP allows unsafe-eval", "present": True})
                    if "data:" in value.lower():
                        findings.append({"header": header, "severity": "medium", "description": "CSP allows data: URIs", "present": True})

        info_disclosure = []
        for h in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-runtime"):
            if h in lower_headers:
                info_disclosure.append({"type": h, "value": lower_headers[h]})

        return {
            "url": url, "status_code": resp.get("status_code"),
            "security_headers": findings, "info_disclosure": info_disclosure,
            "all_headers": headers,
            "body": resp.get("body", ""),
        }

    async def analyze_cors(self, url: str, engagement_id: str = "") -> dict[str, Any]:
        """Deep CORS misconfiguration analysis."""
        url = normalize_target_url(url)
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        hostname = parsed.hostname or parsed.netloc.split(":")[0]

        origins_to_test = [
            ("null", "null origin"),
            (origin, "same origin"),
            (f"{parsed.scheme}://evil.com", "external origin"),
            (f"{parsed.scheme}://evil-{parsed.netloc}", "prefix-similar origin"),
            (f"{parsed.scheme}://{hostname}.evil.com", "subdomain of attacker"),
        ]

        results = []
        for test_origin, desc in origins_to_test:
            resp = await self.http.request("GET", url, headers={"Origin": test_origin})
            acao = resp.get("headers", {}).get("access-control-allow-origin", "")
            acac = resp.get("headers", {}).get("access-control-allow-credentials", "")
            acam = resp.get("headers", {}).get("access-control-allow-methods", "")
            acah = resp.get("headers", {}).get("access-control-allow-headers", "")

            reflected = acao == test_origin and test_origin != origin
            cred_acac = acac.lower() == "true"

            results.append({
                "origin_tested": test_origin,
                "description": desc,
                "access_control_allow_origin": acao,
                "access_control_allow_credentials": acac,
                "access_control_allow_methods": acam,
                "access_control_allow_headers": acah,
                "reflected": reflected,
                "credentials_allowed": cred_acac,
            })

        vulns = [r for r in results if r["reflected"] and r["credentials_allowed"]]
        return {
            "url": url, "cors_results": results,
            "vulnerable": len(vulns) > 0,
            "severity": "high" if vulns else "informational",
            "findings": [{"type": "cors_reflection_with_credentials", "origin": v["origin_tested"], "severity": "high"} for v in vulns],
        }

    async def analyze_cookies(self, url: str, engagement_id: str = "") -> dict[str, Any]:
        """Deep cookie security analysis."""
        url = normalize_target_url(url)
        resp = await self.http.get(url)
        cookies_info = []
        set_cookie_headers = []
        for k, v in resp.get("headers", {}).items():
            if k.lower() == "set-cookie":
                set_cookie_headers.append(v)

        for name, value in resp.get("cookies", {}).items():
            info = {
                "name": name, "value_length": len(value),
                "has_httponly": False, "has_secure": False,
                "has_samesite": False, "samesite_value": "",
                "has_expiry": False, "is_session": True,
            }
            for sc in set_cookie_headers:
                if name in sc.split("=")[0] if "=" in sc else name in sc:
                    sc_lower = sc.lower()
                    info["has_httponly"] = "httponly" in sc_lower
                    info["has_secure"] = "secure" in sc_lower
                    if "samesite=" in sc_lower:
                        info["has_samesite"] = True
                        match = re.search(r"samesite=(\w+)", sc_lower)
                        info["samesite_value"] = match.group(1) if match else "strict"
                    if "expires=" in sc_lower:
                        info["has_expiry"] = True
                        info["is_session"] = False
            cookies_info.append(info)

        findings = []
        for c in cookies_info:
            if not c["has_httponly"]:
                findings.append({"cookie": c["name"], "severity": "medium", "description": f"Cookie '{c['name']}' missing HttpOnly"})
            if not c["has_secure"]:
                findings.append({"cookie": c["name"], "severity": "medium", "description": f"Cookie '{c['name']}' missing Secure flag"})
            if not c["has_samesite"]:
                findings.append({"cookie": c["name"], "severity": "low", "description": f"Cookie '{c['name']}' missing SameSite"})

        return {"url": url, "cookies": cookies_info, "cookie_count": len(cookies_info), "findings": findings}

    async def extract_endpoints(self, url: str, body: str = "", engagement_id: str = "") -> dict[str, Any]:
        """Extract endpoints from HTML/JS with deep pattern matching."""
        endpoints = set()
        api_patterns = set()

        patterns = [
            r'(?:href|src|action|url|data-url|data-action)\s*[=:]\s*["\']([^"\']+)["\']',
            r'fetch\s*\(\s*["\']([^"\']+)["\']',
            r'XMLHttpRequest\.open\s*\(\s*["\'][A-Z]+["\']\s*,\s*["\']([^"\']+)["\']',
            r'axios\.\w+\s*\(\s*["\']([^"\']+)["\']',
            r'\$\.ajax\s*\(\s*\{\s*url\s*:\s*["\']([^"\']+)["\']',
            r'/api/[a-zA-Z0-9/_-]+',
            r'/v[0-9]+/[a-zA-Z0-9/_-]+',
            r'(?:GET|POST|PUT|DELETE|PATCH)\s+[\'"](/[^"\']*)',
            r'["\'](https?://[^"\']+)["\']',
            r'(wss?://[^\s"\']+)',
        ]

        for pattern in patterns:
            matches = re.findall(pattern, body, re.IGNORECASE)
            for m in matches:
                if m.startswith("/"):
                    parsed = urlparse(url)
                    m = f"{parsed.scheme}://{parsed.netloc}{m}"
                elif not m.startswith("http") and not m.startswith("ws"):
                    m = urljoin(url, m)
                endpoints.add(m)
                if "/api/" in m or "/v1/" in m or "/v2/" in m or "graphql" in m.lower():
                    api_patterns.add(m)

        return {
            "url": url, "endpoints": sorted(endpoints),
            "api_endpoints": sorted(api_patterns),
            "count": len(endpoints),
        }

    async def analyze_javascript(self, js_url: str, engagement_id: str = "") -> dict[str, Any]:
        """Deep JavaScript analysis — secrets, endpoints, patterns."""
        js_url = normalize_target_url(js_url)
        resp = await self.http.get(js_url)
        body = resp.get("body", "")

        secrets = []
        secret_patterns = [
            (r'["\']([A-Za-z0-9+/]{40,})["\']', "possible_api_key"),
            (r'["\']?(sk-[A-Za-z0-9]{20,})["\']?', "openai_key"),
            (r'["\']?(ghp_[A-Za-z0-9]{36})["\']?', "github_pat"),
            (r'["\']?(gho_[A-Za-z0-9]{36})["\']?', "github_oauth_token"),
            (r'["\']?(AKIA[A-Z0-9]{16})["\']?', "aws_access_key"),
            (r'(?:password|secret|token|key|api_key|apikey|auth)\s*[:=]\s*["\']([^"\']{8,})["\']', "hardcoded_secret"),
            (r'Bearer\s+[A-Za-z0-9._-]{20,}', "bearer_token"),
            (r'["\']([A-Za-z0-9]{32,})["\']', "possible_token"),
            (r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----', "private_key"),
            (r'mongodb(\+srv)?://[^\s"\']+', "mongodb_connection_string"),
            (r'postgres(ql)?://[^\s"\']+', "database_connection_string"),
            (r'redis://[^\s"\']+', "redis_connection_string"),
        ]
        for pattern, name in secret_patterns:
            found = re.findall(pattern, body, re.IGNORECASE)
            for f in found:
                secrets.append({"type": name, "value_preview": f[:20] + "..." if len(f) > 20 else f, "full_length": len(f)})

        sinks = re.findall(r'(?:document\.write|innerHTML|outerHTML|eval\(|setTimeout\(|setInterval\(|\.html\(|dangerouslySetInnerHTML)', body)
        sources = re.findall(r'(?:document\.URL|document\.documentURI|location\.href|location\.search|window\.name|document\.referrer|postMessage)', body)

        frameworks = []
        if re.search(r'react|jsx|createElement', body, re.I):
            frameworks.append("React")
        if re.search(r'vue|Vue\.', body, re.I):
            frameworks.append("Vue.js")
        if re.search(r'angular|ng-app|ng-controller', body, re.I):
            frameworks.append("Angular")
        if re.search(r'jquery|\$\.', body, re.I):
            frameworks.append("jQuery")
        if re.search(r'next|__NEXT_DATA__', body, re.I):
            frameworks.append("Next.js")
        if re.search(r'nuxt|__NUXT__', body, re.I):
            frameworks.append("Nuxt.js")

        endpoints = await self.extract_endpoints(js_url, body, engagement_id)

        findings = [
            {"type": "dom_xss_risk", "sinks": sinks, "sources": sources, "severity": "medium"} if sinks and sources else None,
            {"type": "secret_in_js", "count": len(secrets), "severity": "high"} if secrets else None,
        ]

        return {
            "url": js_url, "body_length": len(body),
            "secrets": secrets, "endpoints": endpoints.get("endpoints", []),
            "dom_sinks": sinks, "dom_sources": sources,
            "frameworks": frameworks,
            "findings": [f for f in findings if f is not None],
        }

    async def analyze_jwt(self, url: str, engagement_id: str = "") -> dict[str, Any]:
        """Analyze JWT tokens found in cookies/headers."""
        url = normalize_target_url(url)
        resp = await self.http.get(url)
        jwt_tokens = []
        findings = []

        for name, value in resp.get("cookies", {}).items():
            if value.count(".") == 2 and len(value) > 50:
                jwt_tokens.append({"source": "cookie", "name": name, "token": value})

        body = resp.get("body", "")
        jwt_matches = re.findall(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', body)
        for m in jwt_matches:
            jwt_tokens.append({"source": "body", "token": m})

        for token in resp.get("headers", {}).get("authorization", "").split():
            if token.count(".") == 2 and token.startswith("eyJ"):
                jwt_tokens.append({"source": "header", "token": token})

        for jwt_info in jwt_tokens:
            token = jwt_info["token"]
            try:
                parts = token.split(".")
                padding = 4 - len(parts[1]) % 4
                payload = base64.urlsafe_b64decode(parts[1] + "=" * padding)
                data = json.loads(payload)

                jwt_info["header"] = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
                jwt_info["payload"] = data

                alg = jwt_info["header"].get("alg", "")
                if alg == "none":
                    findings.append({"type": "jwt_none_algorithm", "severity": "high", "description": "JWT uses 'none' algorithm"})
                if alg in ("HS256", "HS384", "HS512"):
                    findings.append({"type": "jwt_symmetric", "severity": "info", "description": f"JWT uses symmetric algorithm: {alg}", "note": "Check for weak secret"})

                exp = data.get("exp")
                if exp and isinstance(exp, (int, float)) and exp < time.time():
                    findings.append({"type": "jwt_expired", "severity": "info", "description": "JWT appears expired"})

            except Exception as e:  # noqa: BLE001 - malformed token must not break analysis
                logger.debug("JWT decode failed for %s: %s", jwt_info.get("source"), e)

        # Never leak raw tokens to output — only redacted previews.
        for jwt_info in jwt_tokens:
            raw = jwt_info.pop("token", "")
            jwt_info["token_preview"] = _redact_token(raw)

        return {"url": url, "jwt_tokens": jwt_tokens, "findings": findings}

    async def detect_technologies(self, url: str, engagement_id: str = "") -> dict[str, Any]:
        """Technology stack detection from headers, body, cookies."""
        url = normalize_target_url(url)
        resp = await self.http.get(url)
        headers = {k.lower(): v for k, v in resp.get("headers", {}).items()}
        body = resp.get("body", "")

        technologies = []
        server = headers.get("server", "")
        if server:
            technologies.append({"name": "server", "value": server, "source": "header"})
        powered_by = headers.get("x-powered-by", "")
        if powered_by:
            technologies.append({"name": "x-powered-by", "value": powered_by, "source": "header"})

        body_patterns = [
            (r'wp-content|wordpress', "WordPress"),
            (r'joomla|com_content', "Joomla"),
            (r'drupal', "Drupal"),
            (r'laravel|csrf-token', "Laravel"),
            (r'django|csrfmiddlewaretoken', "Django"),
            (r'rails|csrf-token', "Ruby on Rails"),
            (r'next|__NEXT_DATA__', "Next.js"),
            (r'nuxt|__NUXT__', "Nuxt.js"),
            (r'react|__react', "React"),
            (r'vue|__vue__', "Vue.js"),
            (r'angular|ng-version', "Angular"),
            (r'jquery', "jQuery"),
            (r'bootstrap', "Bootstrap"),
            (r'tailwind', "Tailwind CSS"),
        ]
        for pattern, name in body_patterns:
            if re.search(pattern, body, re.I):
                technologies.append({"name": name, "source": "body"})

        cookie_patterns = [
            ("PHPSESSID", "PHP"),
            ("JSESSIONID", "Java"),
            ("ASP.NET_SessionId", "ASP.NET"),
            ("connect.sid", "Express/Node.js"),
            ("_rails_session", "Ruby on Rails"),
            ("csrftoken", "Django"),
            ("XSRF-TOKEN", "Laravel"),
        ]
        for cookie_name, tech in cookie_patterns:
            if cookie_name in resp.get("cookies", {}):
                technologies.append({"name": tech, "source": "cookie"})

        return {"url": url, "technologies": technologies}

    async def full_scan(self, target: str, engagement_id: str = "") -> dict[str, Any]:
        """Run comprehensive web security scan.

        Each sub-analysis is isolated so a single failed component never crashes
        the whole scan. Failures are surfaced in ``scan_errors`` with the raw
        reason, never fabricated as results.
        """
        url = normalize_target_url(target)
        results: dict[str, Any] = {"target": url, "scan_errors": []}

        async def _safe(name: str, awaitable: Any) -> dict[str, Any]:
            try:
                return await awaitable
            except Exception as e:  # noqa: BLE001 - surface component failure, never crash the scan
                msg = f"{type(e).__name__}: {e}"
                results["scan_errors"].append({"component": name, "error": msg})
                logger.warning("full_scan component '%s' failed for %s: %s", name, url, msg)
                return {"error": msg, "success": False}

        results["headers"] = await _safe("headers", self.analyze_headers(url, engagement_id))
        results["cors"] = await _safe("cors", self.analyze_cors(url, engagement_id))
        results["cookies"] = await _safe("cookies", self.analyze_cookies(url, engagement_id))
        results["technologies"] = await _safe("technologies", self.detect_technologies(url, engagement_id))
        body = results["headers"].get("body", "") if results["headers"].get("status_code") == 200 else ""
        results["endpoints"] = await _safe("endpoints", self.extract_endpoints(url, body, engagement_id))
        results["success"] = not results["scan_errors"]
        return results
