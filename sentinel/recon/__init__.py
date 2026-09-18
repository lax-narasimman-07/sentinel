"""Recon Engine — orchestrates subdomain enumeration, probing, and asset discovery."""

from __future__ import annotations

import json
import logging
from typing import Any

from sentinel.core.schemas import ToolCapability, ToolExecutionRequest, ToolResult, ToolRiskLevel, new_id, now_utc
from sentinel.tools import ToolAdapter, ToolRegistry

logger = logging.getLogger("sentinel.recon")


class SubfinderAdapter(ToolAdapter):
    def name(self) -> str: return "subfinder"
    def version(self) -> str: return "latest"

    def capabilities(self) -> ToolCapability:
        return ToolCapability(
            id=new_id(), name="subfinder", version="latest",
            description="Passive subdomain enumeration",
            risk_level=ToolRiskLevel.PASSIVE,
            capabilities=["subdomain_enumeration", "passive_recon"],
            supported_platforms=["linux", "macos"],
            created_at=now_utc(), updated_at=now_utc(),
        )

    async def execute(self, request: ToolExecutionRequest) -> ToolResult:
        if not self._find_binary():
            return self._missing_binary_result()

        cmd = ["subfinder", "-d", request.target, "-silent", "-json"]
        cmd.extend(request.parameters.get("extra_args", []))

        stdout, stderr, rc, duration = await self._run_subprocess(
            cmd,
            timeout=request.parameters.get("timeout", 120),
            max_output_bytes=self._max_output_bytes(),
        )

        failure = self._run_failure(stdout, stderr, rc, duration)
        if failure:
            return failure

        subdomains = []
        for line in stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                subdomains.append(data.get("host", line))
            except json.JSONDecodeError:
                if "." in line:
                    subdomains.append(line)

        subdomains = sorted(set(subdomains))
        normalized = self.normalize(stdout, {"subdomains": subdomains})

        return ToolResult(
            id=new_id(), tool_name="subfinder", success=True,
            raw_output=stdout[:50000], parsed_output={"subdomains": subdomains},
            normalized_output=normalized, duration_ms=duration,
            target=request.target, created_at=now_utc(), updated_at=now_utc(),
        )

    def normalize(self, raw_output: str, parsed: dict[str, Any]) -> dict[str, Any]:
        return {"assets": [{"type": "subdomain", "value": s} for s in parsed.get("subdomains", [])]}


class HttpxAdapter(ToolAdapter):
    def name(self) -> str: return "httpx"
    def version(self) -> str: return "latest"

    def capabilities(self) -> ToolCapability:
        return ToolCapability(
            id=new_id(), name="httpx", version="latest",
            description="HTTP probing and tech detection",
            risk_level=ToolRiskLevel.PASSIVE,
            capabilities=["http_probing", "technology_detection", "web_server_detection"],
            supported_platforms=["linux", "macos"],
            created_at=now_utc(), updated_at=now_utc(),
        )

    async def execute(self, request: ToolExecutionRequest) -> ToolResult:
        if not self._find_binary():
            return self._missing_binary_result()

        targets = request.parameters.get("targets", [request.target])
        input_text = "\n".join(targets).rstrip("\n") + "\n"

        cmd = [
            "httpx", "-silent", "-json", "-title", "-tech-detect",
            "-status-code", "-content-length", "-follow-redirects",
            "-l", "/dev/stdin",
        ]
        cmd.extend(request.parameters.get("extra_args", []))

        stdout, stderr, rc, duration = await self._run_subprocess_with_input(
            cmd,
            input_data=input_text.encode("utf-8"),
            timeout=request.parameters.get("timeout", 120),
            max_output_bytes=self._max_output_bytes(),
        )

        failure = self._run_failure(stdout, stderr, rc, duration)
        if failure:
            return failure

        live_hosts = []
        for line in stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                host_info = {
                    "url": data.get("url", ""),
                    "status_code": data.get("status_code", 0),
                    "title": data.get("title", ""),
                    "technologies": data.get("tech", []),
                    "webserver": data.get("webserver", ""),
                    "content_length": data.get("content_length", 0),
                }
                live_hosts.append(host_info)
            except json.JSONDecodeError:
                if line.startswith("http"):
                    live_hosts.append({"url": line, "status_code": 0})

        normalized = self.normalize(stdout, {"live_hosts": live_hosts})

        return ToolResult(
            id=new_id(), tool_name="httpx", success=True,
            raw_output=stdout[:50000], parsed_output={"live_hosts": live_hosts},
            normalized_output=normalized, duration_ms=duration,
            target=request.target, created_at=now_utc(), updated_at=now_utc(),
        )

    def normalize(self, raw_output: str, parsed: dict[str, Any]) -> dict[str, Any]:
        assets = []
        for h in parsed.get("live_hosts", []):
            assets.append({"type": "url", "value": h.get("url", "")})
            for tech in h.get("technologies", []):
                assets.append({"type": "technology", "value": tech})
        return {"assets": assets}


class NmapAdapter(ToolAdapter):
    def name(self) -> str: return "nmap"
    def version(self) -> str: return "latest"

    def capabilities(self) -> ToolCapability:
        return ToolCapability(
            id=new_id(), name="nmap", version="latest",
            description="Network port scanning and service detection",
            risk_level=ToolRiskLevel.ACTIVE,
            capabilities=["port_scanning", "service_detection", "os_detection"],
            supported_platforms=["linux", "macos"],
            created_at=now_utc(), updated_at=now_utc(),
        )

    async def execute(self, request: ToolExecutionRequest) -> ToolResult:
        if not self._find_binary():
            return self._missing_binary_result()

        ports = request.parameters.get("ports", "1-10000")
        scan_type = request.parameters.get("scan_type", "syn")
        extra = request.parameters.get("extra_args", [])

        cmd = ["nmap"]
        if scan_type == "syn":
            cmd.append("-sS")
        elif scan_type == "udp":
            cmd.append("-sU")
        cmd.extend(["-p", ports, "-oX", "-", "--open", "-T4", request.target])
        cmd.extend(extra)

        stdout, stderr, rc, duration = await self._run_subprocess(
            cmd,
            timeout=request.parameters.get("timeout", 600),
            max_output_bytes=self._max_output_bytes(),
        )

        failure = self._run_failure(stdout, stderr, rc, duration)
        if failure:
            return failure

        services = []
        if stdout:
            services = self._parse_nmap_xml(stdout)

        normalized = self.normalize(stdout, {"services": services})

        return ToolResult(
            id=new_id(), tool_name="nmap", success=True,
            raw_output=stdout[:100000], parsed_output={"services": services},
            normalized_output=normalized, duration_ms=duration,
            target=request.target, created_at=now_utc(), updated_at=now_utc(),
        )

    def _parse_nmap_xml(self, xml_output: str) -> list[dict[str, Any]]:
        import xml.etree.ElementTree as ET
        services = []
        try:
            root = ET.fromstring(xml_output)
            for host in root.findall(".//host"):
                addr_el = host.find("address")
                addr = addr_el.get("addr", "") if addr_el is not None else ""
                for port_el in host.findall(".//port"):
                    port_id = port_el.get("portid", "")
                    protocol = port_el.get("protocol", "tcp")
                    state_el = port_el.find("state")
                    state = state_el.get("state", "") if state_el is not None else ""
                    service_el = port_el.find("service")
                    svc_name = service_el.get("name", "") if service_el is not None else ""
                    svc_version = service_el.get("version", "") if service_el is not None else ""
                    if state == "open":
                        services.append({
                            "host": addr, "port": int(port_id) if port_id.isdigit() else 0,
                            "protocol": protocol, "service": svc_name, "version": svc_version,
                            "state": state,
                        })
        except ET.ParseError:
            pass
        return services

    def normalize(self, raw_output: str, parsed: dict[str, Any]) -> dict[str, Any]:
        assets = []
        for svc in parsed.get("services", []):
            assets.append({"type": "service", "value": f"{svc['host']}:{svc['port']}/{svc['protocol']}", "metadata": svc})
        return {"assets": assets}


class FfufAdapter(ToolAdapter):
    def name(self) -> str: return "ffuf"
    def version(self) -> str: return "latest"

    def capabilities(self) -> ToolCapability:
        return ToolCapability(
            id=new_id(), name="ffuf", version="latest",
            description="Web fuzzer for directory and parameter discovery",
            risk_level=ToolRiskLevel.ACTIVE,
            capabilities=["directory_fuzzing", "parameter_fuzzing", "web_fuzzing"],
            supported_platforms=["linux", "macos"],
            created_at=now_utc(), updated_at=now_utc(),
        )

    async def execute(self, request: ToolExecutionRequest) -> ToolResult:
        if not self._find_binary():
            return self._missing_binary_result()

        url = request.target
        wordlist = request.parameters.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        mode = request.parameters.get("mode", "directory")
        extensions = request.parameters.get("extensions", "")
        filters = request.parameters.get("filters", "")

        cmd = ["ffuf", "-u", url + "/FUZZ" if mode == "directory" else url, "-w", wordlist, "-o", "/dev/stdout", "-of", "json", "-s"]
        if extensions:
            cmd.extend(["-e", extensions])
        if filters:
            cmd.extend(["-fc", filters])
        cmd.extend(request.parameters.get("extra_args", []))

        stdout, stderr, rc, duration = await self._run_subprocess(
            cmd,
            timeout=request.parameters.get("timeout", 300),
            max_output_bytes=self._max_output_bytes(),
        )

        # ffuf exits 1 when a scan completes but finds no matches — that is a
        # valid outcome, not a failure. All other nonzero codes (2 = bad usage /
        # missing wordlist, -1 = timeout) fail through the shared wrapper.
        effective_rc = 0 if rc == 1 else rc
        failure = self._run_failure(stdout, stderr, effective_rc, duration)
        if failure:
            return failure

        results = []
        if stdout:
            try:
                data = json.loads(stdout)
                results = data.get("results", [])
            except json.JSONDecodeError:
                pass

        normalized = self.normalize(stdout, {"results": results})

        return ToolResult(
            id=new_id(), tool_name="ffuf", success=True,
            raw_output=stdout[:100000], parsed_output={"results": results},
            normalized_output=normalized, duration_ms=duration,
            target=request.target, created_at=now_utc(), updated_at=now_utc(),
        )

    def normalize(self, raw_output: str, parsed: dict[str, Any]) -> dict[str, Any]:
        assets = []
        for r in parsed.get("results", []):
            url = r.get("url", "")
            if url:
                assets.append({"type": "endpoint", "value": url, "metadata": {"status": r.get("status", 0), "length": r.get("length", 0)}})
        return {"assets": assets}


class WhatWebAdapter(ToolAdapter):
    def name(self) -> str: return "whatweb"
    def version(self) -> str: return "latest"

    def capabilities(self) -> ToolCapability:
        return ToolCapability(
            id=new_id(), name="whatweb", version="latest",
            description="Technology fingerprinting",
            risk_level=ToolRiskLevel.PASSIVE,
            capabilities=["technology_detection", "web_fingerprinting"],
            supported_platforms=["linux", "macos"],
            created_at=now_utc(), updated_at=now_utc(),
        )

    async def execute(self, request: ToolExecutionRequest) -> ToolResult:
        if not self._find_binary():
            return self._missing_binary_result()

        import tempfile as _tmp
        with _tmp.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            tmp_path = tf.name
        cmd = ["whatweb", "--color=never", "-a", "3", "--log-json=" + tmp_path, request.target]
        cmd.extend(request.parameters.get("extra_args", []))
        timeout = request.parameters.get("timeout", 30)

        try:
            stdout, stderr, rc, duration = await self._run_subprocess(
                cmd,
                timeout=timeout,
                max_output_bytes=self._max_output_bytes(),
            )
            failure = self._run_failure(stdout, stderr, rc, duration)
            if failure:
                return failure
            try:
                with open(tmp_path, encoding="utf-8") as f:
                    stdout = f.read()
            except OSError as exc:
                return ToolResult(
                    id=new_id(), tool_name="whatweb", success=False,
                    error="INTERNAL: failed to read whatweb JSON output: " + str(exc),
                    duration_ms=duration, target=request.target,
                    created_at=now_utc(), updated_at=now_utc(),
                )
        except Exception as exc:
            return ToolResult(
                id=new_id(), tool_name="whatweb", success=False,
                error=f"INTERNAL: {type(exc).__name__}: {exc}",
                created_at=now_utc(), updated_at=now_utc(),
            )
        finally:
            try:
                import os as _os
                _os.unlink(tmp_path)
            except OSError:
                pass
        techniques = []
        if stdout:
            for line in stdout.strip().split("\n"):
                try:
                    data = json.loads(line)
                    plugins = data.get("plugins", {})
                    for name, info in plugins.items():
                        if name not in ("IP", "Country", "UncommonHeaders"):
                            techniques.append({"name": name, "version": info.get("version", ""), "string": info.get("string", "")})
                except json.JSONDecodeError:
                    pass

        return ToolResult(
            id=new_id(), tool_name="whatweb", success=True,
            raw_output=stdout[:50000], parsed_output={"techniques": techniques},
            normalized_output={"assets": [{"type": "technology", "value": t["name"]} for t in techniques]},
            duration_ms=duration, target=request.target,
            created_at=now_utc(), updated_at=now_utc(),
        )


class GobusterAdapter(ToolAdapter):
    def name(self) -> str: return "gobuster"
    def version(self) -> str: return "latest"

    def capabilities(self) -> ToolCapability:
        return ToolCapability(
            id=new_id(), name="gobuster", version="latest",
            description="Directory and DNS brute-force discovery",
            risk_level=ToolRiskLevel.ACTIVE,
            capabilities=["directory_discovery", "dns_bruteforce", "vhost_discovery"],
            supported_platforms=["linux", "macos"],
            created_at=now_utc(), updated_at=now_utc(),
        )

    async def execute(self, request: ToolExecutionRequest) -> ToolResult:
        if not self._find_binary():
            return self._missing_binary_result()

        timeout = request.parameters.get("timeout", 60)
        wordlist = request.parameters.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        cmd = ["gobuster", "dir", "-u", request.target, "-w", wordlist, "-q", "--no-error"]
        cmd.extend(request.parameters.get("extra_args", []))

        stdout, stderr, rc, duration = await self._run_subprocess(
            cmd,
            timeout=timeout,
            max_output_bytes=self._max_output_bytes(),
        )
        failure = self._run_failure(stdout, stderr, rc, duration)
        if failure:
            return failure

        paths = []
        for line in stdout.strip().split("\n"):
            line = line.strip()
            if line and "(Status:" in line:
                parts = line.split("(Status:")
                path = parts[0].strip()
                status = parts[1].split(")")[0].strip() if len(parts) > 1 else ""
                paths.append({"path": path, "status": int(status) if status.isdigit() else 0})

        return ToolResult(
            id=new_id(), tool_name="gobuster", success=True,
            raw_output=stdout[:50000], parsed_output={"paths": paths},
            normalized_output={"assets": [{"type": "endpoint", "value": p["path"]} for p in paths]},
            duration_ms=duration, target=request.target,
            created_at=now_utc(), updated_at=now_utc(),
        )


class KatanaAdapter(ToolAdapter):
    def name(self) -> str: return "katana"
    def version(self) -> str: return "latest"

    def capabilities(self) -> ToolCapability:
        return ToolCapability(
            id=new_id(), name="katana", version="latest",
            description="Web crawler for endpoint and JavaScript discovery",
            risk_level=ToolRiskLevel.PASSIVE,
            capabilities=["web_crawling", "endpoint_discovery", "js_discovery"],
            supported_platforms=["linux", "macos"],
            created_at=now_utc(), updated_at=now_utc(),
        )

    async def execute(self, request: ToolExecutionRequest) -> ToolResult:
        if not self._find_binary():
            return self._missing_binary_result()

        depth = request.parameters.get("depth", 2)
        timeout = request.parameters.get("timeout", 30)
        # Hard cap katana's own connection timeout so it fails fast on dead hosts
        katana_timeout = min(int(timeout * 0.8), 20)
        cmd = ["katana", "-u", request.target, "-d", str(depth), "-jc", "-silent", "-jsonl", "-timeout", str(katana_timeout)]
        cmd.extend(request.parameters.get("extra_args", []))

        stdout, stderr, rc, duration = await self._run_subprocess(
            cmd,
            timeout=timeout,
            max_output_bytes=self._max_output_bytes(),
        )
        failure = self._run_failure(stdout, stderr, rc, duration)
        if failure:
            return failure

        urls = []
        for line in stdout.strip().split("\n"):
            try:
                data = json.loads(line)
                urls.append({"url": data.get("url", line), "method": data.get("method", "GET")})
            except json.JSONDecodeError:
                if line.startswith("http"):
                    urls.append({"url": line})

        return ToolResult(
            id=new_id(), tool_name="katana", success=True,
            raw_output=stdout[:50000], parsed_output={"urls": urls},
            normalized_output={"assets": [{"type": "url", "value": u["url"]} for u in urls]},
            duration_ms=duration, target=request.target,
            created_at=now_utc(), updated_at=now_utc(),
        )


class NucleiAdapter(ToolAdapter):
    """Nuclei vulnerability scanner adapter."""
    def name(self) -> str: return "nuclei"
    def version(self) -> str: return "latest"

    def capabilities(self) -> ToolCapability:
        return ToolCapability(
            id=new_id(), name="nuclei", version="latest",
            description="Template-based vulnerability scanner",
            risk_level=ToolRiskLevel.ACTIVE,
            capabilities=["vulnerability_scanning", "template_matching", "cve_detection"],
            supported_platforms=["linux", "macos"],
            created_at=now_utc(), updated_at=now_utc(),
        )

    async def execute(self, request: ToolExecutionRequest) -> ToolResult:
        if not self._find_binary():
            return self._missing_binary_result()

        severity_filter = request.parameters.get("severity", "")
        templates = request.parameters.get("templates", "")
        timeout = request.parameters.get("timeout", 120)
        cmd = ["nuclei", "-u", request.target, "-jsonl", "-silent", "-timeout", "5"]
        if severity_filter:
            cmd.extend(["-severity", severity_filter])
        if templates:
            cmd.extend(["-t", templates])
        cmd.extend(request.parameters.get("extra_args", []))

        stdout, stderr, rc, duration = await self._run_subprocess(
            cmd,
            timeout=timeout,
            max_output_bytes=self._max_output_bytes(),
        )
        failure = self._run_failure(stdout, stderr, rc, duration)
        if failure:
            return failure

        findings: list[dict[str, Any]] = []
        for line in stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                findings.append({
                    "template_id": data.get("template-id", data.get("templateID", "")),
                    "name": data.get("info", {}).get("name", data.get("name", "")),
                    "severity": data.get("info", {}).get("severity", data.get("severity", "")),
                    "matched_at": data.get("matched-at", data.get("matched", "")),
                    "type": data.get("type", ""),
                    "matcher_name": data.get("matcher-name", ""),
                    "curl_command": data.get("curl-command", ""),
                })
            except json.JSONDecodeError:
                if "[critical]" in line.lower() or "[high]" in line.lower() or "[medium]" in line.lower():
                    findings.append({"raw": line})

        severity_counts: dict[str, int] = {}
        for f in findings:
            sev = f.get("severity", "unknown")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        normalized = self.normalize(stdout, {"findings": findings})

        return ToolResult(
            id=new_id(), tool_name="nuclei", success=True,
            raw_output=stdout[:100000], parsed_output={"findings": findings, "severity_counts": severity_counts},
            normalized_output=normalized, duration_ms=duration,
            target=request.target, created_at=now_utc(), updated_at=now_utc(),
        )

    def normalize(self, raw_output: str, parsed: dict[str, Any]) -> dict[str, Any]:
        assets = []
        for f in parsed.get("findings", []):
            if f.get("matched_at"):
                assets.append({"type": "finding", "value": f["matched_at"], "metadata": f})
        return {"assets": assets}


class NiktoAdapter(ToolAdapter):
    """Nikto web server scanner adapter."""
    def name(self) -> str: return "nikto"
    def version(self) -> str: return "latest"

    def capabilities(self) -> ToolCapability:
        return ToolCapability(
            id=new_id(), name="nikto", version="latest",
            description="Web server vulnerability scanner",
            risk_level=ToolRiskLevel.ACTIVE,
            capabilities=["web_vulnerability_scanning", "misconfiguration_detection"],
            supported_platforms=["linux", "macos"],
            created_at=now_utc(), updated_at=now_utc(),
        )

    async def execute(self, request: ToolExecutionRequest) -> ToolResult:
        if not self._find_binary():
            return self._missing_binary_result()

        timeout = request.parameters.get("timeout", 120)
        cmd = ["nikto", "-h", request.target, "-Format", "json", "-output", "/dev/stdout"]
        cmd.extend(request.parameters.get("extra_args", []))

        stdout, stderr, rc, duration = await self._run_subprocess(
            cmd,
            timeout=timeout,
            max_output_bytes=self._max_output_bytes(),
        )
        failure = self._run_failure(stdout, stderr, rc, duration)
        if failure:
            return failure

        vulns: list[dict[str, Any]] = []
        server_info: dict[str, str] = {}

        # Parse nikto output
        for line in stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            # Nikto output lines typically have OSVDB or description
            if "OSVDB" in line or "CVE" in line:
                vulns.append({"finding": line, "source": "nikto"})
            elif line.startswith("+ ") or line.startswith("[-]"):
                vulns.append({"info": line})
            # Server header detection
            if "Server:" in line:
                parts = line.split("Server:", 1)
                if len(parts) > 1:
                    server_info["server"] = parts[1].strip()

        normalized = self.normalize(stdout, {"vulnerabilities": vulns, "server_info": server_info})

        return ToolResult(
            id=new_id(), tool_name="nikto", success=True,
            raw_output=stdout[:100000], parsed_output={"vulnerabilities": vulns, "server_info": server_info},
            normalized_output=normalized, duration_ms=duration,
            target=request.target, created_at=now_utc(), updated_at=now_utc(),
        )

    def normalize(self, raw_output: str, parsed: dict[str, Any]) -> dict[str, Any]:
        assets = []
        for v in parsed.get("vulnerabilities", []):
            assets.append({"type": "finding", "value": v.get("finding", v.get("info", ""))})
        return {"assets": assets}


class NaabuAdapter(ToolAdapter):
    """Naabu port scanner adapter."""
    def name(self) -> str: return "naabu"
    def version(self) -> str: return "latest"

    def capabilities(self) -> ToolCapability:
        return ToolCapability(
            id=new_id(), name="naabu", version="latest",
            description="Fast SYN port scanner",
            risk_level=ToolRiskLevel.ACTIVE,
            capabilities=["port_scanning", "service_discovery"],
            supported_platforms=["linux", "macos"],
            created_at=now_utc(), updated_at=now_utc(),
        )

    async def execute(self, request: ToolExecutionRequest) -> ToolResult:
        if not self._find_binary():
            return self._missing_binary_result()

        ports = request.parameters.get("ports", "")
        cmd = ["naabu", "-host", request.target, "-json", "-silent"]
        if ports:
            cmd.extend(["-p", ports])
        cmd.extend(request.parameters.get("extra_args", []))

        stdout, stderr, rc, duration = await self._run_subprocess(
            cmd,
            timeout=request.parameters.get("timeout", 300),
            max_output_bytes=self._max_output_bytes(),
        )
        failure = self._run_failure(stdout, stderr, rc, duration)
        if failure:
            return failure

        open_ports: list[dict[str, Any]] = []
        for line in stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                open_ports.append({
                    "host": data.get("ip", data.get("host", request.target)),
                    "port": data.get("port", 0),
                    "protocol": data.get("protocol", "tcp"),
                })
            except json.JSONDecodeError:
                parts = line.split(":")
                if len(parts) == 2 and parts[1].strip().isdigit():
                    open_ports.append({
                        "host": parts[0].strip() or request.target,
                        "port": int(parts[1].strip()),
                        "protocol": "tcp",
                    })

        normalized = self.normalize(stdout, {"open_ports": open_ports})

        return ToolResult(
            id=new_id(), tool_name="naabu", success=True,
            raw_output=stdout[:50000], parsed_output={"open_ports": open_ports},
            normalized_output=normalized, duration_ms=duration,
            target=request.target, created_at=now_utc(), updated_at=now_utc(),
        )

    def normalize(self, raw_output: str, parsed: dict[str, Any]) -> dict[str, Any]:
        assets = []
        for p in parsed.get("open_ports", []):
            assets.append({"type": "port", "value": f"{p['host']}:{p['port']}/{p.get('protocol', 'tcp')}"})
        return {"assets": assets}


class WafW00fAdapter(ToolAdapter):
    """WAFW00F WAF detection adapter."""
    def name(self) -> str: return "wafw00f"
    def version(self) -> str: return "latest"

    def capabilities(self) -> ToolCapability:
        return ToolCapability(
            id=new_id(), name="wafw00f", version="latest",
            description="Web Application Firewall detection",
            risk_level=ToolRiskLevel.PASSIVE,
            capabilities=["waf_detection", "firewall_fingerprinting"],
            supported_platforms=["linux", "macos"],
            created_at=now_utc(), updated_at=now_utc(),
        )

    async def execute(self, request: ToolExecutionRequest) -> ToolResult:
        if not self._find_binary():
            return self._missing_binary_result()

        cmd = ["wafw00f", request.target, "-o", "/dev/stdout", "-f", "json", "-a"]
        cmd.extend(request.parameters.get("extra_args", []))

        stdout, stderr, rc, duration = await self._run_subprocess(
            cmd,
            timeout=request.parameters.get("timeout", 120),
            max_output_bytes=self._max_output_bytes(),
        )
        failure = self._run_failure(stdout, stderr, rc, duration)
        if failure:
            return failure

        waf_info: list[dict[str, Any]] = []
        firewalls: list[str] = []

        # Parse wafw00f JSON output
        try:
            data = json.loads(stdout)
            if isinstance(data, list):
                for entry in data:
                    firewall = entry.get("firewall", entry.get("manufacturer", ""))
                    if firewall:
                        firewalls.append(firewall)
                        waf_info.append({
                            "firewall": firewall,
                            "manufacturer": entry.get("manufacturer", ""),
                            "url": entry.get("url", ""),
                        })
        except json.JSONDecodeError:
            # Fallback: parse text output
            for line in stdout.strip().split("\n"):
                if "is behind" in line.lower():
                    parts = line.split("is behind", 1)
                    if len(parts) > 1:
                        fw = parts[1].strip().rstrip(".")
                        firewalls.append(fw)
                        waf_info.append({"firewall": fw})
                elif "No WAF" in line:
                    waf_info.append({"firewall": "None detected", "status": "no_waf_found"})

        has_waf = len(firewalls) > 0 and firewalls[0] != "None detected"

        normalized = self.normalize(stdout, {"waf_detected": has_waf, "firewalls": firewalls, "waf_info": waf_info})

        return ToolResult(
            id=new_id(), tool_name="wafw00f", success=True,
            raw_output=stdout[:50000], parsed_output={"waf_detected": has_waf, "firewalls": firewalls, "waf_info": waf_info},
            normalized_output=normalized, duration_ms=duration,
            target=request.target, created_at=now_utc(), updated_at=now_utc(),
        )

    def normalize(self, raw_output: str, parsed: dict[str, Any]) -> dict[str, Any]:
        assets = []
        for fw in parsed.get("firewalls", []):
            if fw and fw != "None detected":
                assets.append({"type": "technology", "value": fw, "metadata": {"type": "waf"}})
        return {"assets": assets}


class GospiderAdapter(ToolAdapter):
    """Gospider web crawler adapter."""
    def name(self) -> str: return "gospider"
    def version(self) -> str: return "latest"

    def capabilities(self) -> ToolCapability:
        return ToolCapability(
            id=new_id(), name="gospider", version="latest",
            description="Fast web crawler for endpoint and link discovery",
            risk_level=ToolRiskLevel.PASSIVE,
            capabilities=["web_crawling", "endpoint_discovery", "link_discovery"],
            supported_platforms=["linux", "macos"],
            created_at=now_utc(), updated_at=now_utc(),
        )

    async def execute(self, request: ToolExecutionRequest) -> ToolResult:
        if not self._find_binary():
            return self._missing_binary_result()

        depth = request.parameters.get("depth", 2)
        cmd = ["gospider", "-s", request.target, "-d", str(depth), "--json", "-c", "10", "-t", "10"]
        cmd.extend(request.parameters.get("extra_args", []))

        stdout, stderr, rc, duration = await self._run_subprocess(
            cmd,
            timeout=request.parameters.get("timeout", 300),
            max_output_bytes=self._max_output_bytes(),
        )
        failure = self._run_failure(stdout, stderr, rc, duration)
        if failure:
            return failure

        urls: list[dict[str, Any]] = []
        js_urls: list[str] = []
        forms: list[dict[str, Any]] = []

        for line in stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                link = data.get("link", "")
                if link:
                    urls.append({
                        "url": link,
                        "source": data.get("source", ""),
                        "tag": data.get("tag", ""),
                    })
            except json.JSONDecodeError:
                if line.startswith("http"):
                    urls.append({"url": line})

        # Deduplicate
        seen_urls: set[str] = set()
        unique_urls: list[dict[str, Any]] = []
        for u in urls:
            if u["url"] not in seen_urls:
                seen_urls.add(u["url"])
                unique_urls.append(u)

        normalized = self.normalize(stdout, {"urls": unique_urls, "js_urls": js_urls, "forms": forms})

        return ToolResult(
            id=new_id(), tool_name="gospider", success=True,
            raw_output=stdout[:100000], parsed_output={"urls": unique_urls, "js_urls": js_urls, "forms": forms},
            normalized_output=normalized, duration_ms=duration,
            target=request.target, created_at=now_utc(), updated_at=now_utc(),
        )

    def normalize(self, raw_output: str, parsed: dict[str, Any]) -> dict[str, Any]:
        assets = []
        for u in parsed.get("urls", []):
            assets.append({"type": "url", "value": u.get("url", "")})
        for js in parsed.get("js_urls", []):
            assets.append({"type": "javascript", "value": js})
        return {"assets": assets}


class DnsxAdapter(ToolAdapter):
    """DNSx DNS toolkit adapter."""
    def name(self) -> str: return "dnsx"
    def version(self) -> str: return "latest"

    def capabilities(self) -> ToolCapability:
        return ToolCapability(
            id=new_id(), name="dnsx", version="latest",
            description="DNS toolkit for resolution, enumeration, and brute-forcing",
            risk_level=ToolRiskLevel.PASSIVE,
            capabilities=["dns_resolution", "dns_enumeration", "dns_bruteforce"],
            supported_platforms=["linux", "macos"],
            created_at=now_utc(), updated_at=now_utc(),
        )

    async def execute(self, request: ToolExecutionRequest) -> ToolResult:
        if not self._find_binary():
            return self._missing_binary_result()

        mode = request.parameters.get("mode", "resolve")
        cmd = ["dnsx", "-json", "-silent"]

        if mode == "resolve":
            cmd.extend(["-l", "/dev/stdin"])
        elif mode == "brute":
            wordlist = request.parameters.get("wordlist", "/usr/share/wordlists/dnsbest.txt")
            cmd.extend(["-d", request.target, "-w", wordlist, "-retry", "3"])
        elif mode == "recon":
            cmd.extend(["-recon", "-d", request.target])

        cmd.extend(request.parameters.get("extra_args", []))

        # For resolve mode, pipe the target via stdin
        input_data = None
        if mode == "resolve":
            input_data = request.target.encode()

        stdout, stderr, rc, duration = await self._run_subprocess_with_input(
            cmd,
            input_data=input_data,
            timeout=request.parameters.get("timeout", 120),
            max_output_bytes=self._max_output_bytes(),
        )
        failure = self._run_failure(stdout, stderr, rc, duration)
        if failure:
            return failure

        dns_records: list[dict[str, Any]] = []
        for line in stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                dns_records.append({
                    "host": data.get("host", ""),
                    "ip": data.get("ip", data.get("a", [])),
                    "cname": data.get("cname", []),
                    "mx": data.get("mx", []),
                    "ns": data.get("ns", []),
                    "txt": data.get("txt", []),
                    "aaaa": data.get("aaaa", []),
                })
            except json.JSONDecodeError:
                # Simple A record line
                parts = line.split()
                if len(parts) >= 1:
                    dns_records.append({"host": parts[0], "ip": parts[1] if len(parts) > 1 else ""})

        normalized = self.normalize(stdout, {"records": dns_records})

        return ToolResult(
            id=new_id(), tool_name="dnsx", success=True,
            raw_output=stdout[:100000], parsed_output={"records": dns_records},
            normalized_output=normalized, duration_ms=duration,
            target=request.target, created_at=now_utc(), updated_at=now_utc(),
        )

    def normalize(self, raw_output: str, parsed: dict[str, Any]) -> dict[str, Any]:
        assets = []
        for r in parsed.get("records", []):
            host = r.get("host", "")
            if host:
                assets.append({"type": "subdomain", "value": host})
            for ip in (r.get("ip") if isinstance(r.get("ip"), list) else [r.get("ip", "")]):
                if ip:
                    assets.append({"type": "ip", "value": str(ip)})
        return {"assets": assets}


class MasscanAdapter(ToolAdapter):
    """Masscan fast port scanner adapter."""
    def name(self) -> str: return "masscan"
    def version(self) -> str: return "latest"

    def capabilities(self) -> ToolCapability:
        return ToolCapability(
            id=new_id(), name="masscan", version="latest",
            description="Internet-scale fast port scanner",
            risk_level=ToolRiskLevel.ACTIVE,
            capabilities=["port_scanning", "banner_grabbing", "internet_scale_scan"],
            supported_platforms=["linux", "macos"],
            created_at=now_utc(), updated_at=now_utc(),
        )

    async def execute(self, request: ToolExecutionRequest) -> ToolResult:
        if not self._find_binary():
            return self._missing_binary_result()

        ports = request.parameters.get("ports", "1-65535")
        rate = request.parameters.get("rate", "1000")
        cmd = [
            "masscan", request.target,
            "-p", ports,
            "--rate", str(rate),
            "--wait", "3",
            "-oJ", "/dev/stdout",
        ]
        cmd.extend(request.parameters.get("extra_args", []))

        stdout, stderr, rc, duration = await self._run_subprocess(
            cmd,
            timeout=request.parameters.get("timeout", 600),
            max_output_bytes=self._max_output_bytes(),
        )
        failure = self._run_failure(stdout, stderr, rc, duration)
        if failure:
            return failure

        open_ports: list[dict[str, Any]] = []
        # Masscan JSON output has trailing comma issues, fix them
        cleaned = stdout.strip().rstrip(",").strip()
        if cleaned:
            # Wrap in array if needed
            if not cleaned.startswith("["):
                cleaned = "[" + cleaned + "]"
            try:
                data = json.loads(cleaned)
                for entry in data:
                    ip = entry.get("ip", "")
                    ports_list = entry.get("ports", [])
                    for p in ports_list:
                        open_ports.append({
                            "host": ip,
                            "port": p.get("port", 0),
                            "proto": p.get("proto", "tcp"),
                            "status": p.get("status", "open"),
                            "service": p.get("service", {}).get("name", ""),
                            "banner": p.get("service", {}).get("banner", ""),
                        })
            except json.JSONDecodeError:
                # Fallback: try line-by-line
                for line in cleaned.split("\n"):
                    try:
                        entry = json.loads(line.strip().rstrip(","))
                        if isinstance(entry, dict) and "ip" in entry:
                            for p in entry.get("ports", []):
                                open_ports.append({
                                    "host": entry.get("ip", ""),
                                    "port": p.get("port", 0),
                                    "proto": p.get("proto", "tcp"),
                                    "status": p.get("status", "open"),
                                })
                    except json.JSONDecodeError:
                        continue

        normalized = self.normalize(stdout, {"open_ports": open_ports})

        return ToolResult(
            id=new_id(), tool_name="masscan", success=True,
            raw_output=stdout[:100000], parsed_output={"open_ports": open_ports},
            normalized_output=normalized, duration_ms=duration,
            target=request.target, created_at=now_utc(), updated_at=now_utc(),
        )

    def normalize(self, raw_output: str, parsed: dict[str, Any]) -> dict[str, Any]:
        assets = []
        for p in parsed.get("open_ports", []):
            assets.append({
                "type": "port",
                "value": f"{p.get('host', '')}:{p.get('port', 0)}/{p.get('proto', 'tcp')}",
                "metadata": {
                    "service": p.get("service", ""),
                    "banner": p.get("banner", ""),
                },
            })
        return {"assets": assets}


def register_all_recon_adapters(registry: ToolRegistry) -> None:
    """Register all recon tool adapters."""
    for adapter_cls in [
        SubfinderAdapter, HttpxAdapter, NmapAdapter, FfufAdapter,
        WhatWebAdapter, GobusterAdapter, KatanaAdapter,
        NucleiAdapter, NiktoAdapter, NaabuAdapter, WafW00fAdapter,
        GospiderAdapter, DnsxAdapter, MasscanAdapter,
    ]:
        registry.register(adapter_cls())
