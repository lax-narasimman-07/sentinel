"""Forensics analysis engine — file analysis, metadata, entropy, timeline construction."""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import re
import struct
from collections import Counter
from datetime import datetime
from typing import Any

from sentinel.core.schemas import new_id, now_utc

logger = logging.getLogger("sentinel.forensics")

# ── Magic bytes database ────────────────────────────────────────────────────

MAGIC_SIGNATURES: list[tuple[str, bytes, str]] = [
    # (name, magic_bytes, description)
    ("elf", b"\x7fELF", "ELF executable"),
    ("pe_mz", b"MZ", "PE/COFF executable (MZ header)"),
    ("pe32", b"MZ\x90\x00\x03\x00", "PE32 executable"),
    ("macho_32", b"\xfe\xed\xfa\xce", "Mach-O 32-bit"),
    ("macho_64", b"\xfe\xed\xfa\xcf", "Mach-O 64-bit"),
    ("macho_32_swap", b"\xce\xfa\xed\xfe", "Mach-O 32-bit (byte swapped)"),
    ("macho_64_swap", b"\xcf\xfa\xed\xfe", "Mach-O 64-bit (byte swapped)"),
    ("pdf", b"%PDF", "PDF document"),
    ("zip", b"PK\x03\x04", "ZIP archive"),
    ("zip_central", b"PK\x01\x02", "ZIP central directory"),
    ("zip_end", b"PK\x05\x06", "ZIP end of central directory"),
    ("gzip", b"\x1f\x8b", "GZIP compressed"),
    ("bzip2", b"BZ", "BZip2 compressed"),
    ("xz", b"\xfd7zXZ\x00", "XZ compressed"),
    ("rar4", b"Rar!\x1a\x07", "RAR archive (v4)"),
    ("rar5", b"Rar!\x1a\x07\x01", "RAR archive (v5)"),
    ("7z", b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    ("tar_ustar", b"ustar", "TAR archive"),
    ("png", b"\x89PNG\r\n\x1a\n", "PNG image"),
    ("jpeg", b"\xff\xd8\xff", "JPEG image"),
    ("gif87", b"GIF87a", "GIF image (87a)"),
    ("gif89", b"GIF89a", "GIF image (89a)"),
    ("bmp", b"BM", "BMP image"),
    ("tiff_le", b"II\x2a\x00", "TIFF (little-endian)"),
    ("tiff_be", b"MM\x00\x2a", "TIFF (big-endian)"),
    ("sqlite", b"SQLite format 3", "SQLite database"),
    ("elf_core", b"\x7fELF", "ELF core dump"),
    ("python_pyc", b"\x03\xf3\r\n", "Python bytecode (PYC)"),
    ("java_class", b"\xca\xfe\xba\xbe", "Java class file"),
    ("mach_fat", b"\xca\xfe\xba\xbe", "Mach-O universal binary"),
    ("java_serial", b"\xac\xed\x00\x05", "Java serialized object"),
    ("pcap", b"\xd4\xc3\xb2\xa1", "PCAP capture (little-endian)"),
    ("pcap_be", b"\xa1\xb2\xc3\xd4", "PCAP capture (big-endian)"),
    ("pcapng", b"\x0a\x0d\x0d\x0a", "PCAP-NG capture"),
    ("iso9660", b"\x01CD001", "ISO 9660 image"),
    ("ogg", b"OggS", "Ogg container"),
    ("flac", b"fLaC", "FLAC audio"),
    ("mp3_id3", b"ID3", "MP3 audio (ID3 tag)"),
    ("mp3_sync", b"\xff\xfb", "MP3 audio"),
    ("wav", b"RIFF", "WAV audio"),
    ("avi", b"RIFF", "AVI video"),
    ("matroska", b"\x1a\x45\xdf\xa3", "Matroska/WebM"),
    ("woff", b"wOFF", "WOFF font"),
    ("woff2", b"wOF2", "WOFF2 font"),
    ("ttf", b"\x00\x01\x00\x00", "TrueType font"),
    ("otf", b"OTTO", "OpenType font"),
    ("lzip", b"LZIP", "LZip compressed"),
    ("lz4", b"\x04\x22\x4d\x18", "LZ4 compressed"),
    ("zstd", b"\x28\xb5\x2f\xfd", "Zstandard compressed"),
    ("dmg", b"\x78\x01\x73\x0d\x62\x62\x60", "Apple DMG image"),
    ("deb", b"!<arch>\n", "Debian package"),
    ("rpm", b"\xed\xab\xee\xdb", "RPM package"),
    ("appimage", b"AI\x02", "AppImage"),
    ("webp", b"RIFF", "WebP image"),
    ("avif", b"\x00\x00\x00", "AVIF image"),
]


class ForensicsEngine:
    """Digital forensics analysis engine for file and artifact analysis."""

    async def analyze_file(self, path: str) -> dict[str, Any]:
        """Perform comprehensive file analysis."""
        result: dict[str, Any] = {
            "id": new_id(),
            "timestamp": now_utc().isoformat(),
            "path": os.path.abspath(path),
            "exists": False,
        }

        if not os.path.exists(path):
            result["error"] = f"File not found: {path}"
            return result

        result["exists"] = True
        stat = os.stat(path)

        # Basic file info
        result["size"] = stat.st_size
        result["size_human"] = self._human_size(stat.st_size)
        result["permissions"] = oct(stat.st_mode)
        result["modified"] = datetime.fromtimestamp(stat.st_mtime).isoformat()
        result["created"] = datetime.fromtimestamp(stat.st_ctime).isoformat()
        result["accessed"] = datetime.fromtimestamp(stat.st_atime).isoformat()
        result["is_symlink"] = os.path.islink(path)
        result["is_dir"] = os.path.isdir(path)

        if os.path.islink(path):
            result["symlink_target"] = os.readlink(path)

        if result["is_dir"]:
            try:
                result["directory_listing"] = sorted(os.listdir(path))[:100]
                result["entry_count"] = len(os.listdir(path))
            except PermissionError:
                result["directory_listing"] = []
                result["error"] = "Permission denied"
            return result

        # Read file content for analysis
        try:
            with open(path, "rb") as f:
                data = f.read(10_000_000)  # Read up to 10MB
        except PermissionError:
            result["error"] = "Permission denied reading file"
            return result

        # Hashing
        result["hashes"] = self._compute_hashes(data)

        # File type detection
        result["file_type"] = await self.detect_file_type(data)

        # Entropy analysis
        result["entropy"] = await self.entropy_analysis(data)

        # Hex preview
        result["hex_preview"] = await self.hex_preview(data, offset=0, length=min(256, len(data)))

        # Metadata extraction
        result["metadata"] = await self.extract_metadata(path)

        # String analysis
        result["strings"] = self._extract_strings(data, min_length=4)

        # Check for common artifacts
        result["embedded_files"] = self._detect_embedded_files(data)
        result["suspicious_patterns"] = self._detect_suspicious_patterns(data)

        return result

    async def entropy_analysis(self, data: bytes) -> dict[str, Any]:
        """Analyze Shannon entropy of data, optionally in blocks."""
        if not data:
            return {
                "id": new_id(),
                "overall_entropy": 0.0,
                "block_entropies": [],
                "analysis": "empty",
            }

        overall = self._shannon_entropy(data)
        block_size = min(1024, max(256, len(data) // 10))
        block_entropies: list[dict[str, Any]] = []

        for i in range(0, len(data), block_size):
            block = data[i:i + block_size]
            ent = self._shannon_entropy(block)
            block_entropies.append({
                "offset": i,
                "size": len(block),
                "entropy": round(ent, 4),
            })

        # Classify entropy
        if overall > 7.5:
            classification = "highly_random_or_encrypted"
            description = "Data appears random or encrypted (entropy > 7.5 bits/byte)"
        elif overall > 6.5:
            classification = "compressed_or_encrypted"
            description = "Data may be compressed or encrypted"
        elif overall > 5.0:
            classification = "compressed_or_binary"
            description = "Data appears to be compressed binary data"
        elif overall > 3.5:
            classification = "text_or_mixed"
            description = "Data is likely text or mixed content"
        else:
            classification = "low_entropy"
            description = "Data has low entropy — may be simple text, repeated patterns, or sparse data"

        # Detect encryption boundaries
        encryption_boundaries: list[dict[str, Any]] = []
        if len(block_entropies) >= 2:
            prev = block_entropies[0]
            for be in block_entropies[1:]:
                delta = abs(be["entropy"] - prev["entropy"])
                if delta > 2.0:
                    encryption_boundaries.append({
                        "offset": be["offset"],
                        "entropy_before": prev["entropy"],
                        "entropy_after": be["entropy"],
                        "delta": round(delta, 4),
                    })
                prev = be

        return {
            "id": new_id(),
            "data_length": len(data),
            "overall_entropy": round(overall, 4),
            "max_possible_entropy": 8.0,
            "block_size": block_size,
            "block_entropies": block_entropies,
            "classification": classification,
            "description": description,
            "encryption_boundaries": encryption_boundaries,
        }

    async def hex_preview(self, data: bytes, offset: int = 0, length: int = 256) -> dict[str, Any]:
        """Generate a hex dump preview of data."""
        preview_data = data[offset:offset + length]
        if not preview_data:
            return {"id": new_id(), "offset": offset, "length": 0, "lines": []}

        lines: list[dict[str, Any]] = []
        bytes_per_line = 16

        for i in range(0, len(preview_data), bytes_per_line):
            chunk = preview_data[i:i + bytes_per_line]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)

            # Add spacing between groups of 8
            hex_groups = hex_part.split(" ")
            hex_formatted = " ".join(hex_groups[:8]) + "  " + " ".join(hex_groups[8:])

            lines.append({
                "offset": offset + i,
                "hex": hex_formatted,
                "ascii": ascii_part,
                "bytes": list(chunk),
            })

        return {
            "id": new_id(),
            "offset": offset,
            "length": len(preview_data),
            "total_length": len(data),
            "lines": lines,
            "truncated": offset + length > len(data),
        }

    async def detect_file_type(self, data: bytes) -> dict[str, Any]:
        """Detect file type using magic bytes and heuristics."""
        if not data:
            return {"id": new_id(), "type": "empty", "description": "Empty file"}

        matches: list[dict[str, Any]] = []

        for name, magic, description in MAGIC_SIGNATURES:
            if data[:len(magic)] == magic:
                matches.append({
                    "type": name,
                    "description": description,
                    "magic_offset": 0,
                })

        # Extended checks for ambiguous signatures
        if len(data) >= 12:
            # WebP: RIFF....WEBP
            if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
                matches = [m for m in matches if m["type"] != "wav" and m["type"] != "avi"]
                matches.insert(0, {"type": "webp", "description": "WebP image", "magic_offset": 0})

            # AVI: RIFF....AVI
            if data[:4] == b"RIFF" and data[8:12] == b"AVI ":
                matches = [m for m in matches if m["type"] != "wav"]
                matches.insert(0, {"type": "avi", "description": "AVI video", "magic_offset": 0})

            # WAV: RIFF....WAVE
            if data[:4] == b"RIFF" and data[8:12] == b"WAVE":
                matches.insert(0, {"type": "wav", "description": "WAV audio", "magic_offset": 0})

        # ELF class detection
        if data[:4] == b"\x7fELF" and len(data) >= 5:
            elf_class = data[4]
            elf_data_encoding = data[5] if len(data) > 5 else 0
            if elf_class == 1:
                for m in matches:
                    if m["type"] == "elf":
                        m["description"] = "ELF 32-bit executable"
            elif elf_class == 2:
                for m in matches:
                    if m["type"] == "elf":
                        m["description"] = "ELF 64-bit executable"

            if len(data) >= 18:
                elf_type = struct.unpack("<H", data[16:18])[0] if elf_data_encoding == 1 else struct.unpack(">H", data[16:18])[0] if len(data) >= 18 else 0
            else:
                elf_type = 0

            type_names = {0: "ET_NONE", 1: "ET_REL", 2: "ET_EXEC", 3: "ET_DYN", 4: "ET_CORE"}
            for m in matches:
                if m["type"] == "elf":
                    m["elf_type"] = type_names.get(elf_type, f"0x{elf_type:x}")
                    break

        # PE detection
        if data[:2] == b"MZ" and len(data) >= 64:
            pe_offset_bytes = data[60:64]
            if len(pe_offset_bytes) == 4:
                pe_offset = struct.unpack("<I", pe_offset_bytes)[0]
                if pe_offset + 4 <= len(data):
                    pe_sig = data[pe_offset:pe_offset + 4]
                    if pe_sig == b"PE\x00\x00":
                        # Read COFF header
                        if pe_offset + 24 <= len(data):
                            machine = struct.unpack("<H", data[pe_offset + 4:pe_offset + 6])[0]
                            machine_names = {
                                0x014c: "i386",
                                0x8664: "AMD64",
                                0x01c0: "ARM",
                                0xaa64: "ARM64",
                                0x0200: "IA64",
                            }
                            for m in matches:
                                if m["type"] == "pe_mz":
                                    m["description"] = f"PE executable ({machine_names.get(machine, f'0x{machine:x}')})"
                                    break

        return {
            "id": new_id(),
            "matches": matches,
            "primary_type": matches[0]["type"] if matches else "unknown",
            "primary_description": matches[0]["description"] if matches else "Unknown file type",
        }

    async def extract_metadata(self, path: str) -> dict[str, Any]:
        """Extract file metadata including EXIF, document properties, etc."""
        result: dict[str, Any] = {
            "id": new_id(),
            "path": path,
            "file_metadata": {},
            "exif": {},
            "document_properties": {},
            "extended_attributes": {},
        }

        if not os.path.exists(path):
            result["error"] = "File not found"
            return result

        # OS-level metadata
        try:
            stat = os.stat(path)
            result["file_metadata"] = {
                "size": stat.st_size,
                "mode": stat.st_mode,
                "uid": stat.st_uid,
                "gid": stat.st_gid,
                "inode": stat.st_ino,
                "device": stat.st_dev,
                "hard_links": stat.st_nlink,
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                "accessed": datetime.fromtimestamp(stat.st_atime).isoformat(),
            }
        except OSError as e:
            result["error"] = str(e)
            return result

        # Read file header for format-specific metadata
        try:
            with open(path, "rb") as f:
                header = f.read(65536)
        except Exception:
            return result

        # PNG metadata
        if header[:8] == b"\x89PNG\r\n\x1a\n":
            result["document_properties"]["format"] = "PNG"
            png_meta = self._parse_png_metadata(header)
            result["document_properties"]["png"] = png_meta

        # JPEG EXIF (basic)
        elif header[:2] == b"\xff\xd8":
            result["document_properties"]["format"] = "JPEG"
            result["document_properties"]["note"] = "Use exiftool for full EXIF extraction"

        # PDF metadata
        elif header[:4] == b"%PDF":
            result["document_properties"]["format"] = "PDF"
            pdf_meta = self._parse_pdf_metadata(header)
            result["document_properties"]["pdf"] = pdf_meta

        # ELF metadata
        elif header[:4] == b"\x7fELF":
            elf_meta = self._parse_elf_metadata(header)
            result["document_properties"]["format"] = "ELF"
            result["document_properties"]["elf"] = elf_meta

        # Try to get xattr
        try:
            import xattr
            xattrs = xattr.xattr(path)
            ea: dict[str, str] = {}
            for attr in xattrs:
                try:
                    ea[str(attr)] = xattrs.get(attr).decode("utf-8", errors="replace")
                except Exception:
                    pass
            result["extended_attributes"] = ea
        except (ImportError, OSError):
            pass

        return result

    async def analyze_archive(self, path: str) -> dict[str, Any]:
        """Analyze archive contents and detect archive type."""
        result: dict[str, Any] = {
            "id": new_id(),
            "timestamp": now_utc().isoformat(),
            "path": path,
            "exists": os.path.exists(path),
            "contents": [],
            "statistics": {},
        }

        if not result["exists"]:
            result["error"] = "File not found"
            return result

        try:
            with open(path, "rb") as f:
                header = f.read(16)
        except Exception as e:
            result["error"] = str(e)
            return result

        # ZIP
        if header[:4] == b"PK\x03\x04" or header[:4] == b"PK\x05\x06":
            result["archive_type"] = "zip"
            result.update(await self._analyze_zip(path))

        # GZIP
        elif header[:2] == b"\x1f\x8b":
            result["archive_type"] = "gzip"
            result.update(await self._analyze_gzip(path))

        # TAR (check for tar magic at offset 257)
        elif header[:5] == b"ustar" or (os.path.getsize(path) > 263 and self._check_tar_magic(path)):
            result["archive_type"] = "tar"
            result.update(await self._analyze_tar(path))

        # RAR
        elif header[:4] == b"Rar!":
            result["archive_type"] = "rar"
            result["note"] = "RAR analysis requires unrar or rarfile library"

        # 7z
        elif header[:6] == b"7z\xbc\xaf\x27\x1c":
            result["archive_type"] = "7z"
            result["note"] = "7z analysis requires py7zr library"

        else:
            result["archive_type"] = "unknown"
            result["note"] = "File does not match known archive signatures"

        return result

    async def build_timeline(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        """Build a consolidated timeline from multiple event sources."""
        sorted_events = sorted(events, key=lambda e: e.get("timestamp", e.get("time", "")))
        result: dict[str, Any] = {
            "id": new_id(),
            "timestamp": now_utc().isoformat(),
            "total_events": len(sorted_events),
            "events": [],
            "time_range": {},
            "categories": {},
        }

        for event in sorted_events:
            ts = event.get("timestamp", event.get("time", ""))
            category = event.get("category", "unknown")
            result["events"].append({
                "timestamp": ts,
                "category": category,
                "description": event.get("description", event.get("message", "")),
                "source": event.get("source", event.get("tool", "")),
                "severity": event.get("severity", "informational"),
                "metadata": event.get("metadata", {}),
            })

            if category not in result["categories"]:
                result["categories"][category] = 0
            result["categories"][category] += 1

        if sorted_events:
            result["time_range"] = {
                "earliest": sorted_events[0].get("timestamp", sorted_events[0].get("time", "")),
                "latest": sorted_events[-1].get("timestamp", sorted_events[-1].get("time", "")),
            }

        return result

    # ── Internal helpers ────────────────────────────────────────────────────

    def _shannon_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        counter = Counter(data)
        length = len(data)
        entropy = 0.0
        for count in counter.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return round(entropy, 4)

    def _human_size(self, size: int) -> str:
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024  # type: ignore[assignment]
        return f"{size:.1f} PB"

    def _compute_hashes(self, data: bytes) -> dict[str, str]:
        return {
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "sha512": hashlib.sha512(data).hexdigest(),
            "ssdeep": "requires ssdeep binary",
        }

    def _extract_strings(self, data: bytes, min_length: int = 4) -> dict[str, Any]:
        """Extract ASCII strings from binary data."""
        ascii_strings: list[str] = []
        unicode_strings: list[str] = []
        current_ascii: list[int] = []
        current_unicode: list[int] = []

        for i, byte in enumerate(data):
            if 32 <= byte < 127:
                current_ascii.append(byte)
            else:
                if len(current_ascii) >= min_length:
                    ascii_strings.append("".join(chr(c) for c in current_ascii))
                current_ascii = []

            # Simple UTF-16LE detection
            if byte != 0 and i + 1 < len(data) and data[i + 1] == 0 and 32 <= byte < 127:
                current_unicode.append(byte)
            else:
                if len(current_unicode) >= min_length:
                    unicode_strings.append("".join(chr(c) for c in current_unicode))
                current_unicode = []

        if len(current_ascii) >= min_length:
            ascii_strings.append("".join(chr(c) for c in current_ascii))
        if len(current_unicode) >= min_length:
            unicode_strings.append("".join(chr(c) for c in current_unicode))

        # Filter interesting strings
        interesting_patterns = [
            re.compile(r"(?:password|passwd|pwd|secret|token|key|api[_-]?key)\s*[=:]\s*\S+", re.IGNORECASE),
            re.compile(r"(?:https?://|ftp://|file://)", re.IGNORECASE),
            re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
            re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
            re.compile(r"(?:BEGIN|END)\s+(?:RSA|DSA|EC|OPENSSH)?\s*(?:PRIVATE|PUBLIC)\s+KEY"),
            re.compile(r"flag\{[^}]+\}", re.IGNORECASE),
        ]

        all_strings = ascii_strings + unicode_strings
        interesting: list[dict[str, Any]] = []
        for s in all_strings:
            for pattern in interesting_patterns:
                match = pattern.search(s)
                if match:
                    interesting.append({
                        "string": s[:200],
                        "pattern": pattern.pattern[:60],
                        "offset_hint": s[:30],
                    })
                    break

        return {
            "ascii_count": len(ascii_strings),
            "unicode_count": len(unicode_strings),
            "ascii_strings": ascii_strings[:200],
            "unicode_strings": unicode_strings[:100],
            "interesting": interesting[:50],
        }

    def _detect_embedded_files(self, data: bytes) -> list[dict[str, Any]]:
        """Detect file signatures embedded within data."""
        embedded: list[dict[str, Any]] = []
        for name, magic, description in MAGIC_SIGNATURES:
            offset = 0
            while True:
                pos = data.find(magic, offset)
                if pos == -1 or pos == 0:
                    break
                embedded.append({
                    "type": name,
                    "description": description,
                    "offset": pos,
                })
                offset = pos + 1
                if len(embedded) >= 20:
                    break
        return embedded

    def _detect_suspicious_patterns(self, data: bytes) -> list[dict[str, Any]]:
        """Detect suspicious patterns in binary data."""
        suspicious: list[dict[str, Any]] = []
        text = data.decode("utf-8", errors="replace")

        patterns: list[tuple[str, str, str]] = [
            (r"(?:cmd|powershell|bash|sh)\s+[/\-]", "command_execution", "Shell command invocation"),
            (r"(?:/etc/passwd|/etc/shadow)", "path_disclosure", "Sensitive file path reference"),
            (r"(?:http[s]?://[^\s\"']+)", "url_found", "URL found in binary"),
            (r"(?:\.\./){3,}", "path_traversal", "Directory traversal pattern"),
            (r"(?:eval|exec|system|passthru|shell_exec)\s*\(", "code_execution", "Dangerous function call"),
            (r"(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s+.*(?:FROM|INTO|TABLE)", "sql", "SQL query detected"),
            (r"(?:<script|javascript:|onerror|onload)", "xss_pattern", "XSS-related pattern"),
            (r"(?:base64_decode|base64_encode|rot13|str_rot13)", "encoding_function", "Encoding/obfuscation function"),
        ]

        for pattern, category, description in patterns:
            matches = re.findall(pattern, text[:100000], re.IGNORECASE)
            if matches:
                suspicious.append({
                    "category": category,
                    "description": description,
                    "count": len(matches),
                    "samples": [m[:100] for m in matches[:5]],
                })

        return suspicious

    def _parse_png_metadata(self, data: bytes) -> dict[str, Any]:
        """Parse basic PNG metadata from chunks."""
        result: dict[str, Any] = {"chunks": []}
        if len(data) < 8:
            return result

        offset = 8  # Skip signature
        while offset + 8 <= len(data):
            try:
                chunk_length = struct.unpack(">I", data[offset:offset + 4])[0]
                chunk_type = data[offset + 4:offset + 8].decode("ascii", errors="replace")

                result["chunks"].append({
                    "type": chunk_type,
                    "length": chunk_length,
                })

                if chunk_type == "IHDR" and offset + 12 + 13 <= len(data):
                    ihdr = data[offset + 8:offset + 21]
                    result["width"] = struct.unpack(">I", ihdr[0:4])[0]
                    result["height"] = struct.unpack(">I", ihdr[4:8])[0]
                    result["bit_depth"] = ihdr[8]
                    result["color_type"] = ihdr[9]

                if chunk_type == "tEXt" or chunk_type == "iTXt":
                    chunk_data = data[offset + 8:offset + 8 + chunk_length]
                    if b"\x00" in chunk_data:
                        key, value = chunk_data.split(b"\x00", 1)
                        result[f"metadata_{key.decode('ascii', errors='replace')}"] = value.decode("utf-8", errors="replace")

                offset += 12 + chunk_length
                if chunk_type == "IEND":
                    break
            except Exception:
                break

        return result

    def _parse_pdf_metadata(self, data: bytes) -> dict[str, Any]:
        """Parse basic PDF metadata."""
        result: dict[str, Any] = {}
        text = data.decode("latin-1", errors="replace")

        # PDF version
        version_match = re.match(r"%PDF-(\d+\.\d+)", text)
        if version_match:
            result["version"] = version_match.group(1)

        # Extract some metadata strings
        for tag in ["Title", "Author", "Subject", "Creator", "Producer", "CreationDate", "ModDate"]:
            pattern = f"/{tag}\\s*\\(([^)]+)\\)"
            match = re.search(pattern, text)
            if match:
                result[tag.lower()] = match.group(1)

        return result

    def _parse_elf_metadata(self, data: bytes) -> dict[str, Any]:
        """Parse ELF header metadata."""
        result: dict[str, Any] = {}
        if len(data) < 20:
            return result

        elf_class = data[4]
        elf_data = data[5]

        if elf_class == 1:  # 32-bit
            result["class"] = "ELF32"
            if elf_data == 1 and len(data) >= 52:  # Little-endian
                result["type"] = struct.unpack("<H", data[16:18])[0]
                result["machine"] = struct.unpack("<H", data[18:20])[0]
                result["entry_point"] = f"0x{struct.unpack('<I', data[24:28])[0]:08x}"
            elif elf_data == 2 and len(data) >= 52:  # Big-endian
                result["type"] = struct.unpack(">H", data[16:18])[0]
                result["machine"] = struct.unpack(">H", data[18:20])[0]
                result["entry_point"] = f"0x{struct.unpack('>I', data[24:28])[0]:08x}"
        elif elf_class == 2:  # 64-bit
            result["class"] = "ELF64"
            if elf_data == 1 and len(data) >= 64:
                result["type"] = struct.unpack("<H", data[16:18])[0]
                result["machine"] = struct.unpack("<H", data[18:20])[0]
                result["entry_point"] = f"0x{struct.unpack('<Q', data[24:32])[0]:016x}"
            elif elf_data == 2 and len(data) >= 64:
                result["type"] = struct.unpack(">H", data[16:18])[0]
                result["machine"] = struct.unpack(">H", data[18:20])[0]
                result["entry_point"] = f"0x{struct.unpack('>Q', data[24:32])[0]:016x}"

        type_names = {0: "ET_NONE", 1: "ET_REL", 2: "ET_EXEC", 3: "ET_DYN", 4: "ET_CORE"}
        machine_names = {
            0x03: "EM_386", 0x08: "EM_MIPS", 0x14: "EM_PPC", 0x15: "EM_PPC64",
            0x28: "EM_ARM", 0x3E: "EM_X86_64", 0xB7: "EM_AARCH64", 0xF3: "EM_RISCV",
        }
        result["type_name"] = type_names.get(result.get("type", 0), f"0x{result.get('type', 0):x}")
        result["machine_name"] = machine_names.get(result.get("machine", 0), f"0x{result.get('machine', 0):x}")

        return result

    def _check_tar_magic(self, path: str) -> bool:
        """Check for tar magic at offset 257."""
        try:
            with open(path, "rb") as f:
                f.seek(257)
                magic = f.read(6)
                return magic[:5] == b"ustar"
        except Exception:
            return False

    async def _analyze_zip(self, path: str) -> dict[str, Any]:
        """Analyze ZIP archive contents."""
        result: dict[str, Any] = {"contents": [], "statistics": {}}
        try:
            import zipfile
            with zipfile.ZipFile(path, "r") as zf:
                total_compressed = 0
                total_uncompressed = 0
                for info in zf.infolist():
                    entry = {
                        "filename": info.filename,
                        "size_uncompressed": info.file_size,
                        "size_compressed": info.compress_size,
                        "compress_type": info.compress_type,
                        "is_dir": info.is_dir(),
                        "modified": datetime(*info.date_time).isoformat() if info.date_time else "",
                        "crc32": f"{info.CRC:08x}",
                    }
                    result["contents"].append(entry)
                    total_compressed += info.compress_size
                    total_uncompressed += info.file_size

                result["statistics"] = {
                    "file_count": len([c for c in result["contents"] if not c["is_dir"]]),
                    "dir_count": len([c for c in result["contents"] if c["is_dir"]]),
                    "total_compressed": total_compressed,
                    "total_uncompressed": total_uncompressed,
                    "compression_ratio": round(1 - (total_compressed / total_uncompressed), 4) if total_uncompressed > 0 else 0,
                }
        except ImportError:
            result["error"] = "zipfile module not available"
        except Exception as e:
            result["error"] = str(e)

        return result

    async def _analyze_gzip(self, path: str) -> dict[str, Any]:
        """Analyze GZIP file."""
        result: dict[str, Any] = {"contents": [], "statistics": {}}
        try:
            import gzip
            with gzip.open(path, "rb") as f:
                data = f.read(10000)
                result["decompressed_preview"] = data[:1000].decode("utf-8", errors="replace")
                result["statistics"] = {
                    "preview_size": len(data),
                }
            stat = os.stat(path)
            result["statistics"]["compressed_size"] = stat.st_size
        except ImportError:
            result["error"] = "gzip module not available"
        except Exception as e:
            result["error"] = str(e)

        return result

    async def _analyze_tar(self, path: str) -> dict[str, Any]:
        """Analyze TAR archive contents."""
        result: dict[str, Any] = {"contents": [], "statistics": {}}
        try:
            import tarfile
            with tarfile.open(path, "r") as tf:
                total_size = 0
                for member in tf.getmembers():
                    entry = {
                        "filename": member.name,
                        "size": member.size,
                        "is_dir": member.isdir(),
                        "is_file": member.isfile(),
                        "is_link": member.issym(),
                        "mode": oct(member.mode),
                        "modified": datetime.fromtimestamp(member.mtime).isoformat() if member.mtime else "",
                        "owner": member.uname,
                    }
                    result["contents"].append(entry)
                    total_size += member.size

                result["statistics"] = {
                    "entry_count": len(result["contents"]),
                    "total_uncompressed": total_size,
                }
        except ImportError:
            result["error"] = "tarfile module not available"
        except Exception as e:
            result["error"] = str(e)

        return result
