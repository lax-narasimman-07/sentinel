"""Crypto analysis engine — encoding detection, cipher analysis, cryptographic weakness detection."""

from __future__ import annotations

import base64
import binascii
import hashlib
import logging
import math
import re
from collections import Counter
from typing import Any

from sentinel.core.schemas import new_id, now_utc

logger = logging.getLogger("sentinel.crypto")

# ── Constants ───────────────────────────────────────────────────────────────

ENGLISH_FREQ = {
    "a": 0.08167, "b": 0.01492, "c": 0.02782, "d": 0.04253,
    "e": 0.12702, "f": 0.02228, "g": 0.02015, "h": 0.06094,
    "i": 0.06966, "j": 0.00153, "k": 0.00772, "l": 0.04025,
    "m": 0.02406, "n": 0.06749, "o": 0.07507, "p": 0.01929,
    "q": 0.00095, "r": 0.05987, "s": 0.06327, "t": 0.09056,
    "u": 0.02758, "v": 0.00978, "w": 0.02360, "x": 0.00150,
    "y": 0.01974, "z": 0.00074,
}

HASH_PATTERNS: dict[str, re.Pattern[str]] = {
    "md5": re.compile(r"^[a-fA-F0-9]{32}$"),
    "sha1": re.compile(r"^[a-fA-F0-9]{40}$"),
    "sha224": re.compile(r"^[a-fA-F0-9]{56}$"),
    "sha256": re.compile(r"^[a-fA-F0-9]{64}$"),
    "sha384": re.compile(r"^[a-fA-F0-9]{96}$"),
    "sha512": re.compile(r"^[a-fA-F0-9]{128}$"),
    "ntlm": re.compile(r"^[a-fA-F0-9]{32}$"),
    "mysql41": re.compile(r"^\*[a-fA-F0-9]{40}$"),
    "bcrypt": re.compile(r"^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$"),
    "argon2": re.compile(r"^\$argon2(id|i|d)\$"),
}

MAGIC_BYTES: dict[str, list[bytes]] = {
    "pdf": [b"%PDF"],
    "zip": [b"PK\x03\x04"],
    "gzip": [b"\x1f\x8b"],
    "rar": [b"Rar!\x1a\x07"],
    "7z": [b"7z\xbc\xaf\x27\x1c"],
    "png": [b"\x89PNG\r\n\x1a\n"],
    "jpeg": [b"\xff\xd8\xff"],
    "gif": [b"GIF87a", b"GIF89a"],
    "elf": [b"\x7fELF"],
    "pe": [b"MZ"],
    "macho": [b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"],
    "sqlite": [b"SQLite format 3"],
}


class CryptoEngine:
    """Cryptographic analysis engine for CTF and security research."""

    async def analyze_input(self, data: str | bytes) -> dict[str, Any]:
        """Detect encoding, hashes, and patterns in input data."""
        if isinstance(data, bytes):
            raw = data
            text = data.decode("utf-8", errors="replace")
        else:
            text = data
            raw = data.encode("utf-8")

        results: dict[str, Any] = {
            "id": new_id(),
            "timestamp": now_utc().isoformat(),
            "input_length": len(raw),
            "detected_encodings": [],
            "detected_hashes": [],
            "detected_patterns": [],
            "entropy": self._shannon_entropy(raw),
        }

        # Encoding detection
        encoding_detections = self._detect_encodings(text, raw)
        results["detected_encodings"] = encoding_detections

        # Hash detection
        hash_detections = self._detect_hashes(text.strip())
        results["detected_hashes"] = hash_detections

        # Pattern matching
        patterns = self._detect_patterns(text)
        results["detected_patterns"] = patterns

        # Hex string detection
        if self._is_hex_string(text.strip()):
            results["detected_encodings"].append({
                "type": "hex",
                "confidence": 0.95,
                "data": text.strip(),
                "decoded": self._try_hex_decode(text.strip()),
            })

        # Base64 detection
        b64_result = self._try_base64_decode(text.strip())
        if b64_result:
            results["detected_encodings"].append(b64_result)

        # URL encoding detection
        if "%" in text and re.search(r"%[0-9a-fA-F]{2}", text):
            decoded = self._try_url_decode(text)
            results["detected_encodings"].append({
                "type": "url_encoding",
                "confidence": 0.9,
                "data": text,
                "decoded": decoded,
            })

        # Unicode escape detection
        unicode_result = self._try_unicode_decode(text)
        if unicode_result:
            results["detected_encodings"].append(unicode_result)

        return results

    async def caesar_shifts(self, ciphertext: str, max_shift: int = 26) -> list[dict[str, Any]]:
        """Brute-force all Caesar shifts and score by English frequency."""
        results: list[dict[str, Any]] = []
        for shift in range(max_shift):
            decrypted = self._caesar_decrypt(ciphertext, shift)
            score = self._english_score(decrypted)
            results.append({
                "shift": shift,
                "plaintext": decrypted,
                "score": round(score, 4),
                "is_likely_english": score > 0.6,
            })
        results.sort(key=lambda r: r["score"], reverse=True)
        return results

    async def xor_single_byte(self, data: bytes) -> list[dict[str, Any]]:
        """XOR decrypt with single-byte key, return top candidates sorted by score."""
        results: list[dict[str, Any]] = []
        for key in range(256):
            decrypted = bytes(b ^ key for b in data)
            try:
                text = decrypted.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                continue
            score = self._english_score(text)
            results.append({
                "key": key,
                "key_hex": f"0x{key:02x}",
                "key_char": chr(key) if 32 <= key < 127 else "",
                "plaintext": text,
                "score": round(score, 4),
            })
        results.sort(key=lambda r: r["score"], reverse=True)
        return results[:20]

    async def xor_repeating_key(
        self, data: bytes, key_length_range: range = range(2, 41)
    ) -> dict[str, Any]:
        """Attempt to break repeating-key XOR using Hamming distance to estimate key length."""
        if not data:
            return {"id": new_id(), "error": "empty input", "candidates": []}

        # Estimate key length via Hamming distance
        scored_lengths: list[dict[str, Any]] = []
        for key_len in key_length_range:
            if key_len > len(data) // 2:
                break
            blocks = [data[i:i + key_len] for i in range(0, min(len(data), key_len * 4), key_len)]
            if len(blocks) < 2:
                continue
            distances: list[float] = []
            for i in range(len(blocks) - 1):
                d = self._hamming_distance(blocks[i], blocks[i + 1])
                distances.append(d / key_len)
            avg_dist = sum(distances) / len(distances) if distances else 999.0
            scored_lengths.append({"key_length": key_len, "normalized_distance": round(avg_dist, 4)})

        scored_lengths.sort(key=lambda x: x["normalized_distance"])

        candidates: list[dict[str, Any]] = []
        for sl in scored_lengths[:5]:
            key_len = sl["key_length"]
            key_bytes = bytearray()
            for pos in range(key_len):
                block = bytes(data[i] for i in range(pos, len(data), key_len))
                best_key = 0
                best_score = -1.0
                for k in range(256):
                    decrypted = bytes(b ^ k for b in block)
                    try:
                        text = decrypted.decode("utf-8", errors="strict")
                    except UnicodeDecodeError:
                        continue
                    score = self._english_score(text)
                    if score > best_score:
                        best_score = score
                        best_key = k
                key_bytes.append(best_key)

            key = bytes(key_bytes)
            plaintext = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
            try:
                text = plaintext.decode("utf-8", errors="replace")
            except Exception:
                text = repr(plaintext)

            candidates.append({
                "key_length": key_len,
                "key_hex": key.hex(),
                "key_ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in key),
                "plaintext_preview": text[:512],
                "normalized_distance": sl["normalized_distance"],
            })

        return {
            "id": new_id(),
            "timestamp": now_utc().isoformat(),
            "data_length": len(data),
            "estimated_key_lengths": scored_lengths[:10],
            "candidates": candidates,
        }

    async def rsa_analyze(self, n: int, e: int, c: int | None = None) -> dict[str, Any]:
        """Analyze RSA parameters and suggest potential attacks."""
        result: dict[str, Any] = {
            "id": new_id(),
            "timestamp": now_utc().isoformat(),
            "n": n,
            "e": e,
            "n_bits": n.bit_length(),
            "attacks": [],
            "suggestions": [],
        }

        if c is not None:
            result["c"] = c
            result["c_bits"] = c.bit_length()

        # Check for small e attack
        if e == 3:
            result["attacks"].append({
                "name": "small_exponent",
                "description": "e=3 is vulnerable to cube root attack if m^e < n",
                "severity": "high",
                "suggestion": "Check if cube_root(c) < n, then m = iroot(c, 3)",
            })

        if c is not None and e == 3:
            m_cubed_root = self._iroot(e, c)
            if m_cubed_root is not None and pow(m_cubed_root, e) < n:
                result["attacks"].append({
                    "name": "small_exponent_cubed",
                    "description": "m^e < n — direct cube root recovery possible",
                    "recovered_m": m_cubed_root,
                    "plaintext_hex": hex(m_cubed_root),
                })

        # Check for common modulus attack hint
        if e == 1:
            result["attacks"].append({
                "name": "trivial_exponent",
                "description": "e=1 means c = m mod n, direct recovery",
                "severity": "critical",
            })

        # Factorization hints
        factor_hints = self._factorization_hints(n)
        result["factorization_hints"] = factor_hints

        if factor_hints.get("is_prime"):
            result["attacks"].append({
                "name": "prime_modulus",
                "description": "n is prime — RSA is broken if modulus is prime",
                "severity": "critical",
            })

        if factor_hints.get("small_prime_factors"):
            result["attacks"].append({
                "name": "small_factors",
                "description": "n has small prime factors — trivial factorization",
                "factors": factor_hints["small_prime_factors"],
                "severity": "critical",
            })

        # Check for Fermat factorization
        fermat = self._fermat_factorization(n, iterations=10000)
        if fermat:
            result["attacks"].append({
                "name": "fermat_factorization",
                "description": "n factors found via Fermat's method (close primes)",
                "p": fermat[0],
                "q": fermat[1],
                "severity": "critical",
            })

        # Wiener's attack hint for small d
        if e > 1 and n.bit_length() < 2048:
            result["suggestions"].append("Try Wiener's attack if d is small (d < n^0.25)")
            result["suggestions"].append("Try Boneh-Durfee attack for slightly larger d")
            result["suggestions"].append("Check for Hastad's broadcast attack if same message encrypted with e=3 to multiple recipients")

        # Common weak primes
        if n in self._known_weak_primes():
            result["attacks"].append({
                "name": "known_weak_modulus",
                "description": "n matches a known weak RSA modulus from public databases",
                "severity": "critical",
            })

        return result

    async def analyze_hash(self, hash_str: str) -> dict[str, Any]:
        """Identify hash type and suggest potential attack approaches."""
        h = hash_str.strip()
        result: dict[str, Any] = {
            "id": new_id(),
            "timestamp": now_utc().isoformat(),
            "hash": h,
            "length": len(h),
            "detected_types": [],
            "attack_suggestions": [],
        }

        for hash_name, pattern in HASH_PATTERNS.items():
            if pattern.match(h):
                result["detected_types"].append(hash_name)

        if not result["detected_types"]:
            result["detected_types"].append("unknown")

        h_lower = h.lower()

        for ht in result["detected_types"]:
            if ht == "md5":
                result["attack_suggestions"].extend([
                    "Check online rainbow tables (cmd5.com, crackstation.net)",
                    "Try hashcat: hashcat -m 0 -a 0 hash.txt wordlist.txt",
                    "Try john: john --format=raw-md5 hash.txt",
                    "Check if unsalted — common in legacy applications",
                    "Look for MD5(MD5(x)) patterns",
                ])
            elif ht == "sha1":
                result["attack_suggestions"].extend([
                    "Check rainbow tables (crackstation.net)",
                    "Try hashcat: hashcat -m 100 -a 0 hash.txt wordlist.txt",
                    "Try john: john --format=raw-sha1 hash.txt",
                    "Note: SHA1 is collision-resistant but preimage attacks exist",
                ])
            elif ht == "sha256":
                result["attack_suggestions"].extend([
                    "Try hashcat: hashcat -m 1400 -a 0 hash.txt wordlist.txt",
                    "Brute force only feasible for short/simple passwords",
                    "Check for known salt patterns if salted",
                ])
            elif ht == "bcrypt":
                result["attack_suggestions"].extend([
                    "Extract cost factor from hash prefix",
                    "Slow hash — use wordlist attacks only",
                    "hashcat -m 3200 for bcrypt",
                ])
            elif ht == "argon2":
                result["attack_suggestions"].extend([
                    "Modern memory-hard KDF — very slow to brute force",
                    "Identify variant (argon2i/argon2d/argon2id)",
                    "Check for implementation flaws",
                ])
            elif ht == "ntlm":
                result["attack_suggestions"].extend([
                    "NTLM hashes are fast to brute force",
                    "hashcat -m 1000 -a 0 hash.txt wordlist.txt",
                    "Often found in Windows SAM database dumps",
                ])

        return result

    async def frequency_analysis(self, text: str) -> dict[str, Any]:
        """Perform letter frequency analysis on text."""
        alpha_only = re.sub(r"[^a-zA-Z]", "", text.lower())
        if not alpha_only:
            return {
                "id": new_id(),
                "timestamp": now_utc().isoformat(),
                "text_length": len(text),
                "alpha_length": 0,
                "frequencies": {},
                "chi_squared": 0.0,
                "is_english_like": False,
            }

        counter = Counter(alpha_only)
        total = len(alpha_only)
        frequencies: dict[str, float] = {}
        observed: list[float] = []
        expected: list[float] = []

        for letter in "abcdefghijklmnopqrstuvwxyz":
            count = counter.get(letter, 0)
            freq = count / total
            frequencies[letter] = round(freq, 6)
            observed.append(count)
            expected.append(ENGLISH_FREQ[letter] * total)

        chi_sq = sum(
            ((o - e) ** 2) / e if e > 0 else 0
            for o, e in zip(observed, expected)
        )

        # Index of coincidence
        ic = sum(counter[c] * (counter[c] - 1) for c in counter) / (total * (total - 1)) if total > 1 else 0.0
        english_ic = 0.0667

        return {
            "id": new_id(),
            "timestamp": now_utc().isoformat(),
            "text_length": len(text),
            "alpha_length": total,
            "frequencies": frequencies,
            "chi_squared": round(chi_sq, 4),
            "index_of_coincidence": round(ic, 6),
            "english_ic_reference": english_ic,
            "is_english_like": chi_sq < 100 and abs(ic - english_ic) < 0.03,
            "top_letters": [
                {"letter": c, "count": cnt, "frequency": round(cnt / total, 4)}
                for c, cnt in counter.most_common(5)
            ],
        }

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

    def _detect_encodings(self, text: str, raw: bytes) -> list[dict[str, Any]]:
        detections: list[dict[str, Any]] = []

        # Base64 pattern
        stripped = text.strip()
        if re.match(r"^[A-Za-z0-9+/]+=*$", stripped) and len(stripped) >= 4 and len(stripped) % 4 == 0:
            try:
                decoded = base64.b64decode(stripped, validate=True)
                if len(decoded) > 0:
                    detections.append({
                        "type": "base64",
                        "confidence": 0.85,
                        "data": stripped,
                        "decoded_length": len(decoded),
                    })
            except Exception:
                pass

        # Base64 with URL-safe alphabet
        if re.match(r"^[A-Za-z0-9_-]+=*$", stripped) and len(stripped) >= 4:
            try:
                decoded = base64.urlsafe_b64decode(stripped + "==")
                if len(decoded) > 0:
                    detections.append({
                        "type": "base64url",
                        "confidence": 0.75,
                        "data": stripped,
                        "decoded_length": len(decoded),
                    })
            except Exception:
                pass

        # Hex detection
        if re.match(r"^[0-9a-fA-F]+$", stripped) and len(stripped) >= 2 and len(stripped) % 2 == 0:
            try:
                decoded = binascii.unhexlify(stripped)
                detections.append({
                    "type": "hex",
                    "confidence": 0.8,
                    "data": stripped,
                    "decoded_length": len(decoded),
                })
            except Exception:
                pass

        return detections

    def _detect_hashes(self, text: str) -> list[dict[str, Any]]:
        detections: list[dict[str, Any]] = []
        for hash_name, pattern in HASH_PATTERNS.items():
            if pattern.match(text):
                detections.append({
                    "type": hash_name,
                    "hash": text,
                    "length": len(text),
                })
        return detections

    def _detect_patterns(self, text: str) -> list[dict[str, Any]]:
        patterns: list[dict[str, Any]] = []

        # JWT detection
        if re.match(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$", text.strip()):
            patterns.append({
                "type": "jwt",
                "description": "JSON Web Token detected",
                "confidence": 0.9,
            })

        # PEM key detection
        if "-----BEGIN" in text:
            if "RSA PRIVATE KEY" in text:
                patterns.append({"type": "pem_rsa_private_key", "confidence": 0.95})
            elif "PUBLIC KEY" in text:
                patterns.append({"type": "pem_public_key", "confidence": 0.95})
            elif "CERTIFICATE" in text:
                patterns.append({"type": "pem_certificate", "confidence": 0.95})
            elif "PRIVATE KEY" in text:
                patterns.append({"type": "pem_private_key", "confidence": 0.95})

        # UUID
        if re.match(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", text.strip()):
            patterns.append({"type": "uuid", "confidence": 0.95})

        # IPv4
        ipv4_match = re.search(r"\b(\d{1,3}\.){3}\d{1,3}\b", text)
        if ipv4_match:
            patterns.append({
                "type": "ipv4",
                "value": ipv4_match.group(),
                "confidence": 0.7,
            })

        # Hex strings with prefix
        if re.search(r"(?:0x|\\x)[0-9a-fA-F]{4,}", text):
            patterns.append({"type": "hex_encoded", "confidence": 0.8})

        # Flag pattern (CTF)
        flag_match = re.search(r"flag\{[^}]+\}", text, re.IGNORECASE)
        if flag_match:
            patterns.append({
                "type": "ctf_flag",
                "value": flag_match.group(),
                "confidence": 0.95,
            })

        # Base32
        if re.match(r"^[A-Z2-7]+=*$", text.strip()) and len(text.strip()) >= 8:
            try:
                import base64 as b64mod
                b64mod.b32decode(text.strip())
                patterns.append({"type": "base32", "confidence": 0.8})
            except Exception:
                pass

        return patterns

    def _is_hex_string(self, s: str) -> bool:
        return bool(re.fullmatch(r"[0-9a-fA-F]+", s)) and len(s) >= 2 and len(s) % 2 == 0

    def _try_hex_decode(self, s: str) -> str:
        try:
            decoded = binascii.unhexlify(s)
            return decoded.decode("utf-8", errors="replace")
        except Exception:
            return ""

    def _try_base64_decode(self, text: str) -> dict[str, Any] | None:
        stripped = text.strip()
        if not stripped or len(stripped) < 4:
            return None
        # Check if it looks like base64
        if not re.match(r"^[A-Za-z0-9+/]+=*$", stripped):
            return None
        # Pad if needed
        padding = 4 - len(stripped) % 4
        if padding != 4:
            stripped += "=" * padding
        try:
            decoded = base64.b64decode(stripped, validate=True)
            return {
                "type": "base64",
                "confidence": 0.85,
                "data": text.strip(),
                "decoded": decoded.decode("utf-8", errors="replace"),
                "decoded_bytes": decoded,
            }
        except Exception:
            return None

    def _try_url_decode(self, text: str) -> str:
        try:
            from urllib.parse import unquote
            return unquote(text)
        except Exception:
            return text

    def _try_unicode_decode(self, text: str) -> dict[str, Any] | None:
        # Detect \uXXXX sequences
        if "\\u" not in text:
            return None
        try:
            decoded = text.encode("utf-8").decode("unicode_escape")
            if decoded != text:
                return {
                    "type": "unicode_escape",
                    "confidence": 0.8,
                    "data": text,
                    "decoded": decoded,
                }
        except Exception:
            pass
        return None

    def _caesar_decrypt(self, ciphertext: str, shift: int) -> str:
        result: list[str] = []
        for ch in ciphertext:
            if ch.isalpha():
                base = ord("A") if ch.isupper() else ord("a")
                result.append(chr((ord(ch) - base - shift) % 26 + base))
            else:
                result.append(ch)
        return "".join(result)

    def _english_score(self, text: str) -> float:
        """Score how likely text is English using chi-squared against English letter frequencies."""
        alpha = [c.lower() for c in text if c.isalpha()]
        if not alpha:
            return 0.0
        total = len(alpha)
        counter = Counter(alpha)
        chi_sq = 0.0
        for letter, expected_freq in ENGLISH_FREQ.items():
            observed = counter.get(letter, 0)
            expected = expected_freq * total
            if expected > 0:
                chi_sq += ((observed - expected) ** 2) / expected
        # Convert chi-squared to a 0-1 score (lower chi-sq = more English)
        score = 1.0 / (1.0 + chi_sq / total)
        return score

    def _hamming_distance(self, a: bytes, b: bytes) -> int:
        dist = 0
        for x, y in zip(a, b):
            xor = x ^ y
            dist += bin(xor).count("1")
        return dist

    def _iroot(self, k: int, n: int) -> int | None:
        """Integer k-th root of n, returns None if not exact."""
        if n < 0:
            return None
        if n == 0:
            return 0
        # Newton's method
        x = int(round(n ** (1.0 / k)))
        # Check neighborhood
        for candidate in range(max(0, x - 2), x + 3):
            if candidate ** k == n:
                return candidate
        return None

    def _factorization_hints(self, n: int) -> dict[str, Any]:
        """Gather hints about n's factorization."""
        hints: dict[str, Any] = {
            "n_bits": n.bit_length(),
            "is_prime": False,
            "small_prime_factors": [],
            "is_power": False,
        }

        if n < 2:
            return hints

        # Trial division with small primes
        small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]
        temp = n
        for p in small_primes:
            while temp % p == 0:
                hints["small_prime_factors"].append(p)
                temp //= p
        if temp != n and not hints["small_prime_factors"]:
            pass

        # Check if n is prime (simple Fermat test for small n)
        if n < 10**12:
            hints["is_prime"] = self._is_prime_miller_rabin(n, 20)

        # Check if n is a perfect power
        for k in range(2, min(n.bit_length(), 64)):
            root = self._iroot(k, n)
            if root is not None and root > 1:
                hints["is_power"] = True
                hints["power_base"] = root
                hints["power_exponent"] = k
                break

        return hints

    def _fermat_factorization(self, n: int, iterations: int = 10000) -> tuple[int, int] | None:
        """Try Fermat factorization (works when factors are close together)."""
        if n % 2 == 0:
            return (2, n // 2)
        a = math.isqrt(n) + 1
        b2 = a * a - n
        for _ in range(iterations):
            sqrt_b2 = math.isqrt(b2)
            if sqrt_b2 * sqrt_b2 == b2:
                b = sqrt_b2
                return (a + b, a - b)
            a += 1
            b2 = a * a - n
        return None

    def _is_prime_miller_rabin(self, n: int, rounds: int = 20) -> bool:
        """Miller-Rabin primality test."""
        if n < 2:
            return False
        if n < 4:
            return True
        if n % 2 == 0:
            return False

        # Write n-1 as 2^r * d
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2

        # Witnesses
        witnesses = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
        for _ in range(rounds):
            a = witnesses[_ % len(witnesses)] if _ < len(witnesses) else pow(2, _ % (n - 3), n - 3) + 2
            if a >= n:
                continue
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    def _known_weak_primes(self) -> set[int]:
        """Return a set of known weak RSA primes (subset for demonstration)."""
        return set()
