"""Safe, syntax-only normalization and parsing for HTTP(S) URLs.

This module never makes a network request and does not assess whether a URL is safe.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import SplitResult, urlsplit


def normalize_and_parse_url(value: object) -> dict:
    """Normalize surrounding whitespace and parse a complete HTTP(S) URL.

    Leading/trailing whitespace is trimmed. Embedded control characters and
    whitespace are rejected rather than silently removed or reinterpreted.
    ``port`` is the effective port (80/443 defaults included); ``explicit_port``
    is the port written in the input, if any.
    """
    result = {
        "valid": False,
        "url": value.strip() if isinstance(value, str) else "",
        "scheme": "",
        "host": "",
        "path": "",
        "port": None,
        "explicit_port": None,
        "error": "Enter a complete HTTP or HTTPS URL, such as https://example.com.",
    }
    normalized = result["url"]
    if not isinstance(value, str) or not normalized:
        result["error"] = "Enter a URL to investigate."
        return result
    if len(normalized) > 2048:
        result["error"] = "URL exceeds the 2,048-character analysis limit."
        return result

    # urlsplit() intentionally strips some controls in recent Python versions;
    # inspect the submitted normalized string first so parsing cannot hide them.
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in normalized):
        result["error"] = "URL contains an embedded control character. Remove it and try again."
        return result
    if any(ch.isspace() for ch in normalized):
        result["error"] = "URL contains embedded whitespace. Encode spaces as %20 or remove them."
        return result

    try:
        parsed = urlsplit(normalized)
        scheme = parsed.scheme.lower()
        if scheme not in ("http", "https"):
            result["error"] = "Only complete HTTP or HTTPS URLs are accepted; include https:// or http://."
            return result
        if not parsed.netloc or not parsed.hostname:
            result["error"] = "A hostname is required. Example: https://example.com."
            return result
        # Accessing .port makes urllib validate the port syntax/range.
        explicit_port = parsed.port
        host = parsed.hostname.lower().rstrip(".")
        if not host:
            result["error"] = "A valid hostname is required."
            return result
        if any(ch.isspace() or ord(ch) < 33 for ch in host):
            result["error"] = "Hostname contains invalid whitespace or control characters."
            return result

        # Validate bracketed IPv6 and reject malformed dotted-decimal IPv4.
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if re.fullmatch(r"[0-9.]+", host) and "." in host:
                result["error"] = "The numeric IP address is malformed."
                return result
            # Validate ordinary DNS labels, while allowing localhost and IDNs.
            try:
                ascii_host = host.encode("idna").decode("ascii")
            except UnicodeError:
                result["error"] = "Hostname is not valid internationalized domain syntax."
                return result
            if len(ascii_host) > 253 or any(
                not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
                or not re.fullmatch(r"[A-Za-z0-9-]+", label)
                for label in ascii_host.split(".")
            ):
                result["error"] = "Hostname format is invalid. Check the domain spelling."
                return result

        default_port = 443 if scheme == "https" else 80
        result.update({
            "valid": True,
            "url": normalized,
            "scheme": scheme,
            "host": host,
            "path": parsed.path or "/",
            "port": explicit_port if explicit_port is not None else default_port,
            "explicit_port": explicit_port,
            "error": "",
        })
        return result
    except ValueError:
        result["error"] = "URL has an invalid hostname, port, or bracket format."
        return result
