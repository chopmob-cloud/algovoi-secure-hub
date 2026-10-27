"""AlgoVoi Secure Hub — WAF (Web Application Firewall) middleware.

Stateless request inspection that runs after the Edge layer and before the
authentication gate. Scans:

  * URL path and query string (every request)
  * JSON / text request body (POST, PUT, PATCH only, up to AHUB_WAF_MAX_BODY)

Rule catalogue:
  sqli-*   SQL injection (UNION SELECT, stacked queries, Boolean probes)
  xss-*    Cross-site scripting (script tags, event handlers, javascript: URIs)
  cmdi-*   OS command injection (shell metacharacters, command substitution)
  pt-*     Path traversal (.. sequences, percent-encoded variants)
  ssrf-*   SSRF helpers (cloud metadata endpoints, loopback in body)
  pi-*     Prompt injection (ignore-prior-instructions, [SYSTEM] tags, LLM jailbreaks)

Enable with AHUB_WAF_ENABLED=1.  The WAF is disabled by default so existing
deployments are unaffected.

Stats are exposed via the admin-gated GET /v1/waf/stats endpoint in service.py.
"""
from __future__ import annotations

import os
import re
from collections import defaultdict
from typing import Any

WAF_ENABLED: bool = os.environ.get("AHUB_WAF_ENABLED", "").strip().lower() not in (
    "", "0", "false", "no"
)
_MAX_BODY: int = int(os.environ.get("AHUB_WAF_MAX_BODY", str(1 * 1024 * 1024)))

# ── Pattern catalogue ─────────────────────────────────────────────────────────
# Each entry: (rule_id, description, compiled_pattern)
_RULES: list[tuple[str, str, re.Pattern]] = []


def _r(rule_id: str, desc: str, pattern: str) -> None:
    _RULES.append((rule_id, desc, re.compile(pattern, re.IGNORECASE | re.DOTALL)))


# SQL injection
_r("sqli-01", "UNION SELECT probe", r"union\s+(?:all\s+)?select\b")
_r("sqli-02", "SQL comment + DML keyword", r"(?:--|#|/\*|\*/)\s*(?:select|insert|update|delete|drop|truncate|alter|create)\b")
_r("sqli-03", "Stacked query semicolon", r";\s*(?:select|insert|update|delete|drop|truncate|alter|create)\b")
_r("sqli-04", "Boolean injection literals", r"\b(?:1\s*=\s*1|'[^']{0,20}'\s*or\s+'[^']{0,20}'\s*=\s*'[^']{0,20}'|or\s+1\s*=\s*1)\b")

# XSS
_r("xss-01", "Script tag", r"<\s*script\b")
_r("xss-02", "Inline JS event handler", r"\bon(?:load|error|click|mouseover|focus|blur|input|change|submit)\s*=")
_r("xss-03", "javascript: URI scheme", r"javascript\s*:")
_r("xss-04", "data: text/html URI", r"data\s*:\s*text/html")

# Command injection
_r("cmdi-01", "Shell pipe/chain + known binary", r"(?:;|\|{1,2}|&&)\s*(?:cat|ls|id|pwd|whoami|wget|curl|bash|sh|python3?|perl|nc|ncat)\b")
_r("cmdi-02", "Backtick command substitution", r"`[^`]{1,200}`")
_r("cmdi-03", "$(…) command substitution", r"\$\([^)]{1,200}\)")

# Path traversal
_r("pt-01", "Directory traversal (../ sequences)", r"(?:\.\./|\.\.\\){2,}")
_r("pt-02", "Percent-encoded traversal", r"%2e%2e[%/\\]")

# SSRF (supplement schema-level guard in schemas.py / service.py)
_r("ssrf-01", "Cloud metadata IP / hostname", r"169\.254\.169\.254|fd00:ec2::254|metadata\.google")
_r("ssrf-02", "Loopback URL in request body", r'"(?:https?://(?:localhost|127\.0\.0\.1|::1))[:/"]')

# Prompt injection
_r("pi-01", "ignore-prior-instructions pattern", r"ignore\s+(?:all\s+)?(?:prior|previous|above)\s+instructions?")
_r("pi-02", "[SYSTEM] tag injection", r"\[SYSTEM\]")
_r("pi-03", "XML instruction tag injection", r"<(?:instruction|system|prompt|context)\b")
_r("pi-04", "LLM jailbreak phrases", r"(?:\bdan\b|do\s+anything\s+now|disregard\s+your\s+guidelines?|you\s+are\s+now\s+(?:a\s+)?(?:evil|unrestricted|jailbroken))\b")

# ── Stats ─────────────────────────────────────────────────────────────────────
_STATS: dict[str, int] = defaultdict(int)


def waf_stats() -> dict[str, Any]:
    """Return WAF state snapshot for GET /v1/waf/stats."""
    return {
        "enabled": WAF_ENABLED,
        "rule_count": len(_RULES),
        "max_body_bytes": _MAX_BODY,
        "rules": [{"id": rid, "desc": desc} for rid, desc, _ in _RULES],
        "counters": dict(_STATS),
    }


def _first_hit(text: str) -> tuple[str, str] | None:
    """Return (rule_id, description) for the first pattern match, or None."""
    for rule_id, desc, pattern in _RULES:
        if pattern.search(text):
            return rule_id, desc
    return None


async def waf_middleware(request, call_next):
    """ASGI middleware: scan path+query then (optionally) body for attack signatures."""
    if not WAF_ENABLED:
        return await call_next(request)

    # 1. Path and query — always inspected, zero extra I/O
    target = request.url.path
    if request.url.query:
        target = target + "?" + request.url.query

    hit = _first_hit(target)
    if hit:
        _STATS["blocked_path"] += 1
        _STATS[f"rule_{hit[0]}"] += 1
        from starlette.responses import Response
        return Response(status_code=400, content="request blocked by WAF")

    # 2. Request body — JSON / text POST|PUT|PATCH only, bounded to _MAX_BODY
    if request.method.upper() in ("POST", "PUT", "PATCH"):
        ct = request.headers.get("content-type", "").lower()
        if "application/json" in ct or ct.startswith("text/"):
            body_bytes = await request.body()
            if len(body_bytes) > _MAX_BODY:
                _STATS["blocked_oversized"] += 1
                from starlette.responses import Response
                return Response(status_code=413, content="request body exceeds WAF limit")
            body_text = body_bytes.decode("utf-8", errors="replace")
            hit = _first_hit(body_text)
            if hit:
                _STATS["blocked_body"] += 1
                _STATS[f"rule_{hit[0]}"] += 1
                from starlette.responses import Response
                return Response(status_code=400, content="request blocked by WAF")

    _STATS["allowed"] += 1
    return await call_next(request)
