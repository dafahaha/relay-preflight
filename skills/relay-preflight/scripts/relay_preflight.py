#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""relay-preflight — offline hygiene check for relay/aggregator API configs.

Scans local config files the user points at (``.mcp.json``, Claude
``settings.json``, ``.env``, shell snippets) and FAILs or WARNs on:

  * an inline literal ``sk-...`` key committed into a file (must use env-var
    indirection);
  * a literal ``Bearer sk-...`` in a command/args line;
  * a plaintext ``http://`` base_url carrying a relay key;
  * a key referenced by env var but no base_url declared at all.

It never reads environment variable *values*, never sends a network request,
and never prints a secret: every token in the report is masked and every URL is
reduced to scheme://host:port (userinfo/query stripped). This is hygiene only —
it does not judge whether the upstream model is genuine (that needs a separate
probe tool).

Exit codes:
    0  clean
    2  warnings
    3  failures (inline secret / bearer / http)
    1  usage / IO error
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from urllib.parse import urlparse

# sk-... literal (covers sk-ant- etc., any length after prefix); pk-live/pk-test
# secret keys; a compact JWT (eyJ header.payload.signature); Bearer token literal.
SK_RE = re.compile(r"sk-[A-Za-z0-9_\-]{6,}")
PK_RE = re.compile(r"pk-(?:live|test)-[A-Za-z0-9_\-]{6,}")
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")
BEARER_RE = re.compile(r"(?i)bearer\s+[A-Za-z0-9_\-\.]{6,}")
URL_RE = re.compile(r"https?://[^\s\"'\\,)]+")
ENV_REF_RE = re.compile(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?")
# A field name that marks an http URL as an actual endpoint (vs a doc link/example).
ENDPOINT_FIELD_RE = re.compile(r"(base_?url|api_?url|server_?url|endpoint|url)", re.IGNORECASE)


def _has_secret_context(text: str) -> bool:
    """True when the same string carries a literal secret, Bearer, or env ref."""
    return bool(
        SK_RE.search(text) or PK_RE.search(text) or JWT_RE.search(text)
        or BEARER_RE.search(text) or ENV_REF_RE.search(text)
    )

# Plaintext http on the loopback interface never leaves the machine; it is a
# WARN, not a FAIL like a public http relay URL.
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}
# 0.0.0.0 binds EVERY interface (reachable off-machine); it is not loopback and
# gets its own rule/message instead of being lumped into local-plaintext-url.
BIND_ALL_HOSTS = {"0.0.0.0"}


@dataclass
class Finding:
    file: str
    line: int
    severity: str
    rule: str
    message: str
    redacted: str


def mask_token(tok: str) -> str:
    """Mask any sk-... token: keep prefix + last 2 chars, middle stars."""
    if len(tok) <= 6:
        return "sk-***"
    return tok[:4] + "***" + tok[-2:]


def redact_url(url: str) -> str:
    """Reduce to scheme://host:port; drop userinfo, path, query, fragment."""
    try:
        parts = urlparse(url)
    except ValueError:
        return "(unparseable URL, hidden)"
    host = (parts.hostname or "").strip("[]").lower()
    netloc = host
    if parts.port:
        netloc = f"{host}:{parts.port}"
    if not netloc:
        return "(no host, hidden)"
    return f"{parts.scheme}://{netloc}"


def _host_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").strip("[]").lower()
    except ValueError:
        return ""


def _is_loopback_url(url: str) -> bool:
    return _host_of(url) in LOOPBACK_HOSTS


def _is_bind_all_url(url: str) -> bool:
    return _host_of(url) in BIND_ALL_HOSTS


def _secret_findings(value: str, file_label: str, line: int, where: str) -> list[Finding]:
    """All literal-secret patterns found in one string (sk-, pk-live/test-, JWT)."""
    out: list[Finding] = []
    for m in SK_RE.finditer(value):
        out.append(Finding(file_label, line, "FAIL", "inline-secret",
                            f"literal sk- key {where}; use an environment-variable reference",
                            mask_token(m.group(0))))
    for m in PK_RE.finditer(value):
        out.append(Finding(file_label, line, "FAIL", "inline-secret",
                           f"literal pk- secret key {where}; use an environment-variable reference",
                           mask_token(m.group(0))))
    for m in JWT_RE.finditer(value):
        out.append(Finding(file_label, line, "FAIL", "inline-secret",
                           f"literal JWT {where}; use an environment-variable reference",
                           "eyJ***"))
    return out


def _http_findings(line: str, file_label: str, lineno: int) -> tuple[list[Finding], bool]:
    """Classify http(s) URLs on one line. Returns (findings, saw_url)."""
    out: list[Finding] = []
    saw_url = False
    for m in URL_RE.finditer(line):
        saw_url = True
        url = m.group(0)
        red = redact_url(url)
        if not url.lower().startswith("http://"):
            continue
        if _is_loopback_url(url):
            out.append(Finding(
                file_label, lineno, "WARN", "local-plaintext-url",
                "http:// loopback endpoint stays on-machine; still prefer httpS for parity",
                red,
            ))
        elif _is_bind_all_url(url):
            # 0.0.0.0 binds ALL interfaces (not loopback): the listener is
            # reachable off-machine, so keep a separate rule/message.
            out.append(Finding(
                file_label, lineno, "WARN", "bind-all-plaintext-url",
                "http:// 0.0.0.0 binds every interface (not loopback); the listener "
                "is reachable off-machine — prefer https:// or bind 127.0.0.1 for local-only",
                red,
            ))
        elif ENDPOINT_FIELD_RE.search(line) or _has_secret_context(line):
            # Endpoint context: field name or a key/env ref on the same line.
            out.append(Finding(
                file_label, lineno, "FAIL", "plaintext-url",
                "http:// public base_url sends the relay key over plaintext; use https://",
                red,
            ))
        else:
            # Non-endpoint http (doc link, example) with no key context: WARN,
            # not a FAIL — it is not being used as a relay base_url.
            out.append(Finding(
                file_label, lineno, "WARN", "nonendpoint-http",
                "http:// link with no key/endpoint context; review manually, "
                "not treated as a relay base_url",
                red,
            ))
    return out, saw_url


def _scan_text_impl(text: str, file_label: str) -> tuple[list[Finding], dict]:
    out: list[Finding] = []
    flags = {"env_ref": False, "url": False}
    for lineno, line in enumerate(text.splitlines(), start=1):
        out.extend(_secret_findings(line, file_label, lineno, "in file"))
        # bearer literal
        for m in BEARER_RE.finditer(line):
            out.append(Finding(
                file_label, lineno, "FAIL", "bearer-literal",
                "literal Bearer token in a command/args line; pass it via env, never inline",
                "Bearer ***",
            ))
        findings, saw_url = _http_findings(line, file_label, lineno)
        out.extend(findings)
        flags["url"] |= saw_url
        if ENV_REF_RE.search(line):
            flags["env_ref"] = True

    if flags["env_ref"] and not flags["url"]:
        out.append(Finding(
            file_label, 0, "WARN", "no-base-url",
            "an env-var key reference exists but no base_url/endpoint was found in this file",
            "",
        ))
    return out, flags


def scan_text(text: str, file_label: str) -> list[Finding]:
    out, _ = _scan_text_impl(text, file_label)
    return out


def _walk_json_strings(node, path: str, sink: list[tuple[str, str]]) -> None:
    """Collect (dotted-path, string-value) from a parsed JSON object."""
    if isinstance(node, dict):
        for k, v in node.items():
            _walk_json_strings(v, f"{path}.{k}" if path else k, sink)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            _walk_json_strings(v, f"{path}[{i}]", sink)
    elif isinstance(node, str):
        sink.append((path, node))


def _scan_json_impl(text: str, file_label: str) -> tuple[list[Finding], dict]:
    """JSON-aware pass: attribute findings to the dotted JSON path; fall back to
    raw line scan if the file is not valid JSON."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return _scan_text_impl(text, file_label)
    sink: list[tuple[str, str]] = []
    _walk_json_strings(data, "", sink)
    out: list[Finding] = []
    flags = {"env_ref": False, "url": False}
    for path_, value in sink:
        out.extend(_secret_findings(value, file_label, 0, f"at JSON path {path_}"))
        for m in BEARER_RE.finditer(value):
            out.append(Finding(
                file_label, 0, "FAIL", "bearer-literal",
                f"literal Bearer token at JSON path {path_}; pass via env",
                "Bearer ***",
            ))
        for m in URL_RE.finditer(value):
            flags["url"] = True
            url = m.group(0)
            if url.lower().startswith("http://"):
                if _is_loopback_url(url):
                    out.append(Finding(
                        file_label, 0, "WARN", "local-plaintext-url",
                        f"http:// loopback at JSON path {path_}; stays on-machine, prefer https",
                        redact_url(url),
                    ))
                elif _is_bind_all_url(url):
                    out.append(Finding(
                        file_label, 0, "WARN", "bind-all-plaintext-url",
                        f"http:// 0.0.0.0 at JSON path {path_} binds every interface "
                        "(not loopback); reachable off-machine — prefer https or bind 127.0.0.1",
                        redact_url(url),
                    ))
                elif ENDPOINT_FIELD_RE.search(path_) or _has_secret_context(value):
                    out.append(Finding(
                        file_label, 0, "FAIL", "plaintext-url",
                        f"http:// public endpoint at JSON path {path_}; use https://",
                        redact_url(url),
                    ))
                else:
                    out.append(Finding(
                        file_label, 0, "WARN", "nonendpoint-http",
                        f"http:// link at JSON path {path_} with no key/endpoint context; "
                        "review manually, not treated as a relay base_url",
                        redact_url(url),
                    ))
        if ENV_REF_RE.search(value):
            flags["env_ref"] = True
    if flags["env_ref"] and not flags["url"]:
        out.append(Finding(
            file_label, 0, "WARN", "no-base-url",
            "an env-var key reference exists but no base_url/endpoint was found", "",
        ))
    return out, flags


def scan_json(text: str, file_label: str) -> list[Finding]:
    out, _ = _scan_json_impl(text, file_label)
    return out


def scan_file_with_flags(path: Path) -> tuple[list[Finding], dict]:
    try:
        text = path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError:
        return [Finding(str(path), 0, "WARN", "binary-skipped", "could not decode as UTF-8; skipped", "")], \
               {"env_ref": False, "url": False}
    if path.suffix.lower() in {".json", ".mcp"}:
        return _scan_json_impl(text, str(path))
    return _scan_text_impl(text, str(path))


def scan_file(path: Path) -> list[Finding]:
    out, _ = scan_file_with_flags(path)
    return out


def format_report(findings: list[Finding]) -> str:
    lines = ["# relay-preflight report", ""]
    fails = [f for f in findings if f.severity == "FAIL"]
    warns = [f for f in findings if f.severity == "WARN"]
    lines.append(f"- FAIL: {len(fails)}  WARN: {len(warns)}")
    lines.append("")
    if not findings:
        lines.append("No hygiene issues found. No secret was read or printed.")
    for f in findings:
        loc = f"L{f.line}" if f.line else "(file)"
        tail = f" | {f.redacted}" if f.redacted else ""
        lines.append(f"- [{f.severity}] {f.file} {loc} ({f.rule}): {f.message}{tail}")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Offline relay-key config hygiene check (no network, no env reads).")
    ap.add_argument("files", nargs="+", help="config files to scan (.mcp.json, settings.json, .env, ...)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--output", default=None)
    args = ap.parse_args(argv)

    all_findings: list[Finding] = []
    any_env_ref = False
    any_url = False
    try:
        for name in args.files:
            p = Path(name)
            if not p.exists():
                raise FileNotFoundError(name)
            findings, flags = scan_file_with_flags(p)
            all_findings.extend(findings)
            any_env_ref |= flags["env_ref"]
            any_url |= flags["url"]
    except (FileNotFoundError, OSError) as exc:
        print(f"relay-preflight: error: {exc}", file=sys.stderr)
        return 1

    # P3-3: aggregate across files. A key reference in A and the endpoint in B
    # must not trip a per-file no-base-url WARN; drop per-file WARNs and emit one
    # consolidated WARN only when no scanned file carries a URL.
    all_findings = [f for f in all_findings if f.rule != "no-base-url"]
    if any_env_ref and not any_url:
        all_findings.append(Finding(
            "(across files)", 0, "WARN", "no-base-url",
            "an env-var key reference exists but no base_url/endpoint was found "
            "in any scanned file", "",
        ))

    if args.json:
        rendered = json.dumps({"findings": [asdict(f) for f in all_findings]}, indent=2, ensure_ascii=False)
    else:
        rendered = format_report(all_findings)

    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)

    if any(f.severity == "FAIL" for f in all_findings):
        return 3
    if all_findings:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
