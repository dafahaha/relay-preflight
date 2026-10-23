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
import ipaddress
import json
import re
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from urllib.parse import urlparse

# sk-... literal (covers sk-ant- etc.); pk-live/pk-test secret keys; a compact
# JWT (eyJ header.payload.signature); Bearer token literal. The negative
# lookbehind keeps `sk-`/`pk-` from matching inside ordinary words (desk-, risk-).
SK_RE = re.compile(r"(?<![A-Za-z0-9])sk-[A-Za-z0-9_\-]{6,}")
PK_RE = re.compile(r"(?<![A-Za-z0-9])pk-(?:live|test)-[A-Za-z0-9_\-]{6,}")
# JWTs are base64url by spec, but some implementations emit standard base64
# (with +, /) and trailing '=' padding; accept both.
JWT_RE = re.compile(
    r"eyJ[A-Za-z0-9_\-+/=]{8,}\.[A-Za-z0-9_\-+/=]+\.[A-Za-z0-9_\-+/=]+"
)
# A real Bearer credential is a long token; prose ("Bearer authentication",
# "Bearer token/scheme/header") must not match. Common prose words are also
# filtered explicitly (see _BEARER_PROSE_WORDS).
BEARER_RE = re.compile(r"(?i)bearer\s+[\"']?([A-Za-z0-9_\-\.]{8,})")
_BEARER_PROSE_WORDS = {
    "authentication", "authorization", "token", "tokens", "scheme", "header",
    "headers", "credentials", "credential", "required", "flow", "example",
    "examples",
}
URL_RE = re.compile(r"https?://[^\s\"'\\,)]+")
# Credentials embedded inline in a URL's userinfo: scheme://user:pass@host.
# The password segment may be empty ("user:@host"); the username is required.
URL_USERINFO_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s@]+:[^/\s@]*@")
# Env-var references: ${VAR} (paired braces, optionally with a shell
# default-value expansion such as ${VAR:-default} or the POSIX ${VAR=default})
# or $VAR (word boundary).
ENV_REF_RE = re.compile(
    r"\$\{[A-Za-z_][A-Za-z0-9_]*(?:(?::[-=?+]|=)[^}]*)?\}"
    r"|\$[A-Za-z_][A-Za-z0-9_]*\b"
)
# Exact key words (matched per variable-name word, not as a substring), so
# AUTHORITY/COMPASS/CREDIT are not misread as key names.
KEY_WORDS = {
    "key", "token", "secret", "auth", "password", "credential", "credentials",
}
# A field name that marks an http URL as an actual endpoint. Used on JSON key
# paths (clean) and, for text, only in an explicit assignment form (see
# TEXT_ENDPOINT_ASSIGN_RE) so prose "configure the endpoint at http://..." does
# not upgrade a documentation link.
ENDPOINT_FIELD_RE = re.compile(
    r"(?:^|[\s\"'\-.,:}])(?:base[_-]?url|api[_-]?url|server[_-]?url|endpoint)\b",
    re.IGNORECASE,
)
# Text configs: an endpoint field assigned a URL on the same line.
TEXT_ENDPOINT_ASSIGN_RE = re.compile(
    r"(?:base[_-]?url|api[_-]?url|server[_-]?url|endpoint)\s*[:=]\s*[\"']?https?://",
    re.IGNORECASE,
)
# Text configs: a key-named assignment left-value, e.g. RELAY_API_KEY=xyz.
ASSIGN_LEFT_RE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9_]*)\s*[:=]")
# A trailing key word even when concatenated without a separator (apikey).
_CONCAT_KEY_RE = re.compile(r"(key|secret|token|password|credential|credentials)$")


def _var_words(name: str) -> list[str]:
    """Split a variable/field name into lowercase words on '_', '-', camelCase
    boundaries, and a trailing concatenated key word (e.g. 'apikey' ->
    ['api','key'])."""
    words: list[str] = []
    for part in re.split(r"[_\-]+", name):
        for w in re.findall(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+", part):
            wl = w.lower()
            m = _CONCAT_KEY_RE.search(wl)
            if m and m.start() > 0:
                words.append(wl[:m.start()])
                words.append(m.group(0))
            else:
                words.append(wl)
    return [w for w in words if w]


def _is_key_name(name: str) -> bool:
    """True when a variable name contains an exact key word (not a substring)."""
    return any(w in KEY_WORDS for w in _var_words(name))


def _key_env_ref(text: str) -> bool:
    """True when text carries an env reference whose name resembles a key."""
    for m in ENV_REF_RE.finditer(text):
        # Strip the leading $ and any braces to inspect the variable name.
        name = m.group(0).lstrip("$").strip("{}")
        # Drop a shell default-value expansion (${VAR:-default} / ${VAR:=x} /
        # POSIX ${VAR=default}) so the default text does not pollute the name.
        colon = re.search(r":[-=?+]", name)
        if colon:
            name = name[:colon.start()]
        elif "=" in name:
            name = name[:name.index("=")]
        if _is_key_name(name):
            return True
    return False


def _key_assignment_ref(text: str) -> bool:
    """True when a text line assigns to a key-named left-value
    (e.g. RELAY_API_KEY=xyz)."""
    m = ASSIGN_LEFT_RE.match(text)
    return bool(m and _is_key_name(m.group(1)))


def _has_key_context(text: str) -> bool:
    """True when text references a key by env var or by assignment left-value."""
    return _key_env_ref(text) or _key_assignment_ref(text)


def _has_bearer_literal(text: str) -> bool:
    """True when the text carries a real Bearer credential (prose such as
    "Bearer token/docs" is filtered, the same way the finding paths do)."""
    for m in BEARER_RE.finditer(text):
        if not _is_bearer_prose(m.group(1)):
            return True
    return False


def _has_secret_context(text: str) -> bool:
    """True when the same string carries a literal secret, Bearer, or key
    reference (env var or assignment left-value)."""
    return bool(
        SK_RE.search(text) or PK_RE.search(text) or JWT_RE.search(text)
        or _has_bearer_literal(text) or _has_key_context(text)
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
    """Mask a secret token: keep its real prefix + last 2 chars, middle stars."""
    if len(tok) <= 6:
        return tok[:3] + "***"
    return tok[:4] + "***" + tok[-2:]


def redact_url(url: str) -> str:
    """Reduce to scheme://host:port; drop userinfo, path, query, fragment."""
    try:
        parts = urlparse(url)
        # Accessing .hostname can raise on a malformed IPv6 bracket even when
        # urlparse returns; guard it so one bad URL cannot abort the whole scan.
        host = (parts.hostname or "").strip("[]").lower()
    except ValueError:
        return "(unparseable URL, hidden)"
    netloc = host
    # A malformed port (e.g. :abc, :99999) must not abort the whole scan; keep
    # just the host when the port is unusable.
    try:
        port = parts.port
    except ValueError:
        port = None
    if port:
        netloc = f"{host}:{port}"
    if not netloc:
        return "(no host, hidden)"
    return f"{parts.scheme}://{netloc}"


def _host_of(url: str) -> str:
    try:
        # strip a trailing dot and any IPv6 brackets; lowercase.
        return (urlparse(url).hostname or "").strip("[]").rstrip(".").lower()
    except ValueError:
        return ""


def _is_loopback_host(host: str) -> bool:
    """Loopback for IP literals via the standard library (`ipaddress` covers
    127.0.0.0/8, ::1, IPv4-mapped forms, and hex/long IPv6), plus the
    localhost names. A name such as '127.evil.com' is NOT loopback."""
    h = host
    if h in LOOPBACK_HOSTS or h == "localhost":
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def _is_loopback_url(url: str) -> bool:
    return _is_loopback_host(_host_of(url))


def _is_bind_all_url(url: str) -> bool:
    """Bind-all (unspecified) addresses: 0.0.0.0 and :: via ipaddress."""
    h = _host_of(url)
    if h in BIND_ALL_HOSTS:
        return True
    try:
        return ipaddress.ip_address(h).is_unspecified
    except ValueError:
        return False


def _is_bearer_prose(token: str) -> bool:
    """True when a Bearer 'token' is really prose. Only a single prose word
    ("authentication", "token", "header") is filtered; a composite value such
    as "abc.token.def" merely containing a prose segment is treated as a real
    credential (fail-closed) rather than silently skipped."""
    return token.lower() in _BEARER_PROSE_WORDS


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


def _userinfo_findings(value: str, file_label: str, line: int) -> list[Finding]:
    """Credentials embedded inline in a URL userinfo (scheme://user:pass@host)."""
    out: list[Finding] = []
    for m in URL_USERINFO_RE.finditer(value):
        out.append(Finding(
            file_label, line, "FAIL", "url-userinfo-credential",
            "credentials embedded inline in a URL's userinfo; pass them via env, not in the URL",
            "(userinfo hidden)",
        ))
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
        elif TEXT_ENDPOINT_ASSIGN_RE.search(line) or _has_secret_context(line):
            # Endpoint context: an explicit endpoint assignment or a key/env
            # reference on the same line. Prose "configure the endpoint" alone
            # does not qualify (that falls through to the non-endpoint WARN).
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
        out.extend(_userinfo_findings(line, file_label, lineno))
        # bearer literal (skip ordinary prose like "Bearer authentication")
        for m in BEARER_RE.finditer(line):
            if _is_bearer_prose(m.group(1)):
                continue
            out.append(Finding(
                file_label, lineno, "FAIL", "bearer-literal",
                "literal Bearer token in a command/args line; pass it via env, never inline",
                "Bearer ***",
            ))
        findings, saw_url = _http_findings(line, file_label, lineno)
        out.extend(findings)
        flags["url"] |= saw_url
        if _has_key_context(line):
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


def _last_key(path_: str) -> str:
    """Last key segment of a dotted JSON path, array index stripped:
    'servers[0].baseUrl' -> 'baseUrl'."""
    tail = path_.split(".")[-1] if path_ else ""
    return re.sub(r"\[\d+\]$", "", tail)


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
        # The JSON key for this value (last path segment, array index stripped)
        # is itself evidence when it is a key/endpoint name.
        key_name = _last_key(path_)
        if _is_key_name(key_name):
            flags["env_ref"] = True
        out.extend(_secret_findings(value, file_label, 0, f"at JSON path {path_}"))
        out.extend(_userinfo_findings(value, file_label, 0))
        for m in BEARER_RE.finditer(value):
            if _is_bearer_prose(m.group(1)):
                continue
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
                elif ENDPOINT_FIELD_RE.search(key_name) or _is_key_name(key_name) \
                        or _has_secret_context(value):
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
        if _key_env_ref(value):
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


class _Parser(argparse.ArgumentParser):
    """ArgumentParser whose usage errors exit 1 (argparse default is 2, which
    collides with the WARN exit code). --help still exits 0."""

    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(1, f"{self.prog}: error: {message}\n")


def main(argv: list[str] | None = None) -> int:
    ap = _Parser(description="Offline relay-key config hygiene check (no network, no env reads).")
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

        # Aggregate across files: a key reference in A and the endpoint in B must
        # not trip a per-file no-base-url WARN; drop per-file WARNs and emit one
        # consolidated WARN only when no scanned file carries a URL.
        all_findings = [f for f in all_findings if f.rule != "no-base-url"]
        if any_env_ref and not any_url:
            all_findings.append(Finding(
                "(across files)", 0, "WARN", "no-base-url",
                "an env-var key reference exists but no base_url/endpoint was found "
                "in any scanned file", "",
            ))

        if args.json:
            rendered = json.dumps({"findings": [asdict(f) for f in all_findings]},
                                  indent=2, ensure_ascii=False)
        else:
            rendered = format_report(all_findings)

        # Output writing stays inside the try so a bad path is a clean exit 1.
        if args.output:
            Path(args.output).write_text(rendered + "\n", encoding="utf-8")
        else:
            print(rendered)
    except (ValueError, OSError) as exc:
        print(f"relay-preflight: error: {exc}", file=sys.stderr)
        return 1

    if any(f.severity == "FAIL" for f in all_findings):
        return 3
    if all_findings:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
