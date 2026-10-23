# -*- coding: utf-8 -*-
"""relay-preflight tests (pytest, stdlib only, no network, no env reads)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
SCRIPT = HERE.parent / "skills" / "relay-preflight" / "scripts" / "relay_preflight.py"
sys.path.insert(0, str(SCRIPT.parent))

import relay_preflight as rp  # noqa: E402


# --------------------------------------------------------------------------- #
# masking / redaction (security-critical)
# --------------------------------------------------------------------------- #

def test_mask_token_keeps_prefix_and_last_two():
    out = rp.mask_token("sk-abcdefgh1234")
    assert out.startswith("sk-")
    assert "***" in out
    assert "abcdefgh" not in out
    assert out.endswith("34")


def test_redact_url_strips_userinfo_query_path():
    red = rp.redact_url("https://user:pw@relay.example.com:8443/v1/chat?key=sk-secret99")
    assert red == "https://relay.example.com:8443"
    assert "user" not in red and "pw" not in red and "key" not in red


def test_redact_url_unparseable_hidden():
    assert "hidden" in rp.redact_url("://bad")


# --------------------------------------------------------------------------- #
# rules
# --------------------------------------------------------------------------- #

def test_inline_sk_is_fail():
    fs = rp.scan_text('{"OPENAI_API_KEY": "sk-abcdef123456"}', "cfg.json")
    assert any(f.rule == "inline-secret" and f.severity == "FAIL" for f in fs)


def test_bearer_literal_is_fail():
    fs = rp.scan_text('args: ["--header", "Authorization: Bearer sk-zzzzzz1111"]', "cfg.json")
    assert any(f.rule == "bearer-literal" for f in fs)


def test_plaintext_url_is_fail():
    fs = rp.scan_text('base_url: http://relay.example.com/v1', "cfg.yaml")
    assert any(f.rule == "plaintext-url" for f in fs)


def test_https_url_clean():
    fs = rp.scan_text('base_url: https://relay.example.com/v1', "cfg.yaml")
    assert fs == []


def test_env_ref_without_url_warns():
    fs = rp.scan_text('OPENAI_API_KEY=${RELAY_KEY}', ".env")
    assert any(f.rule == "no-base-url" and f.severity == "WARN" for f in fs)


def test_env_ref_with_url_clean():
    fs = rp.scan_text('OPENAI_API_KEY=${RELAY_KEY}\nbase_url: https://relay.example.com/v1', ".env")
    assert fs == []


def test_secret_never_appears_in_redacted_field():
    secret = "sk-SUPERSECRET998877"
    fs = rp.scan_text(f"key: {secret}", "cfg")
    rendered = " ".join(f.redacted for f in fs)
    assert secret not in rendered


def test_binary_file_skipped_warns(tmp_path: Path):
    p = tmp_path / "bin.dat"
    p.write_bytes(b"\x00\x01\x02\xff\xfe")
    fs = rp.scan_file(p)
    assert any(f.rule == "binary-skipped" for f in fs)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def _write(tmp: Path, name: str, text: str) -> Path:
    p = tmp / name
    p.write_text(text, encoding="utf-8")
    return p


def test_cli_clean_exit_zero(tmp_path: Path, capsys):
    p = _write(tmp_path, ".env", "RELAY_KEY=${RELAY_KEY}\nbase_url=https://relay.example.com/v1")
    assert rp.main([str(p)]) == 0
    assert "No hygiene issues" in capsys.readouterr().out


def test_cli_fail_exit_three(tmp_path: Path):
    p = _write(tmp_path, "m.json", '{"key": "sk-abcdef123456"}')
    assert rp.main([str(p)]) == 3


def test_cli_warn_exit_two(tmp_path: Path):
    p = _write(tmp_path, ".env", "KEY=${RELAY_KEY}")
    assert rp.main([str(p)]) == 2


def test_cli_missing_file_exit_one(tmp_path: Path):
    assert rp.main([str(tmp_path_missing(tmp_path))]) == 1


def tmp_path_missing(tmp: Path) -> Path:
    return tmp / "nope.json"


def test_cli_json_payload(tmp_path: Path, capsys):
    p = _write(tmp_path, "m.json", '{"key": "sk-abcdef123456"}')
    code = rp.main([str(p), "--json"])
    assert code == 3
    payload = json.loads(capsys.readouterr().out)
    assert payload["findings"][0]["rule"] == "inline-secret"


def test_multiple_files_aggregated(tmp_path: Path):
    a = _write(tmp_path, "a.env", "KEY=${K}\nbase_url=https://h.example.com")
    b = _write(tmp_path, "b.json", '{"key": "sk-abcdef123456"}')
    code = rp.main([str(a), str(b)])
    assert code == 3


# ---- v2: JSON-aware attribution / fallback ----

def test_json_findings_carry_path(tmp_path: Path):
    p = _write(tmp_path, "m.json", '{"servers": {"s": {"env": {"OPENAI_API_KEY": "sk-abcdef123456"}}}}')
    fs = rp.scan_file(p)
    assert any("servers.s.env.OPENAI_API_KEY" in f.message for f in fs)


def test_invalid_json_falls_back_to_line_scan(tmp_path: Path):
    p = _write(tmp_path, "m.json", "not json { but sk-abcdef123456 here")
    fs = rp.scan_file(p)
    assert any(f.rule == "inline-secret" for f in fs)


def test_env_file_uses_line_scan(tmp_path: Path):
    p = _write(tmp_path, ".env", "OPENAI_API_KEY=sk-abcdef123456")
    fs = rp.scan_file(p)
    assert any(f.rule == "inline-secret" and f.line == 1 for f in fs)


def test_json_plaintext_url_fail(tmp_path: Path):
    p = _write(tmp_path, "m.json", '{"base_url": "http://relay.example.com/v1"}')
    fs = rp.scan_file(p)
    assert any(f.rule == "plaintext-url" for f in fs)


# ---- Round-1 review: local plaintext WARN, extra key formats ----

def test_localhost_http_is_warn_not_fail():
    fs = rp.scan_text("base_url: http://127.0.0.1:8080/v1", "cfg.yaml")
    assert any(f.rule == "local-plaintext-url" and f.severity == "WARN" for f in fs)
    assert not any(f.rule == "plaintext-url" for f in fs)


def test_pk_live_prefix_detected():
    fs = rp.scan_text("key: pk-live-abcdef123456", "cfg")
    assert any(f.rule == "inline-secret" and f.severity == "FAIL" for f in fs)


def test_jwt_literal_detected():
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1MTYyMzkwMjJ9.signaturepart123"
    fs = rp.scan_text(f"token: {jwt}", "cfg")
    assert any(f.rule == "inline-secret" for f in fs)
    assert jwt not in " ".join(f.redacted for f in fs)


def test_public_http_still_fail_in_json(tmp_path: Path):
    p = _write(tmp_path, "m.json", '{"base_url": "http://relay.example.com/v1"}')
    fs = rp.scan_file(p)
    assert any(f.rule == "plaintext-url" and f.severity == "FAIL" for f in fs)


# ---- Round-1 follow-up: more key prefixes, URL redaction, aggregation, context ----

def test_sk_ant_prefix_detected():
    fs = rp.scan_text("key: sk-ant-abcdef123456", "cfg")
    assert any(f.rule == "inline-secret" and f.severity == "FAIL" for f in fs)


def test_redact_url_strips_ipv6_brackets():
    red = rp.redact_url("http://[::1]:8080/v1")
    assert red == "http://::1:8080"
    assert "[" not in red and "]" not in red


def test_redact_url_drops_pct40_userinfo():
    red = rp.redact_url("http://user%40pw@relay.example.com:8443/v1")
    assert red == "http://relay.example.com:8443"
    assert "user" not in red and "pw" not in red and "%40" not in red


def test_ipv6_loopback_is_local_warn(tmp_path: Path):
    p = _write(tmp_path, "m.json", '{"base_url": "http://[::1]:8080/v1"}')
    fs = rp.scan_file(p)
    assert any(f.rule == "local-plaintext-url" and f.severity == "WARN" for f in fs)
    assert not any(f.rule == "plaintext-url" for f in fs)


def test_bind_all_0_0_0_0_is_separate_rule_not_loopback():
    # 0.0.0.0 binds every interface, not loopback: its own WARN rule, never
    # local-plaintext-url and never a public FAIL.
    fs = rp.scan_text("base_url: http://0.0.0.0:8080/v1", "cfg.yaml")
    assert any(f.rule == "bind-all-plaintext-url" and f.severity == "WARN" for f in fs)
    assert not any(f.rule == "local-plaintext-url" for f in fs)
    assert not any(f.rule == "plaintext-url" for f in fs)


def test_bind_all_0_0_0_0_in_json_is_separate_rule(tmp_path: Path):
    p = _write(tmp_path, "m.json", '{"base_url": "http://0.0.0.0:8080/v1"}')
    fs = rp.scan_file(p)
    assert any(f.rule == "bind-all-plaintext-url" and f.severity == "WARN" for f in fs)
    assert not any(f.rule == "local-plaintext-url" for f in fs)
    assert not any(f.rule == "plaintext-url" for f in fs)


def test_nonendpoint_http_without_key_context_warns_not_fails():
    # A doc link/example with no endpoint field and no key context -> WARN.
    fs = rp.scan_text("See the setup guide at http://docs.example.com/install for notes.", "README.md")
    assert any(f.rule == "nonendpoint-http" and f.severity == "WARN" for f in fs)
    assert not any(f.rule == "plaintext-url" for f in fs)


def test_cross_file_env_ref_and_url_no_false_warn(tmp_path: Path):
    # P3-3: key reference in A, endpoint in B -> no no-base-url WARN, clean.
    a = _write(tmp_path, "a.env", "RELAY_KEY=${RELAY_KEY}")
    b = _write(tmp_path, "b.json", '{"base_url": "https://relay.example.com/v1"}')
    code = rp.main([str(a), str(b)])
    assert code == 0


def test_cross_file_env_ref_without_url_warns(tmp_path: Path):
    a = _write(tmp_path, "a.env", "RELAY_KEY=${RELAY_KEY}")
    b = _write(tmp_path, "b.txt", "just a plain note, no endpoint here")
    code = rp.main([str(a), str(b)])
    assert code == 2
    assert any(f.rule == "no-base-url" for f in rp.scan_file(a) + rp.scan_file(b))


# ---- R5 review: false-positive guards (word boundary, prose, non-key vars) ----

def test_sk_pattern_inside_word_not_flagged():
    # `desk-`/`risk-` must not be read as an inline sk- key.
    fs = rp.scan_text("sitting at my desk-abcdef to assess risk-123456", "note.txt")
    assert not any(f.rule == "inline-secret" for f in fs)


def test_bearer_prose_not_flagged():
    fs = rp.scan_text("Bearer authentication is required for the Authorization header.", "doc.txt")
    assert not any(f.rule == "bearer-literal" for f in fs)


def test_non_key_shell_vars_no_false_warn(tmp_path: Path):
    # $PATH/$HOME are not key references; no no-base-url WARN on their own.
    a = _write(tmp_path, "a.sh", "export PATH=$HOME/bin:$PATH")
    code = rp.main([str(a)])
    assert code == 0


def test_homepage_url_http_not_fail():
    # A bare `homepage_url` over http is not a relay endpoint -> not FAIL.
    fs = rp.scan_text('"homepage_url": "http://example.com/home"', "cfg.json")
    assert not any(f.rule == "plaintext-url" and f.severity == "FAIL" for f in fs)


def test_database_url_http_not_upgraded_to_fail():
    # `database_url` contains the substring `base_url` but is not an endpoint.
    fs = rp.scan_text('"database_url": "http://example.com/db"', "cfg.json")
    assert not any(f.rule == "plaintext-url" and f.severity == "FAIL" for f in fs)


def test_non_key_env_substrings_no_false_context():
    # AUTHORITY/COMPASS/CREDIT contain AUTH/PASS/CRED as substrings only.
    for name in ("AUTHORITY_URL", "COMPASS_MODE", "CREDIT_LIMIT"):
        assert rp._is_key_name(name) is False
    assert rp._is_key_name("RELAY_KEY") is True
    assert rp._is_key_name("API_TOKEN") is True


def test_loopback_whole_127_range():
    for url in ("http://127.0.0.2:8080/x", "http://localhost.:8080/x"):
        assert rp._is_loopback_url(url) is True


def test_url_userinfo_credentials_fail():
    fs = rp.scan_text("base_url=http://user:pass123@example.com/api", "cfg")
    assert any(f.rule == "url-userinfo-credential" and f.severity == "FAIL" for f in fs)


def test_usage_error_exits_one():
    with pytest.raises(SystemExit) as e:
        rp.main([])
    assert e.value.code == 1


def test_bearer_plural_prose_not_flagged():
    # "Bearer tokens" / "examples" are prose, not a credential.
    assert rp.scan_text("# Bearer tokens available from the docs", "cfg") == []


def test_prose_bearer_does_not_upgrade_doc_link():
    # A doc link beside prose "Bearer token" must stay WARN, not FAIL.
    fs = rp.scan_text("read the Bearer token docs at http://example.com/guide", "cfg")
    assert not any(f.severity == "FAIL" for f in fs)


def test_invalid_127_name_not_loopback():
    # A name '127.evil.com' or invalid '127.999.1.1' must not be treated as loopback.
    assert rp._is_loopback_url("http://127.evil.com/x") is False
    assert rp._is_loopback_url("http://127.999.1.1/x") is False


def test_redact_url_malformed_port_keeps_host():
    # A malformed port must not raise; the host is retained.
    assert rp.redact_url("http://example.com:99999/x") == "http://example.com"


def test_key_env_default_expansion_recognized():
    # ${VAR:-default} must still be recognized from its name.
    assert rp._key_env_ref("${SECRET:-changeme}") is True


# ---- R8 review fixes ----

def test_env_key_assignment_triggers_no_base_url(tmp_path: Path):
    # P1-1: a key-named assignment with no URL must WARN no-base-url.
    p = tmp_path / ".env"
    p.write_text("RELAY_API_KEY=opaquetoken123\n", encoding="utf-8")
    fs = rp.scan_file(p)
    assert any(f.rule == "no-base-url" and f.severity == "WARN" for f in fs)


def test_json_key_name_triggers_no_base_url(tmp_path: Path):
    # P1-1: a JSON key named like a key, no URL -> no-base-url.
    p = tmp_path / "cfg.json"
    p.write_text(json.dumps({"relayApiKey": "opaquetoken123"}), encoding="utf-8")
    fs = rp.scan_file(p)
    assert any(f.rule == "no-base-url" for f in fs)


def test_concatenated_lowercase_key_name():
    # P2-1: apikey/secretkey/privatekey/accesskey are key names.
    assert rp._is_key_name("apikey")
    assert rp._is_key_name("secretkey")
    assert rp._is_key_name("privatekey")
    assert rp._is_key_name("accesskey")
    # authority must not be misread as auth.
    assert rp._is_key_name("authority") is False


def test_prose_endpoint_does_not_upgrade_link():
    # P2-2: prose "configure the endpoint at http://..." stays WARN, not FAIL.
    fs = rp.scan_text("configure the endpoint at http://example.com/guide", "cfg")
    assert not any(f.rule == "plaintext-url" and f.severity == "FAIL" for f in fs)


def test_assigned_endpoint_http_fails():
    # An explicit endpoint=http://... must still FAIL.
    fs = rp.scan_text("base_url=http://example.com/api", "cfg")
    assert any(f.rule == "plaintext-url" and f.severity == "FAIL" for f in fs)


def test_ipv6_loopback_and_unspecified():
    # P2-3: ipaddress recognizes ::1 loopback and :: unspecified.
    assert rp._is_loopback_url("http://[0:0:0:0:0:0:0:1]/x") is True
    assert rp._is_bind_all_url("http://[::]/x") is True


def test_mask_token_keeps_real_prefix():
    # P2-4: a pk- token must not be masked with an sk- prefix.
    assert rp.mask_token("pk-live-abcdefgh").startswith("pk-")


def test_jwt_standard_base64_chars():
    # R9 P2-1: a JWT using standard base64 (+, /, =) is still detected.
    fs = rp.scan_text(
        "eyJabc+/=ab.eyJseg+/=ab.eyJsig+/=ab", "cfg")
    assert any(f.rule == "inline-secret" and f.severity == "FAIL" for f in fs)


def test_composite_bearer_token_not_prose():
    # R9 P2-2: a composite token containing a prose segment is a real credential.
    fs = rp.scan_text("Authorization: Bearer abc.token.def", "cfg")
    assert any(f.rule == "bearer-literal" and f.severity == "FAIL" for f in fs)
    # A single prose word is still filtered.
    assert rp._is_bearer_prose("authentication") is True


def test_redact_url_malformed_ipv6_hidden():
    # R9 P2-3: a malformed IPv6 bracket does not abort the scan.
    assert "hidden" in rp.redact_url("http://[::1/path")


def test_posix_bare_default_env_ref():
    # R9 P2-4: ${API_KEY=default} is recognized as a key reference.
    assert rp._key_env_ref("${API_KEY=default}") is True


def test_empty_password_userinfo_detected():
    # R9 P2-5: "user:@host" (empty password) is userinfo.
    fs = rp.scan_text("http://user:@host.example.com/v1", "cfg")
    assert any(f.rule == "url-userinfo-credential" and f.severity == "FAIL" for f in fs)


def test_underscore_prefix_sk_not_word_boundary():
    # R9 P2-6: "_sk-abcdef1234" is still an inline secret.
    fs = rp.scan_text("_sk-abcdef123456", "cfg")
    assert any(f.rule == "inline-secret" and f.severity == "FAIL" for f in fs)
