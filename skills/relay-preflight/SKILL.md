---
name: relay-preflight
description: Offline hygiene check before writing a relay/aggregator API key into a config (.mcp.json, Claude settings.json, .env, shell snippet). Flags inline literal sk- keys, literal Bearer tokens, plaintext http base_url, and a key reference with no endpoint. Use when the user is about to configure a third-party relay/OpenAI-compatible endpoint, asks "is this config safe to commit", or pastes a key into a settings file. Masks secrets, strips URLs, never reads env values, never sends network requests.
license: MIT
compatibility: Python 3.10+, stdlib only; fully offline; Windows/macOS/Linux; scans files the user points at; does not read environment variable values.
---

# relay-preflight — offline relay-key config hygiene

## When to activate

- The user is adding a relay/aggregator/OpenAI-compatible endpoint key to a config file.
- The user asks whether a config is safe to commit or contains a leaked key.
- Do **not** use this to judge whether the upstream model is genuine; that needs a
  separate probe. This is write-time hygiene only.

## Steps

1. Point the scanner at the actual file(s):

```bash
python skills/relay-preflight/scripts/relay_preflight.py .mcp.json settings.json .env [--json] [--output report.md]
```

2. Triage:
   - **FAIL (exit 3):** inline `sk-...`/`pk-live-...`/JWT literal; literal `Bearer`
     token; public `http://` endpoint (base_url field or a URL carrying a key/env ref).
     Fix before committing: move the key to an env var (`${VAR}`), use https.
   - **WARN (exit 2):** env-var reference with no endpoint across scanned files;
     loopback `http://`; `0.0.0.0` bind-all `http://` (not loopback, reachable
     off-machine); non-endpoint http link with no key context; unreadable binary.
3. The report masks every token (`sk-***34`) and reduces URLs to `scheme://host:port`;
   it never prints the secret or reads env values.

## Rules

| rule | trigger | severity |
|---|---|---|
| inline-secret | literal `sk-...` (incl. `sk-ant-`), `pk-live/pk-test-...`, compact JWT `eyJ...` (JSON path attributed for .json) | FAIL |
| bearer-literal | `Authorization: Bearer <token>` inline on a command/args line | FAIL |
| plaintext-url | public `http://` endpoint (base_url field, or URL with key/env context) | FAIL |
| local-plaintext-url | `http://` on localhost/127.0.0.1/::1 | WARN |
| bind-all-plaintext-url | `http://` on `0.0.0.0` (binds every interface, not loopback) | WARN |
| nonendpoint-http | public `http://` link with no key/endpoint context (doc link, example) | WARN |
| no-base-url | `${VAR}` reference but no endpoint across all scanned files | WARN |

## Boundaries

- Hygiene only: does not verify model authenticity, key validity, or reachability.
- Does not scan the whole disk; only files passed as arguments; `no-base-url` is
  aggregated across files (key in A, endpoint in B does not warn).
- Does not read environment variable values; it only inspects file contents.
- Pattern-based: covered `sk-`/`sk-ant-`, `pk-live/test-`, compact JWT, Bearer;
  non-compact JWTs, custom prefixes, and exotic key formats may be missed; treat as
  a backstop, not an audit.
