# relay-preflight

**Offline hygiene check for relay/aggregator API configs.** Before you commit a
`.mcp.json`, Claude `settings.json`, `.env`, or shell snippet with a third-party
OpenAI-compatible relay key, this flags: inline literal `sk-...` keys, literal
`Bearer` tokens, plaintext `http://` base_urls, and a key reference with no
endpoint. It masks every secret, strips URLs to `host:port`, never reads
environment variable values, and makes no network request.

Pure Python standard library, offline, Windows / macOS / Linux, Python 3.10+.

## Why this exists

Relay/aggregator setups invite two mistakes: pasting the `sk-...` straight into
a committed config, and pointing a key at plaintext `http://`. General scanners
(gitleaks, trufflehog, detect-secrets) can scan named files and directories, but
they target repo/pre-commit code scanning and need an install; this is a
write-time, file-local preflight for the moment a non-developer fills in a relay
config, with relay-specific rules (public plaintext `http://` base_url, env
reference without an endpoint, inline Bearer on a command line), zero install,
masked output, no env-value reads, and no key-validation traffic. It does **not**
judge whether the upstream model is genuine — that needs a separate probe tool.

## Install

No build, no dependencies.

- Claude Code: `claude --plugin-dir ./relay-preflight`, or register the local
  marketplace in `.claude-plugin/marketplace.json`.
- Portable skill (Codex/Cursor/Gemini CLI/Roo Code): copy
  `skills/relay-preflight/` into the client's skills directory.

## Usage

```bash
python skills/relay-preflight/scripts/relay_preflight.py .mcp.json settings.json .env [--json] [--output report.md]
```

### Exit codes

| code | meaning |
|---|---|
| 0 | clean |
| 2 | warnings (reference without endpoint, binary skipped) |
| 3 | failures (inline secret, Bearer literal, http URL) |
| 1 | usage / IO error |

### Rules

| rule | trigger | severity |
|---|---|---|
| inline-secret | literal `sk-...` (incl. `sk-ant-`), `pk-live/pk-test-...`, or compact JWT (`eyJ...`) in file (JSON path attributed for `.json`) | FAIL |
| bearer-literal | `Authorization: Bearer <token>` inline on a command/args line | FAIL |
| plaintext-url | public `http://` endpoint (base_url field, or a URL carrying a key/env ref) | FAIL |
| local-plaintext-url | `http://` on localhost/127.0.0.1/::1 (stays on-machine) | WARN |
| bind-all-plaintext-url | `http://` on `0.0.0.0` (binds every interface, not loopback; reachable off-machine) | WARN |
| nonendpoint-http | public `http://` link with no key/endpoint context (doc link, example) | WARN |
| no-base-url | `${VAR}` reference but no endpoint across all scanned files | WARN |

## Related work

- [gitleaks](https://github.com/gitleaks/gitleaks),
  [trufflehog](https://github.com/trufflesecurity/trufflehog),
  [detect-secrets](https://github.com/Yelp/detect-secrets) all accept explicit
  files/dirs (not only git history); trufflehog additionally verifies keys online.
  They target committed code in a repo/pre-commit flow and need an install. This
  tool differs: it is for the moment a non-developer writes a relay config, runs
  with zero install, adds relay-specific rules (plaintext `http://` base_url,
  env reference with no endpoint, inline Bearer on a command line), masks every
  secret, never reads env values, and never contacts a server.
- Authenticity judgment (is this endpoint really the claimed model?) is out of
  scope here; it belongs to a separate behavioral probe.

## Tests

```bash
python -m pytest tests/ -q
```

34 tests, stdlib only; manual predicate-mutation spot checks (inverting the
http/https gate turns the plaintext test red; recorded in CHANGELOG).

## Limits (honest)

- Hygiene only: no authenticity probe, no key validation, no reachability check.
- Only files passed as arguments; no whole-disk scan. The `no-base-url` check is
  aggregated across every file passed in, so a key reference in A and the endpoint
  in B no longer false-warn.
- Does not read env values; pattern-based. Covered: `sk-` (incl. `sk-ant-`),
  `pk-live/pk-test-`, compact three-segment JWT (`eyJ...`), and inline Bearer.
  Other schemes — non-compact JWTs, custom prefixes, API keys without a known
  prefix — may be missed; treat this as a backstop, not an audit.

## License

MIT, © 2026 Daizhi Liao (dafahaha).
