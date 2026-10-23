# Changelog — relay-preflight

v1.4.0 — 2026-10-23

## Round-6 independent clean review (fresh reviewer, cold reading)
- P2-1 (fixed): the endpoint-field regex is anchored at a boundary so a field
  such as `database_url` (contains `base_url`) or `nameserver_url` (contains
  `server_url`) is not upgraded to FAIL.
- P2-2 (fixed): key-name detection matches exact words (split on `_`/`-`/
  camelCase), so `AUTHORITY_URL`/`COMPASS_MODE`/`CREDIT_LIMIT` are no longer
  misread as secret context; real `RELAY_KEY`/`API_TOKEN` still match.
- P2-3 (fixed): loopback covers the whole 127.0.0.0/8 range (not just .1),
  strips a trailing dot, and handles an IPv4-mapped loopback.
- P2-4 (fixed): the Bearer prose filter splits on punctuation so
  `Bearer example.com` is not a false FAIL.
- P2-5 (fixed): credentials embedded in a URL's userinfo
  (`scheme://user:pass@host`) are now flagged FAIL.
- New tests: database_url, non-key substrings, 127-range, URL userinfo.
  Suite: 39 -> 43.

v1.3.0 — 2026-10-23

## Round-5 independent technical review (fresh reviewer, cold reading)
- P1-1 (fixed): argparse usage errors (missing files, invalid type) exited 2,
  colliding with the WARN exit code; a custom parser now exits 1 for usage
  errors (--help still exits 0).
- P1-2 (fixed): a bare `url` substring in the endpoint-field regex upgraded
  harmless fields (`homepage_url`, `docs_url`) to FAIL; the regex now anchors
  real endpoint names (base_url/api_url/server_url/endpoint).
- P2-1 (fixed): sk-/pk- patterns now require a left boundary, so they no longer
  match inside ordinary words (`desk-`, `risk-`).
- P2-2 (fixed): Bearer detection now requires a longer token and filters common
  prose words ("Bearer authentication/header/token"), avoiding false FAILs.
- P2-3 (fixed): env references that count toward no-base-url/secret-context must
  name a key (KEY/TOKEN/SECRET/...), so $PATH/$HOME no longer trip the WARN.
- Output write moved inside the try (clean exit 1 on a bad path).
- New tests: word boundary, bearer prose, non-key shell vars, homepage_url,
  usage exit 1. Suite: 34 -> 39.

v1.0.0 — 2026-10-22

## v1 (baseline)
- Line scan: inline-secret, bearer-literal, plaintext-url FAIL; no-base-url WARN;
  token masking, URL redaction; Markdown + `--json`; exit codes; 17 tests green.
  Stands alone with no runtime dependency.

## v2 (JSON-aware attribution) — quality issue: raw line scanning a `.mcp.json`
could not say WHICH config carried the secret and risked false positives.
- Parse `.json`/`.mcp` files, walk string values, attribute findings to the
  dotted JSON path; invalid JSON falls back to line scan; `.env`/text keeps
  line-number scan. New tests: JSON path, invalid-JSON fallback, env line scan,
  JSON plaintext URL.

## v3 (security hardening)
- Confirmed: env values are never read; report only contains masked tokens and
  redacted host:port; binary files are skipped with a WARN rather than guessed;
  test asserts the raw secret never appears in any redacted field.

## v4 (multi-file aggregation)
- Accept several files in one invocation; findings aggregate; exit code is the
  worst severity; test covers mixed clean/fail inputs.

## v5 (spec compliance + manual mutation spot check)
- Frontmatter limited to spec fields; README states hygiene-only limits honestly.
- Manual predicate-mutation spot check: inverted the http/https gate -> plaintext
  test red; reverted, full suite green (21). No automated mutation-testing
  framework is configured.

## Round-1 independent review fixes (v1.1.0)
- Public `http://` stays FAIL; loopback `http://` (localhost/127.0.0.1/::1)
  downgrades to a WARN (it never leaves the machine) instead of a false FAIL.
- Added `pk-live-`/`pk-test-` prefix and compact JWT (`eyJ...`) literal detection
  alongside `sk-`; secrets stay masked in output.
- Normalized `[::1]` bracket stripping in redact_url.
- README: corrected the competitor claim (gitleaks/trufflehog/detect-secrets all
  scan named files); added a Related work section; clarified covered key formats.
- Tests: 21 -> 25.

## Round-1 follow-up fixes (v1.2.0)
- P3-1: explicit `sk-ant-` coverage test added (already matched by `sk-`);
  `pk-live/test-` and compact JWT `eyJ...` detection retained.
- P3-2: redact_url strips IPv6 brackets (`[::1]` -> `::1`) and drops `%40`
  encoded userinfo; tests cover both.
- P3-3: `no-base-url` is aggregated across all files passed in — a key reference
  in file A and the endpoint in file B no longer false-warns; one consolidated
  WARN emits only when no scanned file carries a URL.
- Product: non-endpoint `http://` links (doc links, examples) with no key/endpoint
  context downgrade to WARN (`nonendpoint-http`) instead of FAIL; competitor
  wording corrected (gitleaks/trufflehog/detect-secrets all scan named files;
  differences are write-time positioning, zero install, relay-specific rules,
  masking, no env reads, no network); Limits name the covered prefixes and the
  formats that may be missed; no internal codenames appear in the CHANGELOG.
- New tests: sk-ant-, IPv6 brackets, %40 userinfo, IPv6 loopback WARN,
  non-endpoint http WARN, cross-file aggregation clean/warn. Suite: 25 -> 34.
