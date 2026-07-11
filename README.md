> 🔗 **Vaultwarden:** [github.com/dani-garcia/vaultwarden](https://github.com/dani-garcia/vaultwarden)
>
> 📖 **Read the write-up:** [Self-Hosted Vaultwarden — Docker Setup, Clients & Full Guide](https://deb.myguard.nl/2026/05/self-hosted-password-manager-with-vaultwarden/)

# Vaultwarden (Bitwarden) OWASP CRS Plugin

![Lint](https://github.com/myguard-labs/vaultwarden-crs-plugin/actions/workflows/lint.yml/badge.svg) ![Integration Tests](https://github.com/myguard-labs/vaultwarden-crs-plugin/actions/workflows/integration.yml/badge.svg) ![Apache/v2](https://github.com/myguard-labs/vaultwarden-crs-plugin/actions/workflows/apache-modsecurity2.yml/badge.svg) ![NGINX/v3](https://github.com/myguard-labs/vaultwarden-crs-plugin/actions/workflows/nginx-libmodsecurity3.yml/badge.svg) ![NGINX/Coraza](https://github.com/myguard-labs/vaultwarden-crs-plugin/actions/workflows/coraza.yml/badge.svg) ![Security Corpus](https://github.com/myguard-labs/vaultwarden-crs-plugin/actions/workflows/security-corpus.yml/badge.svg)

![Defense-in-depth: the vaultwarden-crs-plugin adds a PATH allowlist and false-positive exclusions at the WAF edge before requests reach the end-to-end encrypted Vaultwarden Rust backend and a hardened Docker container](https://deb.myguard.nl/wp-content/uploads/2026/07/vaultwarden-crs-plugin-defense-in-depth.webp)

A drop-in [OWASP CRS](https://coreruleset.org/) plugin that makes the Core
Rule Set play nicely with **[Vaultwarden](https://github.com/dani-garcia/vaultwarden)**
(the Rust Bitwarden-compatible server) — and, optionally, locks the host
down to Vaultwarden's known route map.

> **Why this differs from a form-app plugin.** Vaultwarden is a JSON API:
> the web vault, browser extensions, mobile, desktop and the Bitwarden CLI
> all POST `application/json` bodies whose argument **names** are JSON keys
> that vary per endpoint and per client version. A vimbadmin-style
> `ARGS_NAMES` allowlist would therefore false-block real clients. This
> plugin **deliberately ships no arg-name allowlist** — its positive-security
> layer is a **PATH allowlist** only. Bodies are end-to-end encrypted
> (EncString `2.<iv>|<ct>|<mac>` blobs + base64), so the before-rules strip
> the known-noisy base64/SQLi/PHP target families on the encrypted write
> paths rather than weakening the whole engine.

It does two things:

1. **False-positive exclusions** (`vaultwarden-before.conf`) — surgical,
   host-scoped exclusions so legitimate inputs (the Argon2 admin `token`,
   the OAuth password-grant hashes on `/identity/connect/token`, the
   EncString cipher/account/send blobs under `/api`, user-supplied icon
   domains) don't trip CRS.

2. **Positive security / path allowlist** (`vaultwarden-after.conf`,
   **opt-in**) — *allow Vaultwarden's real routes, deny everything else*.
   Any path outside Vaultwarden's mount points (`/api`, `/identity`,
   `/admin`, `/events`, `/icons`, `/notifications`, `/attachments`, the
   built-in static routes and the web-vault static tree) is denied. This
   stops the usual `/.env` / `/wp-login.php` scanner noise before it reaches
   the backend, regardless of payload. **No arg-name allowlist** (see above).

The route map is derived from Vaultwarden's source
(`src/api/mod.rs` mount points + `src/api/web.rs` static routes), not guessed.

Since **1.1.0** the positive-security layer also: enforces an **HTTP-method
allowlist** (only `GET/POST/PUT/DELETE/HEAD/OPTIONS` — `TRACE`, `CONNECT`,
`PATCH`, junk verbs are denied, `9530220`); requires **`application/json`** on
`/api` writes (except multipart `/api/sends/file*` and cipher attachment
uploads, `9530225`); **anchors static-file extensions to known prefixes** so a
deep fake path like `/x/y/z.json` no longer slips through the old global
`\.<ext>$` suffix; and **feeds the CRS inbound anomaly score** on every block,
so fail2ban / CRS DOS layers see the probe instead of a silent 404.

### Argument-name allowlist (1.2.0, experimental, separate opt-in)

Vaultwarden is a JSON API, so a body arg-name allowlist is unsafe (keys vary
per endpoint/client/version) and is **never** applied to JSON bodies. But the
two *non-JSON* surfaces are stable and fully enumerable, so 1.2.0 adds an
optional allowlist for them — gated by its **own** flag
`tx.vaultwarden-plugin_argname_allowlist` (default OFF, independent of the
path allowlist):

- **`9530240`** — the `/identity/connect/token` form fields. This is the only
  `x-www-form-urlencoded` endpoint; its field set is fixed by the
  `ConnectData` struct in `src/api/identity.rs` (verified against source,
  case-insensitive, snake_case + flattened variants). Scoped via
  `ARGS_POST_NAMES` to that exact path — JSON bodies elsewhere are untouched.
- **`9530245`** — GET query-string parameter names (`ARGS_GET_NAMES`).

These live in `vaultwarden-before.conf` on purpose: their deny must evaluate
**before** the CRS anomaly-blocking rule `949110` (otherwise a request CRS
already scored ≥5 is blocked there first and the allowlist deny is never
reached). Enable per vhost only after a DetectionOnly burn-in:
`setvar:tx.vaultwarden-plugin_argname_allowlist=1`.

## Requirements

- CRS Version 4.0 or newer
- ModSecurity compatible Web Application Firewall

## Install

Copy the three files into your CRS `plugins/` directory:

```
plugins/vaultwarden-config.conf
plugins/vaultwarden-before.conf
plugins/vaultwarden-after.conf
```

CRS loads `plugins/*-config.conf`, then `*-before.conf` (before the rules),
then `*-after.conf` (after the rules) automatically.

## Configure

Edit `vaultwarden-config.conf`:

| Variable | Default | Meaning |
|---|---|---|
| `tx.vaultwarden-plugin_enabled` | `0` | Master on/off. **OFF by default** — the plugin weakens CRS on the Vaultwarden routes, so it must be enabled per vhost, not globally. Set to `1` only in the Vaultwarden server/location block (see Roll-out). |
| `tx.vaultwarden-plugin_positive_security` | follows `_enabled` | Turn the path-allowlist layer on/off. Defaults to the enable flag; set to `0` explicitly in the enable block to run exclusions without the allowlist. |

Scoping is done entirely by the per-vhost enable flag — there is **no Host
gate**. Enable the plugin only on the Vaultwarden vhost, e.g. (Angie /
nginx + libmodsecurity3):

```nginx
server {
    server_name vault.example.com;
    modsecurity on;
    modsecurity_rules '
        SecAction "id:9530001,phase:1,nolog,pass,setvar:tx.vaultwarden-plugin_enabled=1"
    ';
    # ...
}
```

On Apache/mod_security2, set the same variable inside the matching
`<Location>` / `<VirtualHost>` block.

## Roll-out

1. Install, then enable the plugin in the Vaultwarden vhost only
   (`setvar:tx.vaultwarden-plugin_enabled=1`). The exclusions are safe
   immediately and never touch other vhosts on the same CRS engine.
2. Run CRS in **DetectionOnly** and watch the audit log for `9530230` hits
   — those are paths missing from the route allowlist. If you front
   Vaultwarden with extra routes (a reverse-proxy health check, a custom
   connector), add them to the inline allowlist regex on rule `9530230` in
   `vaultwarden-after.conf`.
3. Flip CRS back to blocking mode.

Rule ID range: **9,530,000 – 9,530,999** (block base 9,530,000; free in the
[CRS plugin registry](https://github.com/coreruleset/plugin-registry),
pending formal assignment).

## Continuous integration

Every push/PR runs five GitHub Actions workflows (each gets its own badge above):

| Workflow | What it does |
|---|---|
| **Lint** | Local rule-ID-range (9530000–9530999) / duplicate-ID / `@pmFromFile` / test-reference checks, then the official `coreruleset/crs-plugin-test-action` lint. |
| **Integration tests** | Plugin-structure gates (no host gate, opt-in allowlist, **no `ARGS_NAMES` allowlist**, conditional config defaults, `ver:` on every rule). |
| **Apache + ModSecurity v2** | Builds a shared CRS+plugin image and runs the go-ftw regression suite on real Apache httpd + mod_security2 (`apache2ctl -t` gates parse). |
| **nginx + libmodsecurity3** | Same shared image on Angie + libmodsecurity3 3.0.14 — a production mirror (`angie -t` gates parse). |
| **Coraza compatibility** | Loads every plugin file into `coraza.NewWAF()` (vendored probe in [`tests/coraza/`](tests/coraza/)) — Coraza fails hard at config load where ModSecurity warns, so this gates the third engine. Runs on PRs. |

The dual-engine harness lives under [`tests/integration/`](tests/integration/);
go-ftw test cases under [`tests/regression/`](tests/regression/) and
[`tests/security/`](tests/security/).

## Disabling the plugin

Set `tx.vaultwarden-plugin_enabled` to `0` (the default), or remove the plugin
files from the `plugins/` directory entirely.

## Edge hardening (rate limiting, native path/method allowlist)

The CRS plugin is the WAF half. For the **edge half** — per-endpoint rate
limiting (`/admin`, `/identity/connect/token`, register, send-download),
a native path allowlist that 404s unknown routes, a method allowlist, security
headers and body/timeout caps — see [`contrib/angie/vault.conf`](contrib/angie/vault.conf)
and [`contrib/README.md`](contrib/README.md).

Rate limiting in particular **cannot** be done in the plugin: libmodsecurity3
(v3) has no persistent per-IP collections, so it belongs at the edge (or in
fail2ban). Run the plugin and the contrib vhost together for belt-and-braces.

## Reporting false positives

Open a new issue or pull request. For issues, include:

- CRS Version
- ModSecurity/Coraza Version
- modsec audit logs
- what caused the false positive

## See also

- Vaultwarden: <https://github.com/dani-garcia/vaultwarden>
- Write-up / deployment guide: [Self-Hosted Vaultwarden on deb.myguard.nl](https://deb.myguard.nl/2026/05/self-hosted-password-manager-with-vaultwarden/)
- ViMbAdmin CRS plugin (same author, form-app variant with arg-name
  allowlist): <https://github.com/myguard-labs/vimbadmin-crs-plugin>
