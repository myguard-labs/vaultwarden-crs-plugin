> 🔗 **Vaultwarden:** [github.com/dani-garcia/vaultwarden](https://github.com/dani-garcia/vaultwarden)

# Vaultwarden (Bitwarden) OWASP CRS Plugin

![Lint](https://github.com/eilandert/bitwarden-crs-plugin/actions/workflows/lint.yml/badge.svg) ![Integration tests](https://github.com/eilandert/bitwarden-crs-plugin/actions/workflows/integration.yml/badge.svg) ![Apache + ModSecurity v2](https://github.com/eilandert/bitwarden-crs-plugin/actions/workflows/apache-modsecurity2.yml/badge.svg) ![nginx + libmodsecurity3](https://github.com/eilandert/bitwarden-crs-plugin/actions/workflows/nginx-libmodsecurity3.yml/badge.svg)

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

1. **False-positive exclusions** (`bitwarden-before.conf`) — surgical,
   host-scoped exclusions so legitimate inputs (the Argon2 admin `token`,
   the OAuth password-grant hashes on `/identity/connect/token`, the
   EncString cipher/account/send blobs under `/api`, user-supplied icon
   domains) don't trip CRS.

2. **Positive security / path allowlist** (`bitwarden-after.conf`,
   **opt-in**) — *allow Vaultwarden's real routes, deny everything else*.
   Any path outside Vaultwarden's mount points (`/api`, `/identity`,
   `/admin`, `/events`, `/icons`, `/notifications`, `/attachments`, the
   built-in static routes and the web-vault static tree) is denied. This
   stops the usual `/.env` / `/wp-login.php` scanner noise before it reaches
   the backend, regardless of payload. **No arg-name allowlist** (see above).

The route map is derived from Vaultwarden's source
(`src/api/mod.rs` mount points + `src/api/web.rs` static routes), not guessed.

## Requirements

- CRS Version 4.0 or newer
- ModSecurity compatible Web Application Firewall

## Install

Copy the three files into your CRS `plugins/` directory:

```
plugins/bitwarden-config.conf
plugins/bitwarden-before.conf
plugins/bitwarden-after.conf
```

CRS loads `plugins/*-config.conf`, then `*-before.conf` (before the rules),
then `*-after.conf` (after the rules) automatically.

## Configure

Edit `bitwarden-config.conf`:

| Variable | Default | Meaning |
|---|---|---|
| `tx.bitwarden-plugin_enabled` | `0` | Master on/off. **OFF by default** — the plugin weakens CRS on the Vaultwarden routes, so it must be enabled per vhost, not globally. Set to `1` only in the Vaultwarden server/location block (see Roll-out). |
| `tx.bitwarden-plugin_positive_security` | follows `_enabled` | Turn the path-allowlist layer on/off. Defaults to the enable flag; set to `0` explicitly in the enable block to run exclusions without the allowlist. |

Scoping is done entirely by the per-vhost enable flag — there is **no Host
gate**. Enable the plugin only on the Vaultwarden vhost, e.g. (Angie /
nginx + libmodsecurity3):

```nginx
server {
    server_name vault.example.com;
    modsecurity on;
    modsecurity_rules '
        SecAction "id:9530001,phase:1,nolog,pass,setvar:tx.bitwarden-plugin_enabled=1"
    ';
    # ...
}
```

On Apache/mod_security2, set the same variable inside the matching
`<Location>` / `<VirtualHost>` block.

## Roll-out

1. Install, then enable the plugin in the Vaultwarden vhost only
   (`setvar:tx.bitwarden-plugin_enabled=1`). The exclusions are safe
   immediately and never touch other vhosts on the same CRS engine.
2. Run CRS in **DetectionOnly** and watch the audit log for `9530230` hits
   — those are paths missing from the route allowlist. If you front
   Vaultwarden with extra routes (a reverse-proxy health check, a custom
   connector), add them to the inline allowlist regex on rule `9530230` in
   `bitwarden-after.conf`.
3. Flip CRS back to blocking mode.

Rule ID range: **9,530,000 – 9,530,999** (block base 9,530,000; free in the
[CRS plugin registry](https://github.com/coreruleset/plugin-registry),
pending formal assignment).

## Continuous integration

Every push/PR runs four GitHub Actions workflows (each gets its own badge above):

| Workflow | What it does |
|---|---|
| **Lint** | Local rule-ID-range (9530000–9530999) / duplicate-ID / `@pmFromFile` / test-reference checks, then the official `coreruleset/crs-plugin-test-action` lint. |
| **Integration tests** | Plugin-structure gates (no host gate, opt-in allowlist, **no `ARGS_NAMES` allowlist**, conditional config defaults, `ver:` on every rule). |
| **Apache + ModSecurity v2** | Builds a shared CRS+plugin image and runs the go-ftw regression suite on real Apache httpd + mod_security2 (`apache2ctl -t` gates parse). |
| **nginx + libmodsecurity3** | Same shared image on Angie + libmodsecurity3 3.0.14 — a production mirror (`angie -t` gates parse). |

The dual-engine harness lives under [`tests/integration/`](tests/integration/);
go-ftw test cases under [`tests/regression/`](tests/regression/) and
[`tests/security/`](tests/security/).

## Disabling the plugin

Set `tx.bitwarden-plugin_enabled` to `0` (the default), or remove the plugin
files from the `plugins/` directory entirely.

## Reporting false positives

Open a new issue or pull request. For issues, include:

- CRS Version
- ModSecurity/Coraza Version
- modsec audit logs
- what caused the false positive

## See also

- Vaultwarden: <https://github.com/dani-garcia/vaultwarden>
- ViMbAdmin CRS plugin (same author, form-app variant with arg-name
  allowlist): <https://github.com/eilandert/vimbadmin-crs-plugin>
