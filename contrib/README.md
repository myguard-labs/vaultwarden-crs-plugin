# contrib/ — edge hardening for Vaultwarden

The CRS plugin is the **WAF half** of the defence. This directory holds the
**edge half**: a reference Angie / nginx reverse-proxy vhost that hardens
Vaultwarden natively, with no per-request ModSecurity cost — and does the
things ModSecurity can't or shouldn't.

## `angie/vault.conf`

A production-shaped, heavily-commented vhost. What it adds:

| Hardening | How | Why not in the CRS plugin |
|---|---|---|
| **Path allowlist → 404** | explicit `location` blocks for every real Vaultwarden route + a default-deny `location / { return 404; }` | The plugin does this in the WAF (rule 9530230); doing it natively at the edge is free per request and works even without ModSecurity. |
| **Method allowlist → 405** | `map $request_method` + `if` | Cheaper at the edge; mirrors plugin rule 9530220. |
| **Per-endpoint rate limiting** | `limit_req_zone` on `/admin`, `/identity/connect/token`, register, send-download | **Can't be done in the plugin** — libmodsecurity3 (v3) has no persistent per-IP collections. Rate limiting *must* live at the edge (or fail2ban). |
| **Security headers** | HSTS, nosniff, frame-options, CSP, referrer-policy | Response-header policy belongs at the proxy. |
| **Body-size / timeout / conn caps** | `client_max_body_size`, `limit_conn`, timeouts | Edge resource controls. |
| **WebSocket** for the notifications hub | `Upgrade`/`Connection` on `/notifications/` | — |

The route map is derived from Vaultwarden's source (`src/api/mod.rs` mount
points + `src/api/web.rs` static routes), the same source-verified map the CRS
plugin uses.

### Install sketch

1. Move the `limit_req_zone` / `map` / `upstream` blocks to your `http{}`
   scope (a `conf.d/` snippet), or keep them at the top of the file if your
   include order puts this file at `http{}` level.
2. Drop `snippets/vault_proxy.conf` at `/etc/nginx/snippets/vault_proxy.conf`.
3. Set `server_name`, the `upstream` backend address, and the cert paths.
4. Optionally enable ModSecurity + the CRS plugin in the same vhost (the
   commented `modsecurity_rules` block) to run **both** layers.
5. `nginx -t` / `angie -t`, then reload.

### Tuning

Rate limits ship **conservative**. Mobile/desktop clients can burst on first
sync — watch the access log for `429`s and loosen the relevant zone. Pair with
**fail2ban** on the Vaultwarden log for distributed slow brute-force that
per-IP `limit_req` can't catch.

## See also

- Plugin README: [`../README.md`](../README.md)
- Vaultwarden: <https://github.com/dani-garcia/vaultwarden>
- Write-up: <https://deb.myguard.nl/2026/05/self-hosted-password-manager-with-vaultwarden/>
