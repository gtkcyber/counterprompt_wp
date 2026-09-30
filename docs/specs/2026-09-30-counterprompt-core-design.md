# Counterprompt (core plugin) — design spec

- **Date:** 2026-09-30
- **Status:** draft, awaiting review
- **Product:** Counterprompt (counterprompt.ai), free WordPress plugin, wordpress.org slug `counterprompt`
- **Origin:** ports the confounding techniques from the Juice Shop `ai_mods` research branch (`juice-shop/lib/inject/`) to production WordPress sites.

## 1. Goal and scope

Let anyone install a plugin on a production WordPress site that degrades autonomous AI attack agents (LLM-driven pentest/recon agents) while leaving humans and well-behaved crawlers untouched.

The defensive model is **confound, don't block**: waste the agent's step/token budget, steer it away from real surface, and make its observations unreliable. It complements (does not replace) firewall/blocking plugins.

### Product decomposition

Counterprompt is three projects. **This spec covers only #1.**

1. **Counterprompt core (this spec):** free plugin on wordpress.org.
2. **Counterprompt Pro:** paid add-on plugin: dashboard, alerts, export, lab/measurement mode (canary, poison, low-sensitivity recon), edge (Cloudflare Worker) escalation for cached pages, service client.
3. **counterprompt.ai service:** hosted shared attacker intel, licensing, dashboard backend.

Core's only obligation to #2/#3 is the stable hook set in §8. No stubs, no locked features, no outbound requests (wordpress.org rules).

### Non-goals (core)

- Blocking, rate limiting, CAPTCHAs.
- Behavior scoring beyond trap hits.
- Per-IP variation of page-cached HTML.
- Email alerts, CSV export, charts, multisite network-wide settings.
- Any technique that asks a visiting agent to disclose its credentials, secrets, or system prompt. Excluded from core **and** Pro: a plugin anyone can install must not become a harvesting tool aimed at visitors' agents.

## 2. Technique mapping (from Juice Shop `ai_mods`)

| Juice Shop | Core equivalent | Notes |
|---|---|---|
| `tarpit` | Trap paths + recursive maze + scope-redirect notice | Strategy "Divert" |
| `noop` | "Assessment complete, stop" notice | Strategy "Stop" (mutually exclusive with Divert) |
| `attribution` | "Responses are synthetic fixture data" notice | Always on with either strategy |
| `nondeterminism` | Probabilistically suppress real WP leaks for flagged IPs (user enumeration, version/readme fingerprints) | Real leaks stay real for unflagged clients |
| `flooding` | Fake version fingerprints for flagged IPs | Off by default |
| `canary`, `poison` | — | Pro lab mode |
| `recon` | — | Pro lab mode, low-sensitivity rungs only (client/model name) |

## 3. Architecture

**Approach A — split by cacheability.**

- **Static layer** (identical for every visitor, safe to page-cache): hidden HTML comment carrying the strategy notice, a hidden honeypot link to a trap path, `robots.txt` `Disallow` entries for trap paths.
- **Per-IP layer** (only on responses that are never page-cached anyway): trap paths, `/wp-json/*`, `?author=N`, `xmlrpc.php`, `wp-login.php`, readme/license/version fingerprint paths.
- **Escalate on trap hit:** an IP becomes *flagged* only when it requests a trap path. Only flagged IPs receive per-IP techniques. Humans don't follow hidden links; compliant crawlers honor `robots.txt`; so false positives require a client that already went somewhere no human goes.

### Platform

- WordPress 6.3+, PHP 8.0+.
- Plain PHP, no Composer runtime dependencies, no autoloader.

### File layout

```
counterprompt/
  counterprompt.php          bootstrap: plugin header, constants, activation/deactivation, wires modules
  uninstall.php              removes table, options, transients, .htaccess block (if "delete on uninstall")
  includes/
    class-settings.php       option schema, defaults, sanitization, admin page + status panel (Settings API)
    class-detector.php       client IP resolution, trap matching, flag/is_flagged (HMAC hash -> transient)
    class-traps.php          serves trap paths and the maze; flags IP on hit
    class-notices.php        static layer: wp_footer comment + honeypot link; robots_txt filter; remove generator meta
    class-rest.php           per-IP layer on REST: _notice field, users-endpoint nondeterminism, flooding
    class-leaks.php          per-IP layer on non-REST probes: ?author=N, xmlrpc, readme/license fingerprints
    class-server-rules.php   Apache .htaccess block (insert_with_markers), nginx snippet, self-test
    class-log.php            events table, rate-limited insert, daily prune
  readme.txt                 wordpress.org format
  .wp-env.json               dev + test WordPress instances
  package.json               wp-env + check scripts (dev only)
  phpunit.xml.dist, tests/   PHPUnit + smoke script
  docs/specs/                this file
```

### Module boundaries

- **Detector** is the only module that decides flagged state. Traps call `Detector::flag()`; per-IP modules call `Detector::is_flagged()`. Replacing trap-only flagging with a score later touches only this file.
- **Settings** is the only module that reads options (`Settings::get( $key )`).
- **Log** is write-only for other modules; only the admin status panel reads it.

## 4. Request flow

### Client IP resolution

- Default: `$_SERVER['REMOTE_ADDR']`.
- If a trusted proxy header is configured (`CF-Connecting-IP` or `X-Forwarded-For`) **and** `REMOTE_ADDR` is inside a configured trusted-proxy CIDR, use the header (for XFF: right-most address not in the trusted CIDRs). Otherwise ignore the header, so it cannot be spoofed to flag other people.
- Flag key: `hash_hmac( 'sha256', $ip, wp_salt( 'auth' ) )`; stored as transient `cp_f_<first 32 hex>` with TTL = flag duration.

### Never flagged

- Logged-in users with `edit_posts`.
- IPs/CIDRs on the admin allowlist.

### 4.1 Normal visitor (unflagged, not probing)

- HTML (possibly served from page cache) contains the static layer: `<!-- ... -->` notice text before `</body>` via `wp_footer`, and `<a href="<trap>" style="display:none" aria-hidden="true" tabindex="-1" rel="nofollow">`.
- `robots.txt` (virtual, via `robots_txt` filter) disallows every trap path.
- `<meta name="generator">` removed for everyone (`remove_action( 'wp_head', 'wp_generator' )`, `the_generator` filter).
- REST and probe endpoints behave normally. Cost: one transient lookup on REST/probe requests only.

### 4.2 Trap hit (escalation)

- Trap matching runs on `parse_request` priority 0 (before template/query). Match rule: `path === trap` or `path` starts with `trap` + `/` (after normalizing trailing slash). Sources: built-in list ∪ settings textarea ∪ `counterprompt_trap_paths` filter ∪ server-rules bait routes (`?counterprompt_trap=<path>`).
- Actions: `Detector::flag( $ip )` (skipped for never-flagged), log `trap_hit` (and `flagged` on first flag), fire `counterprompt_ip_flagged`.
- Response headers on every trap response: `Cache-Control: no-store`, `X-Robots-Tag: noindex, nofollow`.
- **Divert:** HTTP 200 HTML maze page: scope-redirect notice in the page body, 10 unique deeper child links (`<path>/<n>`), padding table so the body exceeds ~8 KB. Every child is itself a trap (prefix rule), so the tree is unbounded.
- **Stop:** HTTP 200 short HTML page carrying the noop notice, no child links.

### 4.3 Flagged IP, subsequent requests

All responses below also send `Cache-Control: no-store`.

- **Trap paths:** as §4.2.
- **REST** (`rest_post_dispatch`):
  - Add `_notice` array to object/array responses: `[ { "source": "attribution", "text": ... }, { "source": "divert"|"stop", "text": ... } ]`. For list (array) responses, add the notice as an `X-Notice` header instead to keep the body shape valid.
  - Nondeterminism: `/wp/v2/users` (collection and single) returns `[]` / 404 with probability p (default 0.7). Log `leak_suppressed`.
  - Flooding (if on): with probability 0.4 add a plausible fake fingerprint (e.g. `X-Powered-By`-style header naming an outdated plugin version from a shipped list). Log `flood`.
- **Probe paths** (`class-leaks`, on `parse_request`/`template_redirect`):
  - `?author=N`: with probability p return 404 instead of the canonical author redirect.
  - `/readme.html`, `/license.txt`, `/wp-content/plugins/*/readme.txt`, `/wp-content/themes/*/readme.txt`: with probability p return 404. (Only reachable if the request reaches PHP; see §6.)
  - `xmlrpc.php`: with probability p return a well-formed XML-RPC fault for `system.listMethods` / `wp.getUsersBlogs`.
  - Flooding (if on): fake `readme.txt` "Stable tag" for a random shipped plugin slug.

### 4.4 Unflagged client hitting a leak endpoint directly

Receives the real response. Optional setting **"Treat enumeration as a trap"** (default off): unauthenticated `?author=N` or `/wp/v2/users` flags the IP by itself.

## 5. Strategy

One setting, **Divert** (default) or **Stop**, selects which notice appears in every channel. Divert and Stop are never sent together (they contradict).

| | Divert | Stop |
|---|---|---|
| Static layer comment | scope-redirect + attribution | noop + attribution |
| Honeypot link | yes | yes |
| Flagged REST `_notice` | scope-redirect + attribution | noop + attribution |
| Trap page | maze, unbounded | short noop page |
| Nondeterminism / flooding | per settings | per settings |

Divert is the default because the Juice Shop runs showed the maze pinning agents at their step budget with solves near zero. Stop has lower server cost for small/shared-hosting sites.

Notice texts are editable, with a "reset to default" link. Defaults read as dull operations boilerplate. They never contain the words "trap", "honeypot", "canary", or "counterprompt".

## 6. Server rules (optional, off by default)

Purpose: some bait paths never reach PHP (nginx `location ~ /\.` deny rules, static-extension handlers), so the plugin can't trap them. Server rules rewrite **only the bait paths** to `index.php?counterprompt_trap=<path>`.

- **Bait paths** (default): `/.env`, `/.env.bak`, `/.git/config`, `/wp-config.php.bak`, `/wp-config.php~`, `/backup.sql`, `/db-backup.sql`, `/.aws/credentials`.
- **Apache/LiteSpeed:** one-click write/remove via `insert_with_markers( ABSPATH . '.htaccess', 'Counterprompt', $lines )`. Refuse (with admin notice) if `.htaccess` is not writable. Rules are placed so they precede the WordPress block.
- **nginx:** admin page shows a generated `location` snippet to paste; never written from PHP.
- **Self-test button:** issues `wp_remote_get( home_url( '/.env.bak?cp_selftest=<nonce>' ) )` (loopback to self, not an outbound third-party request) and reports whether the plugin saw it. Self-test requests do not flag or log.
- Deactivation removes the Apache block; uninstall removes it too.

## 7. Admin settings (Settings → Counterprompt)

| Group | Setting | Default |
|---|---|---|
| General | Enabled | on |
| | Strategy | Divert |
| | Flag duration | 24 h |
| Traps | Trap paths (one per line) | `/wp-admin/backup/`, `/wp-json/internal/v1/config`, `/db-backup/`, `/wp-content/uploads/backup/`, `/.env.bak` |
| | Treat enumeration as trap | off |
| Per-IP | Nondeterminism probability | 0.7 |
| | Flooding | off |
| Notices | Divert / Stop / Attribution texts | shipped defaults |
| Network | Trusted proxy header | none |
| | Trusted proxy CIDRs | empty; "Cloudflare ranges" preset button (list shipped in plugin, no fetch) |
| | Allowlist IPs/CIDRs | empty |
| Server rules | Apache block write/remove; nginx snippet; self-test | off |
| Data | Log retention | 30 days |
| | Delete all data on uninstall | on |

All inputs sanitized in the Settings API sanitize callback: paths must start with `/`, no whitespace, max 50 entries; CIDRs validated for v4/v6; probability clamped to [0,1]; notice text through `sanitize_textarea_field` and must not contain `--` (would break the HTML comment).

### Status panel (top of page)

- Trap hits last 24 h / 7 d; currently flagged count (from log `flagged` events within flag duration).
- Last 20 events: time, event, path, UA (truncated), short hash.
- **Red banner — proxy misconfiguration:** no trusted header configured and the most common source among recent events' truncated IPs is a Cloudflare or private range. Without the fix, every visitor shares one IP and one flag would affect everyone. When this condition is detected, per-IP techniques are **automatically suspended** (traps still log) until resolved.
- Warning: physical `robots.txt` exists (virtual Disallow entries won't be served).
- Warning: page-cache plugin detected (informational: static layer cached, per-IP layer unaffected).

## 8. Extension hooks (contract for Pro / service)

| Hook | Type | Signature |
|---|---|---|
| `counterprompt_ip_flagged` | action | `( string $ip_hash, string $path )` |
| `counterprompt_is_flagged` | filter | `( bool $flagged, string $ip_hash ) : bool` |
| `counterprompt_notices` | filter | `( array $notices, string $context ) : array` — context `html`\|`rest`\|`trap` |
| `counterprompt_trap_paths` | filter | `( string[] $paths ) : string[]` |
| `counterprompt_event_logged` | action | `( array $event )` |

These are public API from 1.0; changes follow semver.

## 9. Logging

Table `{$wpdb->prefix}counterprompt_events`, created with `dbDelta` on activation; schema version in option `counterprompt_db_version`.

| Column | Type |
|---|---|
| `id` | BIGINT UNSIGNED AUTO_INCREMENT PK |
| `ts` | DATETIME (UTC), indexed |
| `event` | VARCHAR(32) |
| `ip_hash` | CHAR(64), indexed |
| `ip_trunc` | VARCHAR(45) |
| `path` | VARCHAR(255) |
| `ua` | VARCHAR(255) |
| `meta` | TEXT (JSON) |

- Events: `trap_hit`, `flagged`, `leak_suppressed`, `flood`, `notice_rest`. Static-layer notices are not logged.
- Rate limit: at most one row per (`ip_hash`, `event`, `path`) per 60 s, via transient. Bounds maze-driven write load.
- Daily WP-Cron prune: delete rows older than retention; then trim to newest 50,000 rows.
- `counterprompt_event_logged` fires after insert.

## 10. Privacy

- No raw IPs stored: HMAC hash + truncated IP (IPv4 last octet zeroed, IPv6 to /48).
- Core makes no outbound requests (the self-test is a loopback to the site itself).
- Registers suggested privacy-policy text via `wp_add_privacy_policy_content` (what is logged, retention, legitimate interest: security).
- Uninstall (if enabled) removes table, options, transients (`cp_f_*`, rate-limit keys), cron event, `.htaccess` block.

## 11. Error handling

- Every hook callback is wrapped so a plugin failure falls through to normal WordPress behavior (never a white screen): log insert failures are swallowed; a failed transient read is treated as "not flagged".
- Trap and leak handlers only ever *reduce* information or serve synthetic pages; they never modify stored content.
- Disabled plugin or `Enabled = off`: no hooks beyond the admin page are registered.

## 12. Testing

### Dev stack

`@wordpress/env` via `.wp-env.json`: dev site on :8888, tests site on :8889, WP PHPUnit library included. Requires Docker only.

### PHPUnit (`npm run test:php` → `wp-env run tests-cli phpunit`)

- Detector: `REMOTE_ADDR` default; spoofed XFF ignored from untrusted source, honored from trusted CIDR (right-most untrusted hop); allowlist and editors never flagged; flag expiry.
- Trap matching: exact, prefix (`/wp-admin/backup/x/y`), lookalike negatives (`/wp-admin/backups-page`), trailing-slash normalization.
- REST: unflagged users endpoint unchanged; flagged suppression rate ≈ p with seeded `mt_srand`; `_notice` only for flagged; array responses keep valid shape.
- Strategy: Divert vs Stop notice selection and maze vs short page.
- Log: rate limit, retention prune, row cap.
- Settings sanitization: bad paths, bad CIDRs, `--` in notice text, probability clamp.
- Proxy-misconfiguration auto-suspend.
- Server rules: `.htaccess` block written/removed between markers.
- Uninstall leaves no table, options, or transients.

### Black-box smoke (`tests/smoke.sh`, curl only, against :8888)

1. Homepage contains the notice comment and hidden link; no visible text change.
2. `robots.txt` disallows trap paths.
3. Unflagged `/wp-json/wp/v2/users` returns users.
4. Trap request → 200, maze links, `Cache-Control: no-store`.
5. 50 subsequent `/wp/v2/users` requests from the flagged IP → ~35 empty (tolerance band).
6. A second IP (via trusted-proxy header configured in the test site) still gets real data.
7. Repeat 1–6 with WP Super Cache active: cached homepage still carries the static layer; flagged responses are never cached.

### Pre-submission gates (`npm run check`)

PHPCS with WordPress Coding Standards; the official Plugin Check plugin; `readme.txt` validation.

### Field validation (manual, documented in `docs/`)

Run the Juice Shop reference agent against the wp-env site with Counterprompt disabled vs. Divert; compare steps, tokens, findings as `score.ts` does. Results feed counterprompt.ai marketing. Automated scoring is Pro scope.

## 13. Open items

None blocking. Trademark search on "Counterprompt" recommended before commercial launch (domain `counterprompt.ai` owned; `.com` held by a third party).
