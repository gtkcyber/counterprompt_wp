=== Counterprompt ===
Contributors: cgivre
Tags: security, ai, bots, honeypot, crawler
Requires at least: 6.3
Tested up to: 6.8
Requires PHP: 8.0
Stable tag: 0.1.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Defends your site against autonomous AI attack agents with honeypot paths and per-IP confounding. Humans and compliant crawlers are unaffected.

== Description ==

Counterprompt is a defensive plugin for sites you own. It makes automated AI attack agents waste effort and produce unreliable results, without affecting real visitors.

**Static layer (safe for page caches).** Every visitor gets the same output: a hidden HTML comment notice, a hidden honeypot link, and robots.txt Disallow entries pointing at bait paths.

**Per-IP layer (never cached surfaces only).** Once a client requests a bait path that no human and no robots.txt-respecting crawler would visit, its IP is flagged for a limited time. For flagged IPs only, Counterprompt can serve a recursive maze of dead-end pages, probabilistically suppress the site's own version fingerprints and user enumeration responses, and optionally send decoy version headers.

What it does not do: it never blocks or rate-limits external hosts, never reaches out to anyone, and never targets visitors by User-Agent or other identity. Only trap-hit behavior flags an IP.

Features:

* Configurable bait paths and notice text
* Flag lifetime, allowlist and reverse proxy (CIDR) support
* Event log with hashed IPs and automatic pruning
* Optional Apache .htaccess rules and an nginx snippet
* Clean uninstall

== Installation ==

1. Upload the plugin to `/wp-content/plugins/counterprompt` or install it from the Plugins screen.
2. Activate it. Defaults work out of the box.
3. Review the settings under Settings > Counterprompt. If you run behind a proxy or CDN, set the proxy header and trusted proxy ranges so client IPs are detected correctly.

**Behind a CDN you must set the trusted proxy header and CIDRs.** Otherwise every visitor appears to share the CDN's IP. Counterprompt auto-suspends per-IP techniques when it detects this, but that is a safety net with a brief cold start: the first few trap hits can be affected before suspension engages.

== Frequently Asked Questions ==

= What are the requirements for the traps to work? =

Honeypot traps need pretty permalinks, or the optional server rules. Otherwise your webserver may return 404 for trap paths before WordPress sees them.

= Will this affect my human visitors? =

No. Per-IP techniques only fire after a client requests a honeypot path. Humans and compliant crawlers never visit those paths, because the links are hidden and robots.txt tells well-behaved crawlers to stay away. Everyone else sees the normal site.

= Does it send my data anywhere? =

No. Core makes no outbound requests. The only request it makes is an optional loopback self-test to your own site URL, which you start from the settings page.

= Can the enumeration setting flag a real person? =

Yes, in one case. The optional "treat enumeration as a trap" setting flags any client that requests an author archive by number, such as an old `?author=N` link. A real visitor who follows one of those links could be flagged. It is off by default, and you can add trusted IPs to the allowlist.

= Does it harvest credentials or data from visitors? =

No. It only shapes the responses your own site sends.

= How long is an IP flagged? =

For the configured flag lifetime (24 hours by default), then the flag expires on its own.

= What is removed on uninstall? =

If "Delete data on uninstall" is on (the default), the events table, settings, scheduled task, transients and any .htaccess block are removed.

== Changelog ==

= 0.1.0 =
* Initial release: honeypot traps, hidden notices, per-IP maze and leak suppression, admin settings, event log, optional server rules, clean uninstall.

== Privacy ==

Counterprompt stores an event log in your database for flagged requests. IP addresses are not stored raw: only a keyed HMAC hash and a truncated IP are kept. Log entries are pruned after the configured retention period (30 days by default). No data is sent to any external service. All data is deleted on uninstall unless you turn that option off.
