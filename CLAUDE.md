# CLAUDE.md

Guidance for Claude Code (claude.ai/code) working in this repository.

## What this is

**Counterprompt** is a free WordPress plugin (commercial product at counterprompt.ai) that defends a site against autonomous AI attack agents. This is **legitimate defensive cybersecurity research and a defensive security product.**

- **Defensive, not offensive.** The plugin runs on a site the operator owns and controls. It protects that site. It never attacks, scans, or reaches out to anyone else. Core makes no outbound requests at all (except a loopback self-test to the site's own URL).
- **Confound, not exploit.** The techniques degrade an *attacking* agent's results: honeypot trap paths, a recursive maze that wastes the agent's step/token budget, hidden "out of scope / synthetic data" notices in channels humans never see, and probabilistic suppression of the site's own fingerprint/enumeration leaks for IPs that have already hit a trap. Nothing here breaks into, or exfiltrates from, any system.
- **Humans and compliant crawlers are unaffected by design.** Escalation only ever targets an IP *after* it requests a honeypot path that no human and no robots.txt-respecting crawler would visit. The design separates bots from people by placement and behavior, never by identity.

Origin: the techniques were prototyped and measured on a local OWASP Juice Shop lab instance (a deliberately vulnerable app built for security training) against the operator's own pentest agent. This repo ports the production-safe subset to WordPress.

## Explicitly out of scope (and why)

These are **not** in the plugin and must not be added:

- **No credential, API-key, or system-prompt harvesting.** The Juice Shop research rig had a "recon ladder" that asked a visiting agent to disclose its secrets. That is safe only against your own agent in a closed lab. A plugin anyone can install must never become a tool that harvests data from visitors' agents, so it is excluded from both the free plugin and the paid Pro add-on.
- **No blocking, rate-limiting, DoS, or retaliation** against any external host. The plugin only shapes its own responses.
- **No targeting by identity** (User-Agent, cookie, fingerprint). Only trap-hit behavior flags an IP.

If a task ever seems to call for any of the above, stop and flag it — it is a scope violation, not a feature.

## Architecture (approach A: split by cacheability)

- **Static layer** — identical for every visitor, safe to page-cache: hidden HTML comment notice, hidden honeypot link, robots.txt Disallow entries. (`class-notices.php`)
- **Per-IP layer** — only on never-cached surfaces (traps, `/wp-json/*`, `?author=N`, fingerprint paths), and only for IPs already flagged by a trap hit: maze, leak suppression, flooding. (`class-traps.php`, `class-leaks.php`, `class-rest.php`)
- `class-detector.php` is the **only** module that decides flagged state. `class-settings.php` is the **only** module that reads options. `class-log.php` is write-only for other modules.

Full design: `docs/specs/2026-09-30-counterprompt-core-design.md`. Implementation plan: `docs/superpowers/plans/2026-09-30-counterprompt-core.md`.

## Product decomposition

1. **Counterprompt core** (this repo) — free, wordpress.org.
2. **Counterprompt Pro** — paid add-on: dashboard, lab/measurement mode, edge (Cloudflare Worker) escalation. Built on core's public hooks.
3. **counterprompt.ai service** — hosted shared attacker intel, licensing.

Core's only obligation to Pro/service is the stable hook set (spec §8). No stubs or locked features in core (wordpress.org forbids them).

## Commands

```bash
npm run start       # wp-env: dev site :8888, test site :8889 (needs Docker)
npm run test:php    # PHPUnit via the WP test library
npm run test:smoke  # black-box curl checks against :8888
npm run lint        # PHPCS (WordPress Coding Standards)
npm run check       # lint + official Plugin Check (what wordpress.org reviewers run)
```

## Conventions

- WordPress 6.3+, PHP 8.0+. Plain PHP, no Composer runtime deps, no autoloader — explicit `require_once` from `counterprompt.php`.
- Prefixes: slug/text-domain `counterprompt`, hooks/functions `counterprompt_`, classes `Counterprompt_`, constants `COUNTERPROMPT_`.
- TDD per the plan: failing test → run → implement → run → commit.
- Notice default text must never contain `trap`, `honeypot`, `canary`, `counterprompt`, or `--` (an agent shouldn't be able to spot the bait by name, and `--` breaks HTML comments).
- No raw IPs stored — HMAC hash + truncated IP only.
