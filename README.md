# DAT — Digital Apocalypse Tracker

A self-updating website that tracks major cyber attacks and major outages: when each one happened, what was hit, and the alleged reason.

Nothing runs on your computer. Everything runs free on GitHub:

```
 every 15 min                                       on every push
┌──────────────┐   fetch 25 sources   ┌───────────┐   commit   ┌──────────────┐
│GitHub Actions│ ─────────────────▶ │collector/ │ ─────────▶ │ data/*.json  │ ──▶ GitHub Pages site
│  (cron)      │                    │  dat.py   │            │ (in the repo)│     (index.html reads it,
└──────────────┘                    └─────┬─────┘            └──────────────┘      refreshes every 5 min)
                                          │ new news items only
                                          ▼
                                   Claude (optional): is this a major incident?
                                   category, target, start time, alleged cause,
                                   attributed group, severity, dedupe key
```

## Where the data comes from

| Kind | Sources |
|---|---|
| Cyber news | BleepingComputer, The Record, The Hacker News, Krebs on Security, SecurityWeek, DataBreaches.net, The Register, CISA advisories |
| Outage news | Google News search for nationwide / global / widespread / IT / network outages and ground stops (covers airlines, banks, telecoms, government systems) |
| Outages (official status pages) | AWS, Google Cloud, Slack, GitHub, Cloudflare, Discord, Reddit, OpenAI, Anthropic, Zoom, Twilio, DigitalOcean, Vercel, Shopify, Dropbox |
| Air traffic | FAA National Airspace System status (live ground stops) |
| Manual | [config/manual_events.json](config/manual_events.json): events you add by hand, e.g. anything the feeds missed |

Add or remove sources in [config/sources.json](config/sources.json). Any Atlassian Statuspage site (most `status.company.com` pages) works with `"type": "statuspage"`, and any RSS/Atom feed works with `"type": "rss"`.

Status-page incidents are re-read every sweep, so the "ongoing" flag, resolution time and cause update as the provider posts updates or a postmortem.

## What gets posted

Every incident gets a severity from 1 to 5. **Only severity 3 and above reaches the site** (`publish_min_severity` in `config/sources.json`).

**Status-page outages** start at 3 if the provider calls the incident critical (2 if major; anything lower is never read), then:

| Rule | Effect |
|---|---|
| Lasted (or has been running) 2+ hours | +1 |
| Over in under 30 minutes | −1 |
| Title says it hit only part of the service ("some users", "Sign in with Apple", billing, webhooks, voice, free plan, delays, latency…) | −1 |
| Only one component affected and not described as a broad outage | −1 |

So a "major" incident has to be broad *and* last two hours to appear. A small Dropbox sign-in issue scores 1 and is never posted. AWS posts only declared "service disruptions"; Slack needs 3+ services hit.

**FAA ground stops** count only when the stated reason is a system failure (equipment, communications, power, software…), never weather, traffic volume or runway work, and only when 3+ airports are stopped. 10+ airports or a nationwide stop is severity 5.

**News** is scored by Claude against the bar "would a well-informed member of the public recognise this as big news?": broad multi-hour outages, 100,000+ people affected, critical infrastructure or government disrupted, or a confirmed attack on a major organisation. Follow-up coverage (costs, politics, blame, recovery stories) is merged into the original incident or dropped.

Changing the rules? Bump `RULES_VERSION` in `collector/dat.py` and the next sweep rebuilds the whole feed under the new rules.

## How news is triaged

- **With an Anthropic API key (recommended):** each new article is sent to Claude, which throws out noise (opinion, research, arrests, vendor news), names the target, pulls out the incident's real start time and the alleged cause, names the group blamed, scores severity 1–5, and gives a dedupe key so five articles about one breach become one event with five sources.
- **Without a key:** keyword heuristics do the same job less well: stricter headline patterns, organisation-name matching to merge duplicates, and a rough affected-count score. Expect the occasional miss or stray story, and generic "cause not yet disclosed" text.

The page footer shows which mode is running.

## Setup

1. Push this folder to a GitHub repo (public, so Pages is free).
2. **Settings → Pages →** Source: *Deploy from a branch*, Branch: `main`, folder `/ (root)`.
3. **Settings → Actions → General →** Workflow permissions: *Read and write*.
4. *(Optional)* **Settings → Secrets and variables → Actions:**
   - Secret `ANTHROPIC_API_KEY` — turns on Claude triage.
   - Variable `DAT_MODEL` — defaults to `claude-opus-5-5`. Set `claude-haiku-5-5` to cut cost by roughly 40×.
5. **Actions → Sweep feeds → Run workflow** once to start it. After that it runs every 15 minutes on its own.

## Run locally

```bash
python3 collector/dat.py          # writes data/events.json and data/status.json
python3 -m http.server 8000       # then open http://localhost:8000
```

## Files

| Path | What it is |
|---|---|
| `collector/dat.py` | Sweeps sources, classifies, dedupes, writes data. Standard library only (+ `anthropic` if a key is set). |
| `config/sources.json` | Source list and the status-page impact threshold. |
| `data/events.json` | Public event feed (last 60 days). Other sites can read it too. |
| `data/status.json` | Last sweep time, threat level, per-source health. |
| `data/seen.json` | Articles already processed, so Claude never sees the same one twice. |
| `index.html`, `assets/` | The site. Static, no build step. |
| `.github/workflows/collect.yml` | The 15-minute sweep. |
| `.github/workflows/keepalive.yml` | Monthly safety net that re-enables the schedule if GitHub ever pauses it. |

## Tuning

- `statuspage_min_impact` in `config/sources.json`: `major` (default) or `critical` for only the biggest outages, `minor` for everything.
- `DAT_KEEP_DAYS` env var: how many days of history to keep (default 60).
- Threat-level thresholds live in `threat_level()` in `collector/dat.py`.
