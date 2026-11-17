# DAT — Digital Apocalypse Tracker

A self-updating website that tracks major cyber attacks and major outages: when each one happened, what was hit, and the alleged reason.

Nothing runs on your computer. Everything runs free on GitHub:

```
 every 15 min                                       on every push
┌──────────────┐   fetch 23 feeds   ┌───────────┐   commit   ┌──────────────┐
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
| Outages (official status pages) | AWS, Google Cloud, Slack, GitHub, Cloudflare, Discord, Reddit, OpenAI, Anthropic, Zoom, Twilio, DigitalOcean, Vercel, Shopify, Dropbox |

Add or remove sources in [config/sources.json](config/sources.json). Any Atlassian Statuspage site (most `status.company.com` pages) works with `"type": "statuspage"`, and any RSS/Atom feed works with `"type": "rss"`.

Status-page incidents are re-read every sweep, so the "ongoing" flag, resolution time and cause update as the provider posts updates or a postmortem.

## How news is triaged

- **With an Anthropic API key (recommended):** each new article is sent to Claude, which throws out noise (opinion, research, arrests, vendor news), names the target, pulls out the incident's real start time and the alleged cause, names the group blamed, scores severity 1–5, and gives a dedupe key so five articles about one breach become one event with five sources.
- **Without a key:** keyword heuristics do the same job less well. It works, but expect some noise and generic "cause not yet disclosed" text.

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
