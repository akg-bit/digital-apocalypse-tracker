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
| Wire & general news | Google News searches for cyberattacks, ransomware, hacks and data breaches (catches Reuters/AP wire stories hours before security outlets), and for nationwide / global / widespread / IT / network outages and ground stops (covers airlines, banks, telecoms, government systems) |
| Outages (official status pages) | AWS, Google Cloud, Slack, GitHub, Cloudflare, Discord, Reddit, OpenAI, Anthropic, Zoom, Twilio, DigitalOcean, Vercel, Shopify, Dropbox |
| Air traffic | FAA National Airspace System status (live ground stops) |
| Manual | [config/manual_events.json](config/manual_events.json): events you add by hand, e.g. anything the feeds missed |

Add or remove sources in [config/sources.json](config/sources.json). Any Atlassian Statuspage site (most `status.company.com` pages) works with `"type": "statuspage"`, and any RSS/Atom feed works with `"type": "rss"`.

Status-page incidents are re-read every sweep, so the "ongoing" flag, resolution time and cause update as the provider posts updates or a postmortem.

## Severity: what gets posted

Every incident, from news or a status page, is scored 0–3 on five questions. The total (0–15) becomes severity 1–5, and **only severity 3 and above is posted** (`publish_min_severity` in `config/sources.json`). Each card on the site has a "Why severity N?" panel showing the breakdown.

| Question | 0 | 1 | 2 | 3 | Answered by |
|---|---|---|---|---|---|
| **Reach**: how many were hit? | one small org / a few thousand people | one large org, up to ~1M people, a city | millions, a region, a whole sector | a country or the world | Claude |
| **Critical system**: what was hit? | entertainment, gaming | business, dev & consumer apps, personal data | banking, payments, telecom, cloud/CDN/DNS, major media | aviation, healthcare, energy, water, emergency services, defence, government | Claude |
| **Impact**: how badly? | slowdown or near miss | some features or users; breached but running | main service down; sensitive data exposed | total outage; data stolen at scale; encrypted; operations halted | Claude |
| **Duration** | under an hour | hours | about a day | days | measured from timestamps (Claude for news) |
| **News coverage** | status page only | 1–2 outlets | 3–9 outlets | 10+ outlets | counted from merged sources |

| Total | 0–4 | 5–6 | 7–8 | 9–11 | 12–15 |
|---|---|---|---|---|---|
| Severity | 1 | 2 | **3 (posted)** | 4 | 5 |

Two hard rules come after the total:
- **No news coverage, no severe rating.** An incident only on a status page is capped at 3, unless it hit a critical system (an official FAA ground stop matters before the press catches up).
- **Critical systems are never minor.** A confirmed attack on, or a real outage of, aviation, healthcare, energy, emergency services or government is at least 3.

Coverage is what lets a story grow: a breaking incident with one source can start below the bar and be posted once more outlets report it. Incidents below the bar are kept in `data/candidates.json` for that reason.

Examples: a 3½-hour Slack loading problem with no news coverage scores 1+1+1+1+0 = 4 → severity 1 (not posted). Equinor's attack on some IT systems scores 1+3+1+1+3 = 9 → severity 4. The FAA nationwide ground stop scores 3+3+3+2+3 = 14 → severity 5.

**Disagree with a rating?** Add an override to `config/manual_events.json`:
```json
"overrides": [{ "match": "Slack: Trouble loading", "severity": 2, "note": "partial, no wider impact" }]
```
Any incident whose headline contains `match` gets that severity, and the card says it was set by hand.

**Without an API key**, keyword rules answer the Claude questions (per-provider `criticality` in `config/sources.json`, scope words in the title, affected head counts in the text). It works, but less precisely.

**FAA ground stops** count only when the stated reason is a system failure (equipment, communications, power, software…), never weather, traffic volume or runway work, and only when 3+ airports are stopped.

Changing the rules? Bump `RULES_VERSION` in `collector/dat.py` and the next sweep rebuilds the whole feed under the new rules.

## How news is triaged

- **With an Anthropic API key (recommended):** each new article is sent to Claude, which throws out noise (opinion, research, arrests, vendor news), names the target, pulls out the incident's real start time and the alleged cause, names the group blamed, answers the severity rubric, and gives a dedupe key so five articles about one breach become one event with five sources.
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

## Backup trigger (if GitHub's schedule stalls)

GitHub's scheduled runs are best-effort: on new repos they can take a day or more to start, and they get delayed or skipped when GitHub is busy. A free external timer guarantees the 15-minute sweep by asking GitHub's API to run the workflow. Runs never overlap (`concurrency: sweep`), so the timer and GitHub's own schedule can both be on.

1. **Token:** GitHub → Settings → Developer settings → Personal access tokens → **Fine-grained tokens** → Generate new token.
   - Repository access: *Only select repositories* → this repo.
   - Repository permissions: **Actions → Read and write** (nothing else).
   - Expiration: the longest offered. Note the date; the timer stops working when it expires.
2. **Timer:** a free account at [cron-job.org](https://cron-job.org) → Create cronjob.
   - URL: `https://api.github.com/repos/<owner>/<repo>/actions/workflows/collect.yml/dispatches`
   - Schedule: every 15 minutes (minutes 7, 22, 37, 52 match the workflow's own schedule).
   - Advanced → Request method **POST**, request body `{"ref":"main"}`, headers:
     - `Accept: application/vnd.github+json`
     - `Authorization: Bearer <your token>`
     - `X-GitHub-Api-Version: 2022-11-28`
     - `Content-Type: application/json`
   - Notifications: on failure, so an expired token gets noticed.
3. **Test run** in cron-job.org should return **HTTP 204**, and a new "Sweep feeds" run appears under the repo's Actions tab.

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
| `data/candidates.json` | Every scored incident, including those below the bar (so they can rise with coverage). |
| `data/scores.json` | Claude's rubric answers for status-page incidents, reused until the incident changes. |
| `data/seen.json` | Articles already processed, so Claude never sees the same one twice. |
| `index.html`, `assets/` | The site. Static, no build step. |
| `.github/workflows/collect.yml` | The 15-minute sweep. |
| `.github/workflows/keepalive.yml` | Monthly safety net that re-enables the schedule if GitHub ever pauses it. |

## Tuning

- `statuspage_min_impact` in `config/sources.json`: `major` (default) or `critical` for only the biggest outages, `minor` for everything.
- `DAT_KEEP_DAYS` env var: how many days of history to keep (default 60).
- Threat-level thresholds live in `threat_level()` in `collector/dat.py`.
