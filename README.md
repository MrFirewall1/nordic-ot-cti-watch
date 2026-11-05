# Nordic OT CTI Watch

**Early warning on cyber attacks against Nordic operational technology and critical infrastructure: hacktivist announcements, attack news and ransomware claims.**

[![tests](https://github.com/MrFirewall1/nordic-ot-cti-watch/actions/workflows/tests.yml/badge.svg)](https://github.com/MrFirewall1/nordic-ot-cti-watch/actions/workflows/tests.yml)
![python](https://img.shields.io/badge/python-3.11%2B-blue)
![deps](https://img.shields.io/badge/dependencies-none-brightgreen)
![license](https://img.shields.io/badge/license-MIT-lightgrey)

Hundreds of organisations are listed on ransomware leak sites every month. Most of them are not relevant to a Nordic OT defender. This tool filters the noise and answers one question: **is someone attacking OT or critical infrastructure in the Nordics right now, or announcing that they will?**

It is a small, dependency free Python tool that runs every 30 minutes in GitHub Actions (or a lab VM) and sends what matters to Telegram, Slack, Teams or Discord.

## What it does

```
┌────────────────────┐ ┌────────────────────┐ ┌────────────────────┐
│ Hacktivist         │ │ Attack news + CERT │ │ ransomware.live    │
│ Telegram channels  │ │ (The Record, NRK,  │ │ leak site claims   │
│ (earliest signal)  │ │ SVT, DR, Yle, ...) │ │ NO SE DK FI IS     │
└─────────┬──────────┘ └─────────┬──────────┘ └─────────┬──────────┘
          └──────────────────────┼──────────────────────┘
                                 ▼
┌───────────────────────────────────────────────────────────┐
│ Triage                                                    │
│  CRITICAL  watchlist match (employer, customer, supplier) │
│  HIGH      Nordic target + OT / critical infra or known   │
│            hacktivist group; Nordic victim in OT sector   │
│  MEDIUM    OT attack elsewhere; other Nordic victim       │
│  LOW       everything else (dropped by default)           │
└────────────────────────────┬──────────────────────────────┘
                             ▼
            dedupe against state, only new items
                             ▼
   console · Markdown report · JSONL · Telegram · webhook
```

**Sources**

| Source | What | Why |
|---|---|---|
| Hacktivist Telegram channels (public web preview `t.me/s/<name>`) | Target lists and attack claims from groups such as NoName057(16), Z-Pentest, Sector 16 and TwoNet | The earliest public signal. Groups post targets when a campaign starts, often hours before it reaches the news |
| News and CERT feeds (The Record, BleepingComputer, SecurityWeek ICS/OT, Industrial Cyber, The Hacker News, CERT-SE, NRK, digi.no, SVT, DR, Yle) | Reported attacks | Confirms and adds context. Vulnerability, CVE and patch stories are dropped on purpose |
| [ransomware.live](https://www.ransomware.live) API v2 | Victims claimed on ransomware leak sites, with country and sector | Early signal that an organisation may be compromised |
| [CISA ICS advisories](https://www.cisa.gov/news-events/cybersecurity-advisories) via [cisagov/CSAF](https://github.com/cisagov/CSAF) | Vulnerabilities in industrial products | **Off by default** (`enable_ics_advisories`). Turn it on if you also want CVE alerts for watched vendors |

**OT relevant sectors** include energy and utilities, manufacturing, food and agriculture, transportation and logistics, water, oil and gas, chemicals, mining, maritime and aquaculture.

## Quick start

```bash
git clone https://github.com/MrFirewall1/nordic-ot-cti-watch.git
cd nordic-ot-cti-watch
cp config.example.toml config.toml        # add your watchlist here
python3 -m nordic_ot_cti_watch -c config.toml --dry-run
```

Example output:

```
🟠 [HIGH] Fjord Kraftverk AS (NO) claimed by examplegroup, sector: Energy & Utilities
🟠 [HIGH] Kraftstyrning Exempel AB (SE) claimed by countrygroup, sector: Other | OT relevant per description: power, automation
🟡 [MEDIUM] Nordic Fashion AB (SE) claimed by othergroup, sector: Retail & E-Commerce
🟡 [MEDIUM] ICS advisory: Siemens SIMATIC Example Controller
```

*(Fictional sample data from the test fixtures.)*

Drop `--dry-run` to save state, write a report to `reports/` and send webhook alerts. Run it again and only new items are shown.

| Option | Description |
|---|---|
| `-c config.toml` | Config file (see `config.example.toml`) |
| `--dry-run` | Do not write state, reports or send alerts |
| `--all` | Ignore state and show everything that matches |
| `--json` | Print matches as JSON |
| `--victims-file`, `--feed-file` | Read from local files instead of the network (offline testing) |

Exit codes: `0` nothing urgent, `1` HIGH or CRITICAL finding, `2` all sources failed. That makes it easy to chain into other tooling.

## Alerts

Set a webhook as an environment variable rather than in the config:

```bash
export CTI_WEBHOOK_URL="https://hooks.slack.com/services/..."
```

and set `webhook_format` to `slack`, `teams` or `discord`.

## Running it continuously

**Linux lab VM (systemd, hourly)**

```bash
sudo useradd --system --home /opt/nordic-ot-cti-watch cti
sudo git clone https://github.com/MrFirewall1/nordic-ot-cti-watch.git /opt/nordic-ot-cti-watch
sudo cp /opt/nordic-ot-cti-watch/config.example.toml /opt/nordic-ot-cti-watch/config.toml
sudo mkdir -p /opt/nordic-ot-cti-watch/{state,reports} && sudo chown -R cti /opt/nordic-ot-cti-watch
echo 'CTI_WEBHOOK_URL=https://...' | sudo tee /etc/nordic-ot-cti-watch.env && sudo chmod 600 /etc/nordic-ot-cti-watch.env
sudo cp /opt/nordic-ot-cti-watch/deploy/nordic-ot-cti-watch.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now nordic-ot-cti-watch.timer
```

**GitHub Actions (every 30 minutes, runs in the cloud)**

`.github/workflows/watch.yml` runs every 30 minutes on GitHub's servers, so it keeps working when your own computer is off. Each run writes its report to the job summary, and state is kept in the Actions cache so you only get new items.

| Repository secret | Purpose |
|---|---|
| `TELEGRAM_BOT_TOKEN` | Bot token from [@BotFather](https://t.me/BotFather) |
| `TELEGRAM_CHAT_ID` | Your chat ID (see below) |
| `CTI_TELEGRAM_CHANNELS` | Recommended. Comma separated public hacktivist channel names to watch (see below) |
| `CTI_WATCHLIST` | Optional. Comma separated organisation names, kept out of the public repo |
| `CTI_WEBHOOK_URL` | Optional. Slack, Teams or Discord webhook |

Note: GitHub pauses scheduled workflows in public repositories after 60 days without commits. Re-enable it from the Actions tab if that happens.

## Telegram alerts

1. In Telegram, open [@BotFather](https://t.me/BotFather), send `/newbot` and follow the steps. Copy the token.
2. Send any message to your new bot.
3. Open `https://api.telegram.org/bot<TOKEN>/getUpdates` in a browser and copy `"chat":{"id": ...}`.
4. Add both as repository secrets (Settings → Secrets and variables → Actions).
5. Actions → **watch** → **Run workflow** → tick *Only send a test alert*. You should get a message within a minute.

The first real run sends one summary ("Nordic OT CTI Watch is live") instead of a burst of alerts for the last two weeks. After that, each new item is one message:

```
🟠 HIGH: ransomware claim
Fjord Kraftverk AS (NO)
Group: examplegroup
Sector: Energy & Utilities
Why: Nordic victim (NO); OT relevant sector: Energy & Utilities
Discovered: 2026-11-02 02:05 UTC
ransomware.live
Unverified leak site claim.
```

If an alert cannot be delivered, the item stays unseen and is retried on the next run.

Locally, use the same environment variables and `--test-alert`:

```bash
export TELEGRAM_BOT_TOKEN=...  TELEGRAM_CHAT_ID=...
python3 -m nordic_ot_cti_watch --test-alert
```

## Hacktivist channels

Groups such as NoName057(16) announce each day's targets in public Telegram channels, and OT focused groups post screenshots and videos of HMIs they claim to control. Reading those channels is how you hear about an attack before the news does.

The watcher reads the public web preview at `https://t.me/s/<name>`: no Telegram account, no login, no joining. Channel names change often when Telegram bans them, so they are not hard coded. Find current names in [deepdarkCTI's Telegram list](https://github.com/fastfire/deepdarkCTI/blob/main/telegram_threat_actors.md) or your own CTI sources and put them in the `CTI_TELEGRAM_CHANNELS` secret, for example `channel_one,channel_two`. If a channel disappears, the run log says so and the other sources keep working.

Any post from a watched channel that names a Nordic country (in English, the Nordic languages or Russian) or a Nordic domain is HIGH. A post that mentions SCADA, PLC, HMI or similar is MEDIUM.

## Design choices

* **Attacks, not patches.** News about vulnerabilities, CVEs and patches is filtered out unless the headline is about an actual attack or exploitation.
* **No Tor, no leak site access.** The tool only talks to public clearweb APIs and pages. It drops the `.onion` claim URL from every record and links to the ransomware.live page instead. It never downloads leaked data.
* **No dependencies.** Standard library only, Python 3.11 or newer, so it runs on a fresh Ubuntu VM.
* **Claims are not facts.** Every report states that a leak site listing is a claim, not a confirmed breach. Verify before acting, and handle findings about named organisations responsibly.
* **Source labels can be wrong.** Country and sector come from ransomware.live and are sometimes inferred. A company can be tagged with the wrong country, or "Other" when it is clearly industrial. When the sector is missing or "Other", the tool falls back to the description, but only if it finds at least two different OT terms, so a municipality that mentions "transport" once is not flagged as OT. It always tells you which rule fired.
* **One claim, one alert.** The same victim often appears in both the global and the per country feed with different field names. Items are deduplicated on group and victim name, and claims older than `max_age_days` are skipped so the first run does not flood you.
* **Secrets stay private.** `config.toml` is git ignored, and in GitHub Actions the watchlist, bot token and chat ID live in repository secrets.

## Responsible use

This tool is for defenders: SOC and CTI analysts, OT security teams and researchers who want early warning for their own organisation, customers or sector. If you find that an organisation is listed, contact them or the relevant national CERT (NSM NCSC in Norway, CERT-SE in Sweden, CFCS in Denmark, NCSC-FI in Finland) rather than publicising it.

## Related resources

* [deepdarkCTI](https://github.com/fastfire/deepdarkCTI) by fastfire: the best curated list of deep and dark web CTI sources (ransomware gang sites, forums, Telegram channels). Use it to go deeper on a group once this tool flags a claim.
* [ransomware.live](https://www.ransomware.live) by Julien Mousqueton: the data source behind the ransomware part of this tool.
* [Nordic Cold Chain Sabotage 2026](https://github.com/MrFirewall1/nordic-cold-chain-sabotage-2026): my case study on the refrigeration controller attacks in Sweden, Norway and Denmark.

## Roadmap

- [ ] More Nordic feeds (NSM, CFCS, NCSC-FI, KraftCERT)
- [ ] Group context: link each claim to the group's entry in deepdarkCTI
- [ ] Simple HTML dashboard of findings over time

## License

MIT. Data belongs to the respective sources. Respect the ransomware.live terms and rate limits.
