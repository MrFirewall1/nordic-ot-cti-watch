# Nordic OT CTI Watch

**Early warning on ransomware leak site claims and ICS advisories that matter to Nordic organisations and operational technology.**

[![tests](https://github.com/MrFirewall1/nordic-ot-cti-watch/actions/workflows/tests.yml/badge.svg)](https://github.com/MrFirewall1/nordic-ot-cti-watch/actions/workflows/tests.yml)
![python](https://img.shields.io/badge/python-3.11%2B-blue)
![deps](https://img.shields.io/badge/dependencies-none-brightgreen)
![license](https://img.shields.io/badge/license-MIT-lightgrey)

Hundreds of organisations are listed on ransomware leak sites every month. Most of them are not relevant to a Nordic OT defender. This tool filters the noise and answers one question: **did something just happen to an organisation in the Nordics, in an OT relevant sector, or on my watchlist?**

It is a small, dependency free Python tool that runs every hour in GitHub Actions (or a lab VM) and sends what matters to Telegram, Slack, Teams or Discord.

## What it does

```
┌──────────────────────────┐     ┌───────────────────────────┐
│ ransomware.live API      │     │ CISA ICS advisories (RSS) │
│ recent + NO SE DK FI IS  │     │                           │
└────────────┬─────────────┘     └─────────────┬─────────────┘
             │                                 │
             ▼                                 ▼
┌───────────────────────────────────────────────────────────┐
│ Triage                                                    │
│  CRITICAL  watchlist match (employer, customer, supplier) │
│  HIGH      Nordic victim in an OT relevant sector         │
│  MEDIUM    other Nordic victim / watched ICS vendor       │
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
| [ransomware.live](https://www.ransomware.live) API v2 | Victims claimed on ransomware leak sites, with country and sector | Early signal that an organisation may be compromised |
| [CISA ICS advisories](https://www.cisa.gov/news-events/cybersecurity-advisories) | New vulnerabilities in industrial products | Flags advisories for vendors common in Nordic OT (Siemens, ABB, Danfoss, Schneider Electric, Kongsberg and others) |

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

**GitHub Actions (hourly, runs in the cloud)**

`.github/workflows/watch.yml` runs every hour on GitHub's servers, so it keeps working when your own computer is off. Each run writes its report to the job summary, and state is kept in the Actions cache so you only get new items.

| Repository secret | Purpose |
|---|---|
| `TELEGRAM_BOT_TOKEN` | Bot token from [@BotFather](https://t.me/BotFather) |
| `TELEGRAM_CHAT_ID` | Your chat ID (see below) |
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

## Design choices

* **No Tor, no leak site access.** The tool only talks to public clearweb APIs. It drops the `.onion` claim URL from every record and links to the ransomware.live page instead. It never downloads leaked data.
* **No dependencies.** Standard library only, Python 3.11 or newer, so it runs on a fresh Ubuntu VM.
* **Claims are not facts.** Every report states that a leak site listing is a claim, not a confirmed breach. Verify before acting, and handle findings about named organisations responsibly.
* **Source labels can be wrong.** Country and sector come from ransomware.live and are sometimes inferred. A company can be tagged with the wrong country, or "Other" when it is clearly industrial. The tool therefore also checks the description for OT terms and tells you which rule fired.
* **One claim, one alert.** The same victim often appears in both the global and the per country feed with different field names. Items are deduplicated on group and victim name, and claims older than `max_age_days` are skipped so the first run does not flood you.
* **Secrets stay private.** `config.toml` is git ignored, and in GitHub Actions the watchlist, bot token and chat ID live in repository secrets.

## Responsible use

This tool is for defenders: SOC and CTI analysts, OT security teams and researchers who want early warning for their own organisation, customers or sector. If you find that an organisation is listed, contact them or the relevant national CERT (NSM NCSC in Norway, CERT-SE in Sweden, CFCS in Denmark, NCSC-FI in Finland) rather than publicising it.

## Related resources

* [deepdarkCTI](https://github.com/fastfire/deepdarkCTI) by fastfire: the best curated list of deep and dark web CTI sources (ransomware gang sites, forums, Telegram channels). Use it to go deeper on a group once this tool flags a claim.
* [ransomware.live](https://www.ransomware.live) by Julien Mousqueton: the data source behind the ransomware part of this tool.
* [Nordic Cold Chain Sabotage 2026](https://github.com/MrFirewall1/nordic-cold-chain-sabotage-2026): my case study on the refrigeration controller attacks in Sweden, Norway and Denmark.

## Roadmap

- [ ] More Nordic advisory feeds (NSM, CERT-SE, CFCS, NCSC-FI)
- [ ] Group context: link each claim to the group's entry in deepdarkCTI
- [ ] Simple HTML dashboard of findings over time

## License

MIT. Data belongs to the respective sources. Respect the ransomware.live terms and rate limits.
