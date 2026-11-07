"""Configuration loading. Uses TOML (stdlib tomllib, Python 3.11+)."""
from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_COUNTRIES = ["NO", "SE", "DK", "FI", "IS"]

# Substrings matched (case insensitive) against the ransomware.live "activity" field and the
# victim description. Covers the sector labels ransomware.live uses, e.g. "Energy & Utilities",
# "Manufacturing", "Agriculture and Food Production", "Transportation".
DEFAULT_OT_SECTORS = [
    "energy", "utilit", "power", "hydro", "grid", "heating", "manufactur", "industrial",
    "automation", "refrigerat", "agricultur", "food", "dairy", "transport", "logistic",
    "water", "oil", "gas", "chemical", "mining", "maritime", "shipping", "aquaculture",
]

DEFAULT_ICS_VENDORS = [
    "Siemens", "Danfoss", "Copeland", "Dixell", "Schneider Electric", "ABB", "Hitachi Energy",
    "Rockwell", "Phoenix Contact", "Moxa", "Mitsubishi Electric", "Honeywell", "Emerson",
    "Johnson Controls", "Kongsberg", "Wago", "Beckhoff",
]

# Attack news. "country" marks a Nordic source whose articles rarely name their own country.
DEFAULT_NEWS_FEEDS = [
    {"name": "The Record", "url": "https://therecord.media/feed/"},
    {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/"},
    {"name": "SecurityWeek ICS/OT", "url": "https://www.securityweek.com/category/ics-ot/feed/"},
    {"name": "Industrial Cyber", "url": "https://industrialcyber.co/feed/"},
    {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"name": "CERT-SE", "url": "https://www.cert.se/feed.rss", "country": "SE"},
    {"name": "Traficom NCSC-FI", "url": "https://www.kyberturvallisuuskeskus.fi/feed/rss/fi", "country": "FI"},
    {"name": "SAMSIK (DK)", "url": "https://samsik.dk/feed/", "country": "DK"},
    {"name": "MCF (SE)", "url": "https://www.mcf.se/sv/rss-floden/rss-alla-nyheter-fran-myndigheten-for-civilt-forsvar/", "country": "SE"},
    {"name": "NRK", "url": "https://www.nrk.no/toppsaker.rss", "country": "NO"},
    {"name": "digi.no", "url": "https://www.digi.no/rss", "country": "NO"},
    {"name": "SVT", "url": "https://www.svt.se/nyheter/rss.xml", "country": "SE"},
    {"name": "DR", "url": "https://www.dr.dk/nyheder/service/feeds/allenyheder", "country": "DK"},
    {"name": "Yle", "url": "https://feeds.yle.fi/uutiset/v1/recent.rss?publisherIds=YLE_UUTISET", "country": "FI"},
]

# Background reading for the daily digest (no Nordic requirement, not instant alerts).
DEFAULT_CONTEXT_FEEDS = [
    {"name": "SecPost", "url": "https://secpost.ru/feed"},
    {"name": "Industrial Cyber", "url": "https://industrialcyber.co/feed/"},
    {"name": "The Record", "url": "https://therecord.media/feed"},
]


@dataclass
class Config:
    countries: list[str] = field(default_factory=lambda: list(DEFAULT_COUNTRIES))
    ot_sectors: list[str] = field(default_factory=lambda: list(DEFAULT_OT_SECTORS))
    watchlist: list[str] = field(default_factory=list)
    ics_vendors: list[str] = field(default_factory=lambda: list(DEFAULT_ICS_VENDORS))
    min_priority: str = "MEDIUM"
    # Ignore leak site claims discovered more than this many days ago. The per country
    # endpoint returns the full history, so this keeps the first run from flooding.
    max_age_days: float = 14
    ransomware_api: str = "https://api.ransomware.live/v2"
    cisa_ics_feed: str = "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml"
    # "csaf" = CISA's CSAF repo on GitHub (works from cloud runners), "rss" = cisa.gov feed.
    ics_source: str = "csaf"
    ics_limit: int = 15
    enable_news: bool = False
    news_feeds: list[dict] = field(default_factory=lambda: [dict(f) for f in DEFAULT_NEWS_FEEDS])
    context_feeds: list[dict] = field(default_factory=lambda: [dict(f) for f in DEFAULT_CONTEXT_FEEDS])
    digest_hour_utc: int = 6      # send the daily digest on the first run at or after this UTC hour
    digest_max_items: int = 12
    # Public hacktivist channels read via t.me/s/<name>. Names change often, so they are set in
    # config or the CTI_TELEGRAM_CHANNELS secret rather than hard coded.
    telegram_channels: list[str] = field(default_factory=list)
    enable_ransomware: bool = True
    enable_ics_advisories: bool = True
    request_delay_seconds: float = 2.0
    timeout_seconds: float = 30.0
    state_file: str = "state/seen.json"
    report_dir: str = "reports"
    webhook_url: str = ""
    webhook_format: str = "slack"  # slack | teams | discord

    @classmethod
    def load(cls, path: str | Path | None) -> "Config":
        cfg = cls()
        if not path:
            return cfg
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"config file not found: {p}")
        data = tomllib.loads(p.read_text(encoding="utf-8"))
        for section in ("filters", "sources", "news", "output", "network"):
            for key, value in (data.get(section) or {}).items():
                if not hasattr(cfg, key):
                    raise ValueError(f"unknown config key [{section}].{key}")
                setattr(cfg, key, value)
        cfg.countries = [c.upper() for c in cfg.countries]
        cfg.min_priority = cfg.min_priority.upper()
        return cfg
