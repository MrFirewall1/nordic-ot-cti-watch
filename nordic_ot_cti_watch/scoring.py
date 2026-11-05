"""Triage: decide which items matter for a Nordic OT defender."""
from __future__ import annotations

import re
from dataclasses import dataclass

from .config import Config
from .sources import Advisory, Victim

PRIORITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def rank(p: str) -> int:
    return PRIORITIES.index(p)


def _match_terms(text: str, terms: list[str]) -> list[str]:
    hits = []
    for t in terms:
        if t and re.search(r"(?<![\w])" + re.escape(t) + r"(?![\w])", text, re.IGNORECASE):
            hits.append(t)
    return hits


def _sector_hits(text: str, sectors: list[str]) -> list[str]:
    # Prefix match at a word start, so "utilit" hits "Utilities" but "oil" does not hit "soil".
    # Returns the matched words ("manufacturer"), not the stems.
    hits: list[str] = []
    for s in sectors:
        m = re.search(r"\b" + re.escape(s) + r"\w*", text, re.IGNORECASE)
        if m and m.group(0).lower() not in hits:
            hits.append(m.group(0).lower())
    return hits


@dataclass
class Finding:
    kind: str          # "ransomware" | "ics-advisory"
    priority: str
    reasons: list[str]
    item: Victim | Advisory

    @property
    def key(self) -> str:
        return self.item.key


def score_victim(v: Victim, cfg: Config) -> Finding:
    reasons: list[str] = []
    nordic = v.country in cfg.countries
    ot_activity = _sector_hits(v.activity, cfg.ot_sectors)
    ot = ot_activity or _sector_hits(v.description, cfg.ot_sectors)
    watch = _match_terms(f"{v.victim} {v.domain} {v.description}", cfg.watchlist)

    if nordic:
        reasons.append(f"Nordic victim ({v.country})")
    if ot_activity:
        reasons.append(f"OT relevant sector: {v.activity}")
    elif ot:
        reasons.append("OT relevant per description: " + ", ".join(ot))
    if watch:
        reasons.append("watchlist match: " + ", ".join(watch))

    if watch:
        prio = "CRITICAL"
    elif nordic and ot:
        prio = "HIGH"
    elif nordic:
        prio = "MEDIUM"
    else:
        prio = "LOW"
    return Finding("ransomware", prio, reasons, v)


def score_advisory(a: Advisory, cfg: Config) -> Finding:
    vendors = _match_terms(f"{a.title} {a.summary}", cfg.ics_vendors)
    watch = _match_terms(f"{a.title} {a.summary}", cfg.watchlist)
    a.vendors = vendors
    reasons = []
    if vendors:
        reasons.append("watched ICS vendor: " + ", ".join(vendors))
    if watch:
        reasons.append("watchlist match: " + ", ".join(watch))
    prio = "HIGH" if watch else ("MEDIUM" if vendors else "LOW")
    return Finding("ics-advisory", prio, reasons, a)
