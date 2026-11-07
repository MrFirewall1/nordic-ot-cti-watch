"""Attack signals: hacktivist Telegram channels (earliest public signal, groups announce targets
and post proof there) and news / CERT feeds (later, but confirmed). Vulnerability and patch news
is dropped on purpose: the goal is attacks, not CVEs."""
from __future__ import annotations

import html
import re
from dataclasses import dataclass
from datetime import datetime, timezone

from .sources import SourceError, _get, parse_feed


@dataclass
class NewsItem:
    title: str
    link: str
    published: str
    summary: str
    source: str
    region: str = ""      # country code when the source itself is Nordic (e.g. NRK = NO)
    channel: bool = False  # True for a hacktivist Telegram channel post

    @property
    def key(self) -> str:
        return "news:" + (self.link or self.title)

    def age_days(self, now: datetime) -> float | None:
        try:
            ts = datetime.fromisoformat(self.published.replace("Z", "+00:00"))
        except ValueError:
            return None
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return (now - ts).total_seconds() / 86400


def _clean(s: str) -> str:
    s = re.sub(r"<br\s*/?>", "\n", s or "")
    return " ".join(html.unescape(re.sub(r"<[^>]+>", " ", s)).split())


def fetch_feed(name: str, url: str, region: str, timeout: float) -> list[NewsItem]:
    return [NewsItem(_clean(a.title), a.link, a.published, _clean(a.summary)[:400], name, region)
            for a in parse_feed(_get(url, timeout))]


_POST = re.compile(r'data-post="([\w/]+)"')
_TEXT = re.compile(r'<div class="tgme_widget_message_text[^"]*"[^>]*>(.*?)</div>', re.S)
_TIME = re.compile(r'<time[^>]*datetime="([^"]+)"')


def parse_telegram(page: str, channel: str) -> list[NewsItem]:
    """Posts from the public web preview (t.me/s/<channel>), no login and no Telegram API."""
    out = []
    chunks = _POST.split(page)
    for post, body in zip(chunks[1::2], chunks[2::2]):
        t = _TEXT.search(body)
        text = _clean(t.group(1)) if t else ""
        if not text:
            continue
        ts = _TIME.search(body)
        out.append(NewsItem(text[:120], f"https://t.me/{post}", ts.group(1) if ts else "",
                            text[:1500], f"Telegram @{channel}", channel=True))
    return out


def fetch_telegram(channel: str, timeout: float) -> list[NewsItem]:
    channel = channel.strip().lstrip("@").removeprefix("https://t.me/").removeprefix("s/")
    items = parse_telegram(_get(f"https://t.me/s/{channel}", timeout).decode("utf-8", "replace"),
                           channel)
    if not items:
        raise SourceError(f"no posts found for Telegram channel @{channel} (renamed or banned?)")
    return items


# ------------------------------------------------------------------------- triage

def _rx(words: list[str], flags=re.I) -> re.Pattern:
    return re.compile(r"(?<!\w)(?:" + "|".join(words) + r")\w*", flags)


# OT / critical infrastructure. Short acronyms are case sensitive and whole word only.
OT_ACRONYMS = re.compile(r"\b(?:OT|ICS|SCADA|PLCs?|HMIs?|DCS|RTU)\b")
OT_TERMS = _rx([
    r"operational technology", r"industrial control", r"control systems?", r"programmable logic",
    r"refrigerat", r"freezers?", r"cold (?:storage|chain)", r"supermarket cool",
    r"energy (?:sector|company|companies|supplier|infrastructure)", r"power (?:grid|plant|station|supply|outage)",
    r"electric(?:ity)? (?:grid|utility|utilities|supply|company)", r"grid operator", r"substation",
    r"hydro ?(?:power|electric)", r"dams?\b", r"wind (?:farm|turbine|park)", r"solar (?:park|farm|inverter)",
    r"water (?:treatment|utility|utilities|supply|plant|system)", r"wastewater", r"pipelines?",
    r"oil and gas", r"district heating", r"critical infrastructure", r"(?:nuclear|power) plant",
    r"industrial (?:site|plant|systems?|facility)", r"manufactur\w* plant", r"port operations?",
    # Norwegian / Danish
    r"kraftverk", r"kraftselskap", r"kraftstasjon", r"kraftforsyning", r"strømnett", r"strømforsyning",
    r"strømbrudd", r"vannverk", r"fjernvarme", r"kritisk infrastruktur", r"kjøle(?:disk|anlegg|system)",
    r"fryse(?:disk|r|anlegg)", r"styringssystem", r"damanlegg", r"energiselskap", r"nettselskap",
    r"elnet", r"vandværk", r"kraftværk", r"køle(?:anlæg|disk|system)\w*", r"frysedisk", r"frysesystem\w*", r"kolde?kæde", r"termostat\w*",
    # Swedish
    r"elnät", r"kraftverk", r"vattenverk", r"kylanläggning", r"kyl(?:disk|system)", r"frys(?:disk|ar)",
    r"styrsystem", r"energibolag", r"elbolag", r"dammluck",
    # Finnish
    r"sähköverk", r"voimala", r"vesilaito", r"kriittinen infrastruktuuri", r"kaukolämpö", r"energiayhtiö",
])
ATTACK_TERMS = _rx([
    r"attack(?!\s+surface)", r"cyber-?attack", r"hack(?!athon)", r"breach", r"intrusion", r"compromis",
    r"ransomware", r"ddos", r"denial.of.service", r"sabotag", r"wiper", r"tamper", r"manipulat",
    r"took control", r"disrupt", r"claims? responsibility", r"exploited in the wild", r"targeted",
    r"angrep", r"angreb", r"dataangrep", r"hackerangrep", r"løsepengevirus", r"overbelastning",
    r"attack", r"intrång", r"överbelastningsattack", r"it-attack", r"cyberangrep", r"cyberangreb", r"cyberattack\w*", r"cyberattak\w*", r"hackerangreb",
    r"hyökkäy", r"palvelunesto", r"tietomurto", r"kyberhyökkäy",
])
ACTORS = _rx([
    r"noname ?057", r"noname05716", r"ddosia", r"cyber army of russia", r"\bCARR\b", r"z-?pentest",
    r"sector ?16", r"twonet", r"server ?killers", r"killnet", r"dark ?storm", r"holy league",
    r"keymous", r"nullsec", r"cyber ?av3ngers", r"people'?s cyber army", r"z-?alliance", r"overflame",
    r"infrastructure destruction squad", r"hacktivis", r"pro-russian hack", r"sandworm", r"apt ?44",
    r"volt typhoon", r"electrum", r"voltzite", r"chernovite", r"kamacite", r"hackergruppe",
    r"hackergrupp", r"prorussisk", r"proryska", r"venäjämieli",
])
NORDIC = _rx([
    r"norw", r"norge", r"norsk", r"swed", r"sverige", r"svensk", r"denmark", r"danish", r"danmark",
    r"dansk", r"finland", r"finnish", r"suomi", r"suomen", r"iceland", r"ísland", r"nordic",
    r"scandinavia", r"skandinavi", r"faroe", r"færøy", r"greenland", r"grønland",
    r"норвег", r"швец", r"швед", r"дани", r"датск", r"финлянд", r"финск", r"исланд",
    r"\.no\b", r"\.se\b", r"\.dk\b", r"\.fi\b", r"\.is\b",
])
IVANTI = re.compile(r"ivanti|connect secure|pulse secure", re.I)
VULN_ONLY = re.compile(r"CVE-\d|vulnerabilit|patch|advisory|flaw|security update|bug bounty", re.I)
STRONG_ATTACK = re.compile(r"exploit|attack|hack|breach|sabotag|ransomware|ddos|in the wild", re.I)


def _hits(rx: re.Pattern, text: str) -> list[str]:
    seen: list[str] = []
    for m in rx.finditer(text):
        w = m.group(0).strip().lower()
        if w not in seen:
            seen.append(w)
    return seen[:4]


def score_news(n: NewsItem, watchlist: list[str]):
    from .scoring import Finding, _match_terms
    text = f"{n.title} {n.summary}"
    ot = _hits(OT_ACRONYMS, text) + _hits(OT_TERMS, text)
    if IVANTI.search(text):  # "ICS" = Ivanti Connect Secure, not industrial control systems
        ot = [w for w in ot if w != "ics"]
    attack_title = _hits(ATTACK_TERMS, n.title)
    attack = attack_title or _hits(ATTACK_TERMS, text)
    actor = _hits(ACTORS, text)
    nordic = _hits(NORDIC, text) or ([n.region] if n.region else [])
    watch = _match_terms(text, watchlist)
    reasons = []
    if nordic:
        reasons.append("Nordic: " + ", ".join(nordic))
    if ot:
        reasons.append("OT / critical infrastructure: " + ", ".join(ot))
    if actor and not n.channel:
        reasons.append("threat actor: " + ", ".join(actor))
    if watch:
        reasons.append("watchlist match: " + ", ".join(watch))
    if n.channel:
        reasons.insert(0, "hacktivist channel post")

    vuln_only = VULN_ONLY.search(n.title) and not STRONG_ATTACK.search(n.title)
    if watch:
        prio = "CRITICAL"
    elif vuln_only:
        prio = "LOW"
    elif n.channel:
        # A group's own channel: any Nordic target or any OT claim is worth knowing at once.
        prio = "HIGH" if nordic else ("MEDIUM" if ot else "LOW")
    elif nordic and attack and (ot or actor):
        prio = "HIGH"
    elif attack_title and ot:
        prio = "MEDIUM"
    else:
        prio = "LOW"
    return Finding("news", prio, reasons, n)


# ----------------------------------------------------------------------------- context digest
# Background reading (trend reports, hacktivist alliances, OT attacks anywhere). Not alerts: these go
# into one daily summary, so no Nordic requirement here.
ACTORS_CTX = _rx([r"хактивист", r"прорусск", r"проукраинск", r"ддос", r"DDoS", r"хакерск\w* групп"])
OT_CTX = _rx([r"АСУ ?ТП", r"SCADA", r"критическ\w* инфраструктур", r"промышленн\w* систем", r"OT[ -]?сет"])
ATTACK_CTX = _rx([r"атак", r"взлом", r"кибератак", r"инцидент", r"утечк"])


class CtxItem(NewsItem):
    """Background item for the daily digest. Own key prefix so it never mixes with alerts."""

    @property
    def key(self) -> str:
        return "ctx:" + (self.link or self.title)


def score_context(n: NewsItem):
    """A Finding of kind "context" if the item is background on hacktivists or OT attacks, else None."""
    from .scoring import Finding
    text = f"{n.title} {n.summary}"
    actor = _hits(ACTORS, text) + _hits(ACTORS_CTX, text)
    ot = _hits(OT_ATTACKISH_OT, text)
    attack = _hits(ATTACK_TERMS, text) + _hits(ATTACK_CTX, text)
    if not (actor or (ot and attack)):
        return None
    reasons = []
    if actor:
        reasons.append("hacktivist / actor: " + ", ".join(actor))
    if ot:
        reasons.append("OT: " + ", ".join(ot))
    item = CtxItem(n.title, n.link, n.published, n.summary, n.source, n.region)
    return Finding("context", "MEDIUM", reasons, item)


OT_ATTACKISH_OT = re.compile(OT_ACRONYMS.pattern + "|" + OT_TERMS.pattern + "|" + OT_CTX.pattern,
                             re.I)


def fetch_context(name: str, url: str, timeout: float) -> list[NewsItem]:
    return fetch_feed(name, url, "", timeout)
