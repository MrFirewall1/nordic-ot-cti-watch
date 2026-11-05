"""Data sources. Only public, clearweb APIs and feeds are used. The tool never connects to
Tor / .onion sites and never downloads leaked data."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from . import __version__

USER_AGENT = f"nordic-ot-cti-watch/{__version__} (+https://github.com/MrFirewall1/nordic-ot-cti-watch)"


class SourceError(RuntimeError):
    pass


def _get(url: str, timeout: float) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read()
    except urllib.error.HTTPError as e:
        if e.code == 429:
            raise SourceError(f"rate limited by {url} (HTTP 429), try again later") from e
        raise SourceError(f"HTTP {e.code} from {url}") from e
    except urllib.error.URLError as e:
        raise SourceError(f"cannot reach {url}: {e.reason}") from e


# ---------------------------------------------------------------- ransomware.live

@dataclass
class Victim:
    victim: str
    group: str
    country: str
    activity: str
    description: str
    domain: str
    attackdate: str
    discovered: str
    url: str  # ransomware.live page, never the .onion claim URL

    @property
    def key(self) -> str:
        # Group + victim, normalised, so the same claim seen via /recentvictims and
        # /countryvictims (different field names, one without a URL) is only reported once.
        return "rw:" + " ".join(f"{self.group}|{self.victim}".lower().split())

    @classmethod
    def from_api(cls, d: dict) -> "Victim":
        def s(*keys: str) -> str:
            for k in keys:
                v = d.get(k)
                if v:
                    return str(v).strip()
            return ""
        # /recentvictims uses victim/group/domain/attackdate/url, while /countryvictims uses
        # post_title/group_name/website/published. "post_url" and "claim_url" point to the
        # leak site itself and are deliberately never read.
        url = s("url", "permalink")
        if ".onion" in url:
            url = ""
        return cls(
            victim=s("victim", "post_title"),
            group=s("group", "group_name"),
            country=s("country").upper(),
            activity=s("activity", "sector"),
            description=s("description"),
            domain=s("domain", "website"),
            attackdate=s("attackdate", "published"),
            discovered=s("discovered", "published", "attackdate"),
            url=url,
        )

    def age_days(self, now: "datetime") -> float | None:
        try:
            ts = datetime.fromisoformat(self.discovered.replace("Z", "+00:00"))
        except ValueError:
            return None
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return (now - ts).total_seconds() / 86400


def fetch_victims(api_base: str, countries: list[str], timeout: float, delay: float) -> list[Victim]:
    """Recent victims globally plus the latest victims for each watched country."""
    base = api_base.rstrip("/")
    urls = [f"{base}/recentvictims"] + [f"{base}/countryvictims/{c}" for c in countries]
    seen: dict[str, Victim] = {}
    for i, url in enumerate(urls):
        if i:
            time.sleep(delay)
        data = json.loads(_get(url, timeout))
        if isinstance(data, dict):
            data = data.get("victims") or data.get("data") or []
        for item in data:
            if isinstance(item, dict):
                v = Victim.from_api(item)
                if v.victim:
                    seen.setdefault(v.key, v)
    return list(seen.values())


# ---------------------------------------------------------------- CISA ICS advisories

@dataclass
class Advisory:
    title: str
    link: str
    published: str
    summary: str = ""
    vendors: list[str] = field(default_factory=list)

    @property
    def key(self) -> str:
        return "ics:" + (self.link or self.title)


def _text(el: ET.Element | None) -> str:
    return (el.text or "").strip() if el is not None else ""


def parse_feed(xml_bytes: bytes) -> list[Advisory]:
    """Parse RSS 2.0 or Atom."""
    root = ET.fromstring(xml_bytes)
    out: list[Advisory] = []
    for item in root.iter("item"):
        pub = _text(item.find("pubDate"))
        try:
            pub = parsedate_to_datetime(pub).isoformat() if pub else ""
        except (TypeError, ValueError):
            pass
        out.append(Advisory(_text(item.find("title")), _text(item.find("link")), pub,
                            _text(item.find("description"))[:500]))
    atom = "{http://www.w3.org/2005/Atom}"
    for entry in root.iter(f"{atom}entry"):
        link_el = entry.find(f"{atom}link")
        out.append(Advisory(_text(entry.find(f"{atom}title")),
                            link_el.get("href", "") if link_el is not None else "",
                            _text(entry.find(f"{atom}updated")),
                            _text(entry.find(f"{atom}summary"))[:500]))
    return out


def fetch_ics_advisories(feed_url: str, timeout: float) -> list[Advisory]:
    return parse_feed(_get(feed_url, timeout))
