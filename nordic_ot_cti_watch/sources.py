"""Data sources. Only public, clearweb APIs and feeds are used. The tool never connects to
Tor / .onion sites and never downloads leaked data."""
from __future__ import annotations

import json
import re
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


def _get(url: str, timeout: float, headers: dict | None = None) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*",
                                               **(headers or {})})
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
    cvss: float = 0.0
    cves: list[str] = field(default_factory=list)

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


# ---------------------------------------------------------------- CISA CSAF on GitHub
# cisa.gov blocks many cloud IPs (HTTP 403 from GitHub Actions). CISA publishes the same ICS
# advisories as machine readable CSAF 2.0 JSON in github.com/cisagov/CSAF, which is reachable.

CSAF_TREE = "https://api.github.com/repos/cisagov/CSAF/git/trees/develop:csaf_files/OT/white/{year}"
CSAF_RAW = "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/{year}/{name}"
_CSAF_NAME = re.compile(r"^ics(m)?a-(\d\d)-(\d{3})-(\d\d)\.json$")


def _csaf_sort_key(name: str) -> tuple[int, int, int]:
    m = _CSAF_NAME.match(name)
    return (int(m.group(2)), int(m.group(3)), int(m.group(4))) if m else (0, 0, 0)


def parse_csaf(doc: dict) -> Advisory:
    d = doc.get("document", {})
    tracking = d.get("tracking", {})
    adv_id = tracking.get("id", "")
    refs = d.get("references", [])
    web = next((r.get("url", "") for r in refs if "cisa.gov" in r.get("url", "")
                and r.get("category") == "self"), "")
    if not web:
        web = next((r.get("url", "") for r in refs if r.get("category") == "self"), "")
    vendors = [b.get("name", "") for b in doc.get("product_tree", {}).get("branches", [])
               if b.get("category") == "vendor"]
    cves, scores = [], []
    for v in doc.get("vulnerabilities", []):
        if v.get("cve"):
            cves.append(v["cve"])
        for s in v.get("scores", []):
            score = (s.get("cvss_v3") or {}).get("baseScore") or (s.get("cvss_v4") or {}).get("baseScore")
            if score:
                scores.append(float(score))
    adv = Advisory(
        title=f"{adv_id} {d.get('title', '')}".strip(),
        link=web,
        published=tracking.get("initial_release_date", ""),
        summary=" ".join(vendors),
    )
    adv.cvss = max(scores) if scores else 0.0
    adv.cves = cves
    return adv


def fetch_ics_csaf(timeout: float, limit: int = 15, now: datetime | None = None,
                   github_token: str = "") -> list[Advisory]:
    """Latest `limit` OT advisories from cisagov/CSAF (one API call, then raw file fetches)."""
    now = now or datetime.now(timezone.utc)
    headers = {"Accept": "application/vnd.github+json"}
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"
    names: list[tuple[int, str]] = []
    for year in (now.year, now.year - 1) if now.month == 1 else (now.year,):
        tree = json.loads(_get(CSAF_TREE.format(year=year), timeout, headers))
        names += [(year, t["path"]) for t in tree.get("tree", []) if _CSAF_NAME.match(t.get("path", ""))]
    names.sort(key=lambda yn: _csaf_sort_key(yn[1]))
    out = []
    for year, name in names[-limit:]:
        try:
            out.append(parse_csaf(json.loads(_get(CSAF_RAW.format(year=year, name=name), timeout))))
        except (SourceError, ValueError):
            continue  # one broken file should not stop the run
    return out
