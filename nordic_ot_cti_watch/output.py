"""State (dedupe), reports and notifications."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from .news import NewsItem
from .scoring import Finding
from .sources import USER_AGENT, Advisory, Victim

ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "⚪"}


class State:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.seen: dict[str, str] = {}
        if self.path.exists():
            self.seen = json.loads(self.path.read_text(encoding="utf-8"))

    def is_new(self, key: str) -> bool:
        return key not in self.seen

    def mark(self, key: str) -> None:
        self.seen[key] = datetime.now(timezone.utc).isoformat(timespec="seconds")

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.seen, indent=1, sort_keys=True), encoding="utf-8")


def _md(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ").strip()


def line(f: Finding) -> str:
    i = f.item
    if isinstance(i, Victim):
        why = next((r for r in f.reasons if r.startswith("watchlist")), "") or \
            next((r for r in f.reasons if r.startswith("OT relevant")), "")
        return (f"{ICON[f.priority]} [{f.priority}] {i.victim} ({i.country or '??'}) "
                f"claimed by {i.group}, sector: {i.activity or 'unknown'}"
                + (f" | {why}" if why and not why.endswith(i.activity) else ""))
    if isinstance(i, NewsItem):
        return f"{ICON[f.priority]} [{f.priority}] {i.source}: {i.title}"
    return f"{ICON[f.priority]} [{f.priority}] ICS advisory: {i.title}"


def markdown_report(findings: list[Finding], generated: datetime) -> str:
    rw = [f for f in findings if f.kind == "ransomware"]
    ics = [f for f in findings if f.kind == "ics-advisory"]
    news = [f for f in findings if f.kind in ("news", "telegram")]
    out = [f"# Nordic OT CTI Watch report",
           "",
           f"Generated {generated.strftime('%Y-%m-%d %H:%M UTC')}. "
           f"{len(news)} new attack signals, {len(rw)} new ransomware claims and "
           f"{len(ics)} new ICS advisories matched the filters.",
           "",
           "> Leak site claims are unverified. A listing means a group *claims* an attack. "
           "Confirm with the organisation or official sources before acting.",
           ""]
    if news:
        out += ["## Attack signals (hacktivist channels and news)", "",
                "| Priority | Item | Source | Published | Why |", "|---|---|---|---|---|"]
        for f in news:
            n: NewsItem = f.item  # type: ignore[assignment]
            out.append(f"| {ICON[f.priority]} {f.priority} | [{_md(n.title)}]({n.link}) | "
                       f"{_md(n.source)} | {n.published[:10]} | {_md('; '.join(f.reasons))} |")
        out.append("")
    if rw:
        out += ["## Ransomware leak site claims", "",
                "| Priority | Victim | Country | Sector | Group | Discovered | Why | Source |",
                "|---|---|---|---|---|---|---|---|"]
        for f in rw:
            v: Victim = f.item  # type: ignore[assignment]
            out.append(f"| {ICON[f.priority]} {f.priority} | {_md(v.victim)} | {v.country} | "
                       f"{_md(v.activity)} | {_md(v.group)} | {v.discovered[:10]} | "
                       f"{_md('; '.join(f.reasons))} | "
                       f"{f'[ransomware.live]({v.url})' if v.url else 'ransomware.live'} |")
        out.append("")
    if ics:
        out += ["## ICS advisories for watched vendors", "",
                "| Priority | Advisory | Vendors | Published |", "|---|---|---|---|"]
        for f in ics:
            a: Advisory = f.item  # type: ignore[assignment]
            out.append(f"| {ICON[f.priority]} {f.priority} | [{_md(a.title)}]({a.link}) | "
                       f"{_md(', '.join(a.vendors))} | {a.published[:10]} |")
        out.append("")
    if not findings:
        out += ["No new items matched the filters.", ""]
    out += ["---", "Data: public hacktivist channels, news and CERT feeds (linked per item), "
            "[ransomware.live](https://www.ransomware.live) and, if enabled, "
            "[CISA ICS advisories](https://www.cisa.gov/news-events/cybersecurity-advisories)."]
    return "\n".join(out) + "\n"


def write_reports(findings: list[Finding], report_dir: str | Path) -> tuple[Path, Path]:
    now = datetime.now(timezone.utc)
    d = Path(report_dir)
    d.mkdir(parents=True, exist_ok=True)
    md = d / f"report-{now.strftime('%Y%m%d-%H%M')}.md"
    md.write_text(markdown_report(findings, now), encoding="utf-8")
    jl = d / "findings.jsonl"
    with jl.open("a", encoding="utf-8") as fh:
        for f in findings:
            fh.write(json.dumps({"seen_at": now.isoformat(timespec="seconds"), "kind": f.kind,
                                 "priority": f.priority, "reasons": f.reasons,
                                 **asdict(f.item)}, ensure_ascii=False) + "\n")
    return md, jl


def notify(findings: list[Finding], url: str, fmt: str, timeout: float = 15) -> None:
    if not url or not findings:
        return
    text = "Nordic OT CTI Watch\n" + "\n".join(line(f) for f in findings[:25])
    if len(findings) > 25:
        text += f"\n... and {len(findings) - 25} more"
    if fmt == "discord":
        body = {"content": text[:1990]}
    elif fmt == "teams":
        body = {"text": text.replace("\n", "<br>")}
    else:
        body = {"text": text}
    _post_json(url, body, timeout)


def _post_json(url: str, body: dict, timeout: float) -> None:
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout):
            pass
    except urllib.error.HTTPError as e:
        # Surface the API's own explanation (e.g. Telegram's "chat not found"), never the URL,
        # which for Telegram contains the bot token.
        detail = ""
        try:
            detail = json.loads(e.read().decode("utf-8", "replace")).get("description", "")
        except Exception:  # noqa: BLE001
            pass
        hint = ""
        if "chat not found" in detail.lower():
            hint = " (open your bot in Telegram, press Start and send it a message, then check TELEGRAM_CHAT_ID)"
        elif e.code == 401:
            hint = " (the bot token is wrong or was revoked)"
        raise RuntimeError(f"HTTP {e.code}: {detail or e.reason}{hint}") from None


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def telegram_messages(findings: list[Finding]) -> list[str]:
    """One message per finding (HTML), so each alert is readable on a phone."""
    msgs = []
    for f in findings:
        i = f.item
        if isinstance(i, Victim):
            link = f'\n<a href="{_esc(i.url)}">ransomware.live</a>' if i.url else ""
            msgs.append(
                f"{ICON[f.priority]} <b>{f.priority}: ransomware claim</b>\n"
                f"<b>{_esc(i.victim)}</b> ({_esc(i.country or '??')})\n"
                f"Group: {_esc(i.group)}\nSector: {_esc(i.activity or 'unknown')}\n"
                f"Why: {_esc('; '.join(f.reasons))}\n"
                f"Discovered: {_esc(i.discovered[:16].replace('T', ' '))} UTC"
                f"{link}\n<i>Unverified leak site claim.</i>")
        elif isinstance(i, NewsItem):
            head = "hacktivist channel" if i.channel else "attack news"
            body = f"\n{_esc(i.summary[:600])}" if i.channel else ""
            msgs.append(
                f"{ICON[f.priority]} <b>{f.priority}: {head}</b>\n"
                f'<a href="{_esc(i.link)}">{_esc(i.title)}</a>{body}\n'
                f"Source: {_esc(i.source)}\nWhy: {_esc('; '.join(f.reasons))}\n"
                f"Published: {_esc(i.published[:16].replace('T', ' '))}")
        else:
            cves = f"\nCVEs: {_esc(', '.join(i.cves[:5]))}" if getattr(i, "cves", None) else ""
            msgs.append(
                f"{ICON[f.priority]} <b>{f.priority}: ICS advisory</b>\n"
                f'<a href="{_esc(i.link)}">{_esc(i.title)}</a>\n'
                f"Why: {_esc('; '.join(f.reasons))}{cves}")
    return msgs


def digest_message(findings: list[Finding], max_items: int = 8) -> str:
    """One Telegram message with the newest background items (hacktivists, OT attacks, trends)."""
    items = sorted(findings, key=lambda f: f.item.published or "", reverse=True)
    shown = items[:max_items]
    out = [f"📰 <b>Daily context: {len(items)} new item(s)</b>"]
    for f in shown:
        i = f.item
        out.append(f'• <a href="{_esc(i.link)}">{_esc(i.title[:140])}</a> <i>({_esc(i.source)}, '
                   f'{_esc(i.published[:10])})</i>')
    if len(items) > len(shown):
        out.append(f"… and {len(items) - len(shown)} more.")
    return "\n".join(out)


def notify_telegram(findings: list[Finding], token: str, chat_id: str, timeout: float = 15,
                    max_messages: int = 20, summary: str = "") -> None:
    if not token or not chat_id or not (findings or summary):
        return
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    msgs = ([summary] if summary else []) + telegram_messages(findings)
    if len(msgs) > max_messages:
        rest = len(msgs) - max_messages + 1
        msgs = msgs[:max_messages - 1] + [f"… and {rest} more. See the report in GitHub Actions."]
    for m in msgs:
        _post_json(url, {"chat_id": chat_id, "text": m[:4000], "parse_mode": "HTML",
                         "disable_web_page_preview": True}, timeout)
        time.sleep(1.1)  # stay well under Telegram's per chat rate limit
