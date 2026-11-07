"""Command line entry point."""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .config import Config
from .news import (fetch_context, fetch_feed, fetch_telegram, parse_telegram, score_context,
                   score_news)
from .output import (State, digest_message, line, notify, notify_telegram, write_reports)
from .scoring import Finding, rank, score_advisory, score_victim
from .sources import (SourceError, Victim, fetch_ics_advisories, fetch_ics_csaf, fetch_victims,
                      parse_csaf, parse_feed)


def _redact(text: str, secret: str) -> str:
    return text.replace(secret, "***") if len(secret) >= 8 else text


PREFIX = {"ransomware": "rw:", "ics-advisory": "ics:", "news": "news:", "telegram": "tg:"}


def select_digest(state, ctx: list[Finding], now: datetime, hour: int, all_items: bool = False):
    """Returns (due, items). The digest goes out once per UTC day, on the first run at or after `hour`;
    until then context items stay unseen so none are lost."""
    today = now.date().isoformat()
    due = now.hour >= hour and state.seen.get("meta:digest") != today
    new = ctx if all_items else [f for f in ctx if state.is_new(f.key)]
    return due, new


def collect(cfg: Config, victims_file: str | None = None, feed_file: str | None = None,
            now: datetime | None = None, news_file: str | None = None,
            telegram_file: str | None = None) -> tuple[list[Finding], list[str], list[str]]:
    findings: list[Finding] = []
    errors: list[str] = []
    warnings: list[str] = []
    now = now or datetime.now(timezone.utc)
    if cfg.enable_ransomware:
        try:
            if victims_file:
                raw = json.loads(Path(victims_file).read_text(encoding="utf-8"))
                victims = [Victim.from_api(d) for d in raw]
            else:
                victims = fetch_victims(cfg.ransomware_api, cfg.countries,
                                        cfg.timeout_seconds, cfg.request_delay_seconds)
            if cfg.max_age_days:
                victims = [v for v in victims
                           if (age := v.age_days(now)) is None or age <= cfg.max_age_days]
            findings += [score_victim(v, cfg) for v in victims]
        except (SourceError, ValueError) as e:
            errors.append(f"ransomware.live: {e}")
    if cfg.enable_ics_advisories:
        try:
            if feed_file:
                raw = Path(feed_file).read_bytes()
                advisories = ([parse_csaf(d) for d in json.loads(raw)]
                              if feed_file.endswith(".json") else parse_feed(raw))
            elif cfg.ics_source == "csaf":
                advisories = fetch_ics_csaf(cfg.timeout_seconds, cfg.ics_limit,
                                            github_token=os.environ.get("GITHUB_TOKEN", ""))
            else:
                advisories = fetch_ics_advisories(cfg.cisa_ics_feed, cfg.timeout_seconds)
            findings += [score_advisory(a, cfg) for a in advisories]
        except (SourceError, ValueError) as e:
            errors.append(f"CISA ICS feed: {e}")
    if cfg.enable_news or news_file or telegram_file:
        items = []
        if news_file or telegram_file:
            if news_file:
                items += [i for i in fetch_feed_file(news_file)]
            if telegram_file:
                items += parse_telegram(Path(telegram_file).read_text(encoding="utf-8"), "test")
        else:
            ok = 0
            for ch in cfg.telegram_channels:
                try:
                    items += fetch_telegram(ch, cfg.timeout_seconds)
                    ok += 1
                except Exception as e:  # noqa: BLE001
                    warnings.append(f"telegram {ch}: {e}")
            for f in cfg.news_feeds:
                try:
                    items += fetch_feed(f.get("name", f["url"]), f["url"], f.get("country", ""),
                                        cfg.timeout_seconds)
                    ok += 1
                except Exception as e:  # noqa: BLE001
                    warnings.append(f"news feed {f.get('name', f.get('url'))}: {e}")
            if not ok and (cfg.telegram_channels or cfg.news_feeds):
                errors.append("news: no feed or channel could be read")
        if cfg.max_age_days:
            items = [i for i in items if (age := i.age_days(now)) is None or age <= cfg.max_age_days]
        seen_keys = set()
        for i in items:
            if i.key not in seen_keys:
                seen_keys.add(i.key)
                findings.append(score_news(i, cfg.watchlist))
    if cfg.enable_news and not (news_file or telegram_file or victims_file or feed_file):
        seen_ctx = set()
        for f in cfg.context_feeds:
            try:
                for i in fetch_context(f.get("name", f["url"]), f["url"], cfg.timeout_seconds):
                    if cfg.max_age_days and (age := i.age_days(now)) is not None \
                            and age > cfg.max_age_days:
                        continue
                    c = score_context(i)
                    if c and c.item.key not in seen_ctx:
                        seen_ctx.add(c.item.key)
                        findings.append(c)
            except Exception as e:  # noqa: BLE001
                warnings.append(f"context feed {f.get('name', f.get('url'))}: {e}")
    tg = {k: os.environ.get(k, "").strip() for k in ("TG_API_ID", "TG_API_HASH", "TG_SESSION")}
    if all(tg.values()) and not (news_file or telegram_file or victims_file or feed_file):
        try:
            from .tg_account import fetch_account
            posts, w = fetch_account(tg["TG_API_ID"], tg["TG_API_HASH"], tg["TG_SESSION"],
                                     cfg.max_age_days)
            warnings += w
            for p in posts:
                f = score_news(p, cfg.watchlist)
                f.kind = "telegram"
                findings.append(f)
        except Exception as e:  # noqa: BLE001
            errors.append(f"telegram account: {type(e).__name__}: {e}")
    return findings, errors, warnings


def fetch_feed_file(path: str):
    from .news import NewsItem, _clean
    return [NewsItem(_clean(a.title), a.link, a.published, _clean(a.summary)[:400], "file")
            for a in parse_feed(Path(path).read_bytes())]


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="nordic-ot-cti-watch",
                                description="Early warning on ransomware claims and ICS advisories "
                                            "relevant to Nordic organisations and OT.")
    p.add_argument("-c", "--config", default=None, help="path to config.toml")
    p.add_argument("--all", action="store_true", help="ignore state and show everything that matches")
    p.add_argument("--dry-run", action="store_true", help="do not update state, reports or webhook")
    p.add_argument("--victims-file", help="read ransomware.live JSON from a file instead of the API")
    p.add_argument("--feed-file", help="read the ICS advisory RSS from a file instead of CISA")
    p.add_argument("--news-file", help="read a news RSS file instead of the configured feeds")
    p.add_argument("--telegram-file", help="read a saved t.me/s/<channel> page instead of Telegram")
    p.add_argument("--json", action="store_true", help="print matches as JSON")
    p.add_argument("--now", help=argparse.SUPPRESS)  # fixed reference time, used by tests
    p.add_argument("--test-alert", action="store_true",
                   help="send one test alert to Telegram / webhook and exit")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    a = p.parse_args(argv)

    cfg = Config.load(a.config)
    cfg.webhook_url = os.environ.get("CTI_WEBHOOK_URL", cfg.webhook_url)
    # Secrets from the environment (e.g. GitHub Actions secrets), never committed to the repo.
    extra = os.environ.get("CTI_WATCHLIST", "")
    cfg.watchlist += [w.strip() for w in extra.replace("\n", ",").split(",") if w.strip()]
    chans = os.environ.get("CTI_TELEGRAM_CHANNELS", "")
    cfg.telegram_channels += [c.strip() for c in chans.replace("\n", ",").split(",") if c.strip()]
    tg_token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    tg_chat = os.environ.get("TELEGRAM_CHAT_ID", "").strip()

    if a.test_alert:
        if not (tg_token and tg_chat) and not cfg.webhook_url:
            print("error: set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID (or CTI_WEBHOOK_URL)", file=sys.stderr)
            return 2
        test = Finding("ransomware", "HIGH", ["test alert, the watcher is connected"],
                       Victim("Test Kraftverk AS", "testgroup", "NO", "Energy & Utilities", "", "",
                              "", datetime.now(timezone.utc).isoformat(), ""))
        try:
            notify_telegram([test], tg_token, tg_chat)
            notify([test], cfg.webhook_url, cfg.webhook_format)
        except Exception as e:  # noqa: BLE001
            print(f"error: test alert failed: {_redact(str(e), tg_token)}", file=sys.stderr)
            return 2
        print("test alert sent", file=sys.stderr)
        return 0

    now = datetime.fromisoformat(a.now) if a.now else None
    findings, errors, warnings = collect(cfg, a.victims_file, a.feed_file, now, a.news_file,
                                         a.telegram_file)
    ctx_all = [f for f in findings if f.kind == "context"]
    findings = [f for f in findings if f.kind != "context"]
    threshold = rank(cfg.min_priority)
    matched = [f for f in findings if rank(f.priority) >= threshold]
    state = State(cfg.state_file)
    new = matched if a.all else [f for f in matched if state.is_new(f.key)]
    new.sort(key=lambda f: (-rank(f.priority), f.kind != "ransomware"))

    if a.json:
        print(json.dumps([{"kind": f.kind, "priority": f.priority, "reasons": f.reasons,
                           **vars(f.item)} for f in new], ensure_ascii=False, indent=2))
    else:
        for f in new:
            print(line(f))
        print(f"\n{len(new)} new item(s), {len(matched)} matching, {len(findings)} checked.",
              file=sys.stderr)
    for e in errors + warnings:
        print(f"warning: {e}", file=sys.stderr)

    if not a.dry_run:
        if new:
            md, _ = write_reports(new, cfg.report_dir)
            print(f"report: {md}", file=sys.stderr)
        first_run = not state.path.exists()
        # Baseline per source: the first time a source produces items (first run, or a source
        # enabled later), send one summary instead of a burst of alerts for the last max_age_days.
        baseline = set() if a.all else {
            f.kind for f in new if not any(k.startswith(PREFIX[f.kind]) for k in state.seen)}
        alerts = [f for f in new if f.kind not in baseline]
        summary = ""
        base = [f for f in new if f.kind in baseline]
        if base:
            counts = {p: sum(f.priority == p for f in base) for p in ("CRITICAL", "HIGH", "MEDIUM")}
            head = ("✅ <b>Nordic OT CTI Watch is live.</b>" if first_run else
                    "✅ <b>New source enabled: " + ", ".join(sorted(baseline)) + ".</b>")
            summary = (f"{head}\nBaseline from the last {cfg.max_age_days:g} days: "
                       + ", ".join(f"{n} {p}" for p, n in counts.items() if n)
                       + ".\nFrom now on you only get alerts for new items.")
        send_tg = lambda: notify_telegram(alerts, tg_token, tg_chat, summary=summary)  # noqa: E731
        send_hook = lambda: notify(alerts, cfg.webhook_url, cfg.webhook_format)  # noqa: E731
        delivered = True
        for name, send in (("webhook", send_hook), ("telegram", send_tg)):
            try:
                send()
            except Exception as e:  # noqa: BLE001
                delivered = False
                errors.append(f"{name}: {e}")
                print(f"warning: {name} failed: {_redact(str(e), tg_token)}", file=sys.stderr)
        # If an alert could not be delivered, leave the new items unseen so the next run retries.
        new_keys = {f.key for f in new}
        for f in matched:
            if delivered or f.key not in new_keys:
                state.mark(f.key)
        # Daily context digest (background reading, one message per day).
        run_now = now or datetime.now(timezone.utc)
        due, ctx_new = select_digest(state, ctx_all, run_now, cfg.digest_hour_utc)
        if due and delivered and tg_token and tg_chat:
            try:
                if ctx_new:
                    notify_telegram([], tg_token, tg_chat,
                                    summary=digest_message(ctx_new, cfg.digest_max_items))
                for f in ctx_new:
                    state.mark(f.key)
                state.seen["meta:digest"] = run_now.date().isoformat()
            except Exception as e:  # noqa: BLE001
                errors.append(f"digest: {e}")
                print(f"warning: digest failed: {_redact(str(e), tg_token)}", file=sys.stderr)
        state.save()

    if errors and not findings and not ctx_all:
        return 2
    return 1 if any(f.priority in ("HIGH", "CRITICAL") for f in new) else 0


if __name__ == "__main__":
    sys.exit(main())
