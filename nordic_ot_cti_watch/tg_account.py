"""Read the channels and group chats a dedicated research Telegram account has joined.

This is how closed hacktivist channels (invite only) are monitored. It needs the optional
`telethon` package and three secrets: TG_API_ID, TG_API_HASH (from my.telegram.org) and
TG_SESSION (created once with `python tools/telegram_login.py`). The account only reads; the
watcher never sends, reacts or joins anything.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

from .news import NewsItem


class TgItem(NewsItem):
    """A post read through the research account. Own key prefix, so it gets its own baseline."""

    @property
    def key(self) -> str:
        return "tg:" + self.link


def to_item(chat_id: int, chat_title: str, username: str | None, msg_id: int,
            date: datetime, text: str) -> TgItem | None:
    text = " ".join((text or "").split())
    if not text:
        return None
    if username:
        link = f"https://t.me/{username}/{msg_id}"
    else:
        # Private channel / supergroup link. Only opens for members (like the research account).
        cid = str(abs(chat_id))
        cid = cid[3:] if cid.startswith("100") else cid
        link = f"https://t.me/c/{cid}/{msg_id}"
    if date.tzinfo is None:
        date = date.replace(tzinfo=timezone.utc)
    return TgItem(text[:120], link, date.isoformat(), text[:1500], f"Telegram: {chat_title}",
                  channel=True)


async def _fetch(api_id: int, api_hash: str, session: str, since: datetime,
                 per_chat: int) -> tuple[list[TgItem], list[str]]:
    from telethon import TelegramClient  # optional dependency
    from telethon.sessions import StringSession

    items: list[TgItem] = []
    warnings: list[str] = []
    # connect() instead of start(): start() would prompt for a phone number if the session is
    # invalid, which hangs in CI.
    client = TelegramClient(StringSession(session), api_id, api_hash)
    await client.connect()
    try:
        if not await client.is_user_authorized():
            raise RuntimeError("TG_SESSION is not logged in, run tools/telegram_login.py again")
        async for d in client.iter_dialogs():
            if not (d.is_channel or d.is_group):
                continue  # skip private chats and bots
            try:
                async for m in client.iter_messages(d.entity, limit=per_chat):
                    if m.date < since:
                        break
                    it = to_item(d.id, d.name or "?", getattr(d.entity, "username", None),
                                 m.id, m.date, m.message or "")
                    if it:
                        items.append(it)
            except Exception as e:  # noqa: BLE001  one closed chat should not stop the run
                warnings.append(f"telegram account, {d.name}: {e}")
    finally:
        await client.disconnect()
    return items, warnings


def fetch_account(api_id: str, api_hash: str, session: str, max_age_days: float,
                  per_chat: int = 100) -> tuple[list[TgItem], list[str]]:
    since = datetime.now(timezone.utc) - timedelta(days=max_age_days or 14)
    return asyncio.run(_fetch(int(api_id), api_hash, session, since, per_chat))
