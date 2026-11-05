"""One time login for the research Telegram account. Run this on your own computer:

    pip install telethon
    python tools/telegram_login.py

It asks for api_id and api_hash (from https://my.telegram.org -> API development tools), then
Telegram asks for the account's phone number, the login code and the 2FA password if set.
It prints a session string. Put it in the GitHub secret TG_SESSION and never share or commit it:
anyone with that string can use the account.
"""
from telethon.sessions import StringSession
from telethon.sync import TelegramClient

api_id = int(input("api_id: ").strip())
api_hash = input("api_hash: ").strip()
with TelegramClient(StringSession(), api_id, api_hash) as client:
    me = client.get_me()
    print(f"\nLogged in as {me.first_name} (id {me.id}).")
    print("\nTG_SESSION (treat it like a password):\n")
    print(client.session.save())
