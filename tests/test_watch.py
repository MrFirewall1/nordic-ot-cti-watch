import json
import os
from datetime import datetime, timezone
import tempfile
import unittest
from pathlib import Path

from nordic_ot_cti_watch.cli import main
from nordic_ot_cti_watch.config import Config
from nordic_ot_cti_watch.scoring import score_advisory, score_victim
from nordic_ot_cti_watch.sources import Victim, _csaf_sort_key, parse_csaf, parse_feed

FIX = Path(__file__).parent / "fixtures"


def victims():
    return {v.victim: v for v in
            (Victim.from_api(d) for d in json.loads((FIX / "victims.json").read_text()))}


class ScoringTests(unittest.TestCase):
    def setUp(self):
        self.cfg = Config(watchlist=["Contoso Energy"])
        self.v = victims()

    def test_nordic_ot_is_high(self):
        f = score_victim(self.v["Fjord Kraftverk AS"], self.cfg)
        self.assertEqual(f.priority, "HIGH")

    def test_nordic_non_ot_is_medium(self):
        self.assertEqual(score_victim(self.v["Nordic Fashion AB"], self.cfg).priority, "MEDIUM")

    def test_non_nordic_is_low(self):
        self.assertEqual(score_victim(self.v["Acme Software Inc"], self.cfg).priority, "LOW")

    def test_watchlist_is_critical_anywhere(self):
        f = score_victim(self.v["Beispiel GmbH"], self.cfg)
        self.assertEqual(f.priority, "CRITICAL")
        self.assertIn("watchlist match: Contoso Energy", f.reasons)

    def test_country_code_case_insensitive(self):
        self.assertEqual(score_victim(self.v["Mejeri Eksempel A/S"], self.cfg).priority, "HIGH")

    def test_no_substring_false_positive(self):
        # "soil" must not count as the "oil" sector
        self.assertEqual(score_victim(self.v["Puutarha Oy"], self.cfg).priority, "MEDIUM")

    def test_onion_claim_url_is_not_kept(self):
        self.assertFalse(hasattr(self.v["Fjord Kraftverk AS"], "claim_url"))

    def test_country_endpoint_field_names(self):
        v = self.v["Kraftstyrning Exempel AB"]
        self.assertEqual((v.group, v.domain, v.country), ("countrygroup", "kraftstyrning.example", "SE"))
        self.assertEqual(v.url, "")  # post_url (.onion) is never used
        # sector "Other", but the description says power plant automation
        self.assertEqual(score_victim(v, self.cfg).priority, "HIGH")

    def test_age(self):
        now = datetime(2026, 11, 3, tzinfo=timezone.utc)
        self.assertGreater(self.v["Gammel Fabrikk AS"].age_days(now), 14)
        self.assertLess(self.v["Fjord Kraftverk AS"].age_days(now), 2)


class FalsePositiveTests(unittest.TestCase):
    """Regression cases taken from real ransomware.live descriptions."""

    def setUp(self):
        self.cfg = Config()

    def v(self, activity, description):
        return Victim("X", "g", "SE", activity, description, "", "", "2026-11-01T00:00:00+00:00", "")

    def test_known_non_ot_sector_is_not_upgraded_by_description(self):
        municipality = self.v("Government & Defense", "Municipality with schools, transport and water services")
        self.assertEqual(score_victim(municipality, self.cfg).priority, "MEDIUM")

    def test_single_description_hit_is_not_enough(self):
        it_firm = self.v("Not Found", "IT services company providing cloud, cybersecurity and automation")
        self.assertEqual(score_victim(it_firm, self.cfg).priority, "MEDIUM")

    def test_two_description_hits_with_unclassified_sector(self):
        plant = self.v("Other", "Power plant automation company delivering control systems")
        self.assertEqual(score_victim(plant, self.cfg).priority, "HIGH")


class FeedTests(unittest.TestCase):
    def test_csaf_parsing_and_scoring(self):
        ads = [parse_csaf(d) for d in json.loads((FIX / "csaf.json").read_text())]
        siemens, other = ads
        self.assertEqual(siemens.title, "ICSA-26-300-01 Siemens SIMATIC Example PLC")
        self.assertEqual(siemens.link, "https://www.cisa.gov/news-events/ics-advisories/icsa-26-300-01")
        self.assertEqual(siemens.cvss, 9.8)
        self.assertEqual(siemens.cves, ["CVE-2026-00001", "CVE-2026-00002"])
        f = score_advisory(siemens, Config())
        self.assertEqual(f.priority, "MEDIUM")
        self.assertIn("CVSS 9.8", f.reasons)
        self.assertEqual(score_advisory(other, Config()).priority, "LOW")

    def test_csaf_sort_is_chronological_across_icsa_and_icsma(self):
        names = ["icsma-26-295-01.json", "icsa-26-307-01.json", "icsa-26-302-03.json"]
        self.assertEqual(sorted(names, key=_csaf_sort_key)[-1], "icsa-26-307-01.json")

    def test_advisory_vendor_and_watchlist(self):
        cfg = Config(watchlist=["Contoso Energy"])
        ads = {a.title: a for a in parse_feed((FIX / "ics-advisories.xml").read_bytes())}
        self.assertEqual(len(ads), 3)
        self.assertEqual(score_advisory(ads["Siemens SIMATIC Example Controller"], cfg).priority, "MEDIUM")
        self.assertEqual(score_advisory(ads["Danfoss AK-SM 800A Example"], cfg).priority, "HIGH")
        self.assertEqual(score_advisory(ads["Unwatched Vendor HMI"], cfg).priority, "LOW")


class NewsTests(unittest.TestCase):
    def setUp(self):
        from nordic_ot_cti_watch.cli import fetch_feed_file
        from nordic_ot_cti_watch.news import parse_telegram
        self.news = {i.link: i for i in fetch_feed_file(str(FIX / "news.xml"))}
        self.tg = parse_telegram((FIX / "telegram.html").read_text(), "examplechannel")

    def prio(self, item):
        from nordic_ot_cti_watch.news import score_news
        return score_news(item, []).priority

    def test_nordic_ot_attack_is_high(self):
        self.assertEqual(self.prio(self.news["https://news.example/dam"]), "HIGH")

    def test_hacktivist_campaign_against_nordic_country_is_high(self):
        self.assertEqual(self.prio(self.news["https://news.example/noname-se"]), "HIGH")

    def test_ot_attack_elsewhere_is_medium(self):
        self.assertEqual(self.prio(self.news["https://news.example/texas"]), "MEDIUM")

    def test_cve_and_patch_news_is_dropped(self):
        self.assertEqual(self.prio(self.news["https://news.example/patch"]), "LOW")

    def test_unrelated_news_is_dropped(self):
        self.assertEqual(self.prio(self.news["https://news.example/phish"]), "LOW")

    def test_telegram_posts(self):
        self.assertEqual([p.link for p in self.tg], [f"https://t.me/examplechannel/{n}" for n in (101, 102, 103)])
        self.assertIn("example-energi.se", self.tg[0].summary)
        self.assertEqual([self.prio(p) for p in self.tg], ["HIGH", "LOW", "MEDIUM"])

    def test_ivanti_ics_is_not_industrial(self):
        from nordic_ot_cti_watch.news import NewsItem
        n = NewsItem("Attackers chain Ivanti Connect Secure (ICS) flaws to gain root", "u", "", "", "x")
        self.assertEqual(self.prio(n), "LOW")

    def test_research_account_posts(self):
        from nordic_ot_cti_watch.news import score_news
        from nordic_ot_cti_watch.tg_account import to_item
        d = datetime(2026, 11, 5, 20, 0, tzinfo=timezone.utc)
        private = to_item(-1001234567890, "Closed channel", None, 42, d,
                          "Атакуем энергетику Норвегии: example-kraft.no")
        self.assertEqual(private.link, "https://t.me/c/1234567890/42")
        self.assertTrue(private.key.startswith("tg:"))
        self.assertEqual(score_news(private, []).priority, "HIGH")
        public = to_item(-1009, "Open", "somechannel", 7, d, "hello")
        self.assertEqual(public.link, "https://t.me/somechannel/7")
        self.assertIsNone(to_item(1, "x", None, 1, d, "   "))

    def test_watchlist_in_news_is_critical(self):
        from nordic_ot_cti_watch.news import score_news
        self.assertEqual(score_news(self.tg[0], ["example-energi"]).priority, "CRITICAL")


class CliTests(unittest.TestCase):
    def test_end_to_end_and_dedupe(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "config.toml"
            cfg.write_text(f'[filters]\nwatchlist = ["Contoso Energy"]\n'
                           f'[output]\nstate_file = "{tmp}/seen.json"\nreport_dir = "{tmp}/reports"\n')
            args = ["-c", str(cfg), "--victims-file", str(FIX / "victims.json"),
                    "--feed-file", str(FIX / "ics-advisories.xml"),
                    "--now", "2026-11-03T00:00:00+00:00"]
            self.assertEqual(main(args), 1)  # HIGH/CRITICAL found
            reports = list((Path(tmp) / "reports").glob("report-*.md"))
            self.assertEqual(len(reports), 1)
            text = reports[0].read_text()
            self.assertIn("Fjord Kraftverk AS", text)
            self.assertNotIn("Acme Software Inc", text)
            self.assertNotIn(".onion", text)
            self.assertIn("Kraftstyrning Exempel AB", text)
            self.assertNotIn("Gammel Fabrikk AS", text)  # older than max_age_days
            seen = json.loads((Path(tmp) / "seen.json").read_text())
            self.assertEqual(len(seen), 8)  # 6 recent victims + 2 advisories at MEDIUM or above
            self.assertEqual(main(args), 0)  # second run: nothing new

    def test_telegram_alerts_baseline_then_new_items(self):
        import nordic_ot_cti_watch.output as out
        sent = []
        orig_post, orig_sleep = out._post_json, out.time.sleep
        out._post_json = lambda url, body, timeout: sent.append((url, body))
        out.time.sleep = lambda s: None
        env = {"TELEGRAM_BOT_TOKEN": "123:abc", "TELEGRAM_CHAT_ID": "42",
               "CTI_WATCHLIST": "Contoso Energy"}
        old_env = {k: os.environ.get(k) for k in env}
        os.environ.update(env)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                cfg = Path(tmp) / "config.toml"
                cfg.write_text(f'[output]\nstate_file = "{tmp}/seen.json"\nreport_dir = "{tmp}/r"\n')
                base = ["-c", str(cfg), "--feed-file", str(FIX / "ics-advisories.xml"),
                        "--now", "2026-11-03T00:00:00+00:00"]
                # first run: one baseline summary, no burst
                main(base + ["--victims-file", str(FIX / "victims.json")])
                self.assertEqual(len(sent), 1)
                self.assertIn("is live", sent[0][1]["text"])
                self.assertIn("1 CRITICAL", sent[0][1]["text"])  # watchlist from env var
                self.assertEqual(sent[0][0], "https://api.telegram.org/bot123:abc/sendMessage")
                # second run with one new Nordic victim: exactly one alert
                newv = Path(tmp) / "new.json"
                newv.write_text(json.dumps([{"victim": "Ny Kraft AS", "group": "g", "country": "NO",
                                             "activity": "Energy & Utilities",
                                             "discovered": "2026-11-02T10:00:00+00:00"}]))
                sent.clear()
                main(base + ["--victims-file", str(newv)])
                self.assertEqual(len(sent), 1)
                body = sent[0][1]
                self.assertEqual((body["chat_id"], body["parse_mode"]), ("42", "HTML"))
                self.assertIn("<b>Ny Kraft AS</b> (NO)", body["text"])
                self.assertIn("HIGH", body["text"])
        finally:
            out._post_json, out.time.sleep = orig_post, orig_sleep
            for k, v in old_env.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

    def test_failed_delivery_is_retried(self):
        import nordic_ot_cti_watch.output as out
        orig = out._post_json

        def boom(*a, **k):
            raise OSError("network down")
        out._post_json = boom
        os.environ.update({"TELEGRAM_BOT_TOKEN": "t", "TELEGRAM_CHAT_ID": "1"})
        try:
            with tempfile.TemporaryDirectory() as tmp:
                (Path(tmp) / "seen.json").write_text("{}")  # not a first run
                cfg = Path(tmp) / "config.toml"
                cfg.write_text(f'[output]\nstate_file = "{tmp}/seen.json"\nreport_dir = "{tmp}/r"\n')
                main(["-c", str(cfg), "--victims-file", str(FIX / "victims.json"),
                      "--feed-file", str(FIX / "ics-advisories.xml"),
                      "--now", "2026-11-03T00:00:00+00:00"])
                self.assertEqual(json.loads((Path(tmp) / "seen.json").read_text()), {})
        finally:
            out._post_json = orig
            os.environ.pop("TELEGRAM_BOT_TOKEN"); os.environ.pop("TELEGRAM_CHAT_ID")

    def test_new_source_gets_its_own_baseline(self):
        import nordic_ot_cti_watch.output as out
        sent = []
        orig_post, orig_sleep = out._post_json, out.time.sleep
        out._post_json = lambda url, body, timeout: sent.append(body["text"])
        out.time.sleep = lambda s: None
        os.environ.update({"TELEGRAM_BOT_TOKEN": "123:abc", "TELEGRAM_CHAT_ID": "42"})
        try:
            with tempfile.TemporaryDirectory() as tmp:
                cfg = Path(tmp) / "config.toml"
                cfg.write_text(f'[output]\nstate_file = "{tmp}/seen.json"\nreport_dir = "{tmp}/r"\n')
                base = ["-c", str(cfg), "--victims-file", str(FIX / "victims.json"),
                        "--feed-file", str(FIX / "ics-advisories.xml"),
                        "--now", "2026-11-03T00:00:00+00:00"]
                main(base)
                sent.clear()
                # news is added later: one "new source" summary, no burst of old articles
                main(base + ["--news-file", str(FIX / "news.xml")])
                self.assertEqual(len(sent), 1)
                self.assertIn("New source enabled: news", sent[0])
                self.assertIn("2 HIGH", sent[0])  # the 5 week old article is skipped
                sent.clear()
                # then a new channel post is alerted on its own
                main(base + ["--news-file", str(FIX / "news.xml"),
                             "--telegram-file", str(FIX / "telegram.html")])
                self.assertEqual(len(sent), 2)  # Sweden post (HIGH) + SCADA post (MEDIUM)
                self.assertIn("hacktivist channel", sent[0])
                self.assertIn("example-energi.se", sent[0])
        finally:
            out._post_json, out.time.sleep = orig_post, orig_sleep
            os.environ.pop("TELEGRAM_BOT_TOKEN"); os.environ.pop("TELEGRAM_CHAT_ID")

    def test_unknown_config_key_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "c.toml"
            cfg.write_text('[filters]\ncountrys = ["NO"]\n')
            with self.assertRaises(ValueError):
                Config.load(cfg)


if __name__ == "__main__":
    unittest.main()


class ContextDigestTests(unittest.TestCase):
    def _ctx(self, title, link):
        from nordic_ot_cti_watch.news import NewsItem, score_context
        return score_context(NewsItem(title, link, "2026-11-06T12:00:00+00:00", "", "SecPost"))

    def test_hacktivist_background_is_context_not_alert(self):
        f = self._ctx("Хактивисты объединяют усилия с поставщиками DDoS-атак", "http://a/1")
        self.assertIsNotNone(f)
        self.assertEqual(f.kind, "context")
        self.assertTrue(f.item.key.startswith("ctx:"))

    def test_unrelated_is_dropped(self):
        self.assertIsNone(self._ctx("Windows 11 можно взломать через Paint", "http://a/2"))

    def test_digest_is_due_once_per_day_after_the_hour(self):
        import tempfile
        from datetime import datetime, timezone
        from nordic_ot_cti_watch.cli import select_digest
        from nordic_ot_cti_watch.output import State, digest_message
        with tempfile.TemporaryDirectory() as d:
            st = State(d + "/s.json")
            f = self._ctx("Pro-Russian hacktivists announce DDoS alliance", "http://a/3")
            early = datetime(2026, 11, 7, 5, 0, tzinfo=timezone.utc)
            late = datetime(2026, 11, 7, 6, 30, tzinfo=timezone.utc)
            self.assertFalse(select_digest(st, [f], early, 6)[0])
            due, items = select_digest(st, [f], late, 6)
            self.assertTrue(due)
            self.assertEqual(len(items), 1)
            self.assertIn("Daily context", digest_message(items))
            st.seen["meta:digest"] = late.date().isoformat()
            self.assertFalse(select_digest(st, [f], late, 6)[0])
