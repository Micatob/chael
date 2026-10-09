import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest
import digest
from digest import build_digest, render_text, send_digest


class StubOS:
    """Canned OpenSearch: logs aggs + 2 incidents."""

    def search(self, index=None, body=None, ignore_unavailable=True):
        if "incident" in (index or ""):
            return {"hits": {"hits": [
                {"_source": {"incident_id": "aaa111", "timestamp": "t",
                             "risk_score": 85, "status": "OPEN",
                             "description": "SSH brute force"}},
                {"_source": {"incident_id": "bbb222", "timestamp": "t",
                             "risk_score": 40, "status": "INVESTIGATING",
                             "description": "odd login"}},
            ]}}
        return {"aggregations": {
            "by_sev": {"buckets": [{"key": "HIGH", "doc_count": 12},
                                   {"key": "INFO", "doc_count": 400}]},
            "by_host": {"buckets": [{"key": "web-01", "doc_count": 300}]}}}

    def count(self, index=None, body=None, ignore_unavailable=True):
        q = str(body)
        if "sla_breached" in q:
            return {"count": 1}
        if "RESOLVED" in q:
            return {"count": 3}
        return {"count": 412}


class TestBuildDigest:
    def test_numbers_assembled(self):
        d = build_digest(StubOS(), hours=24)
        assert d["logs_total"] == 412
        assert d["logs_by_severity"] == {"HIGH": 12, "INFO": 400}
        assert d["incidents_created"] == 2
        assert d["incidents_open"] == 3
        assert d["sla_breached"] == 1
        assert d["top_hosts"] == [("web-01", 300)]
        assert d["top_incidents"][0]["risk"] == 85

    def test_render_contains_key_lines(self):
        d = build_digest(StubOS(), hours=24)
        text = render_text(d, "daily")
        for needle in ("CHAEL SIEM DAILY DIGEST", "Logs ingested: 412",
                       "Incidents open: 3", "SLA breached: 1",
                       "SSH brute force", "do not reply"):
            assert needle in text

    def test_empty_window_message(self, monkeypatch):
        class Empty(StubOS):
            def search(self, index=None, body=None, ignore_unavailable=True):
                return {"hits": {"hits": []}, "aggregations": {}}

            def count(self, index=None, body=None, ignore_unavailable=True):
                return {"count": 0}

        text = render_text(build_digest(Empty()), "daily")
        assert "verify agents are shipping" in text

    def test_client_errors_never_raise(self):
        class Broken:
            def search(self, *a, **k):
                raise ConnectionError("down")

            def count(self, *a, **k):
                raise ConnectionError("down")

        d = build_digest(Broken())
        assert d["logs_total"] == 0 and d["incidents_created"] == 0


class TestSend:
    def test_disabled_without_smtp(self, monkeypatch):
        import digest as _d
        monkeypatch.setattr(_d.settings, "SMTP_HOST", "", raising=False)
        out = send_digest("daily", build_digest(StubOS()))
        assert out["sent"] is False and "not configured" in out["reason"]

    def test_sends_via_smtp(self, monkeypatch):
        import digest as _d
        import smtplib
        sent = {}

        class FakeSMTP:
            def __init__(self, *a, **k):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def starttls(self):
                sent["tls"] = True

            def login(self, u, p):
                sent["login"] = u

            def sendmail(self, frm, to, msg):
                sent["to"] = to
                sent["subject"] = "SUBJECT-CAPTURED"

        monkeypatch.setattr(_d.settings, "SMTP_HOST", "mail.local", raising=False)
        monkeypatch.setattr(_d.settings, "SMTP_TO", "soc@x.test, lead@x.test", raising=False)
        monkeypatch.setattr(_d.settings, "SMTP_USER", "bot", raising=False)
        monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
        out = send_digest("daily", build_digest(StubOS()))
        assert out["sent"] is True and sent["to"] == ["soc@x.test", "lead@x.test"]

    def test_non_ascii_body_encodes(self, monkeypatch):
        import digest as _d
        import smtplib
        import email
        captured = {}

        class FakeSMTP:
            def __init__(self, *a, **k):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def starttls(self):
                pass

            def login(self, u, p):
                pass

            def sendmail(self, frm, to, msg):
                captured["raw"] = msg

        monkeypatch.setattr(_d.settings, "SMTP_HOST", "mail.local", raising=False)
        monkeypatch.setattr(_d.settings, "SMTP_TO", "soc@x.test", raising=False)
        monkeypatch.setattr(_d.settings, "SMTP_USER", "", raising=False)
        monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
        out = send_digest("daily", build_digest(StubOS()))
        assert out["sent"] is True
        parsed = email.message_from_string(captured["raw"])
        body = parsed.get_payload(decode=True).decode("utf-8")
        assert "CHAEL SIEM DAILY DIGEST" in body
