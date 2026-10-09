from unittest.mock import patch, MagicMock
import json


class TestOTXFeed:
    def test_skipped_when_no_key(self):
        from feeds.otx import OTXFeed
        feed = OTXFeed(api_key="")
        result = feed.poll()
        assert result == []

    @patch("urllib.request.urlopen")
    def test_parse_otx_response(self, mock_urlopen):
        from feeds.otx import OTXFeed
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "results": [{
                "name": "Test Pulse",
                "description": "A test pulse",
                "TLP": "AMBER",
                "tags": ["malware"],
                "reference": "https://example.com",
                "indicators": [{
                    "type": "IPv4",
                    "indicator": "203.0.113.42",
                    "created": "2026-01-01T00:00:00",
                }],
            }]
        }).encode()
        mock_urlopen.return_value.__enter__.return_value = mock_response

        feed = OTXFeed(api_key="test-key")
        result = feed.poll()
        assert len(result) == 3
        assert result[0]["type"] == "IPV4"
        assert result[0]["value"] == "203.0.113.42"
        assert result[0]["feed"] == "alienvault-otx"
        assert result[0]["tlp"] == "AMBER"

    @patch("urllib.request.urlopen")
    def test_handles_network_error(self, mock_urlopen):
        from feeds.otx import OTXFeed
        mock_urlopen.side_effect = Exception("Connection refused")
        feed = OTXFeed(api_key="test-key")
        result = feed.poll()
        assert result == []


class TestURLhausFeed:
    def test_parse_urlhaus_csv(self):
        from feeds.urlhaus import URLhausFeed
        feed = URLhausFeed()
        sample_csv = (
            '1,2016-01-01 00:00:00,https://example.com/malware.exe,'
            'online,2026-01-01,malware_download,"test-tag",https://urlhaus.abuse.ch/url/1,reporter\n'
        )
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_response = MagicMock()
            mock_response.read.return_value = sample_csv.encode()
            mock_urlopen.return_value.__enter__.return_value = mock_response

            result = feed.poll()
            assert len(result) == 1
            assert result[0]["type"] == "URL"
            assert "example.com/malware.exe" in result[0]["value"]
            assert result[0]["feed"] == "urlhaus"

    @patch("urllib.request.urlopen")
    def test_handles_network_error(self, mock_urlopen):
        from feeds.urlhaus import URLhausFeed
        mock_urlopen.side_effect = Exception("Timeout")
        feed = URLhausFeed()
        result = feed.poll()
        assert result == []


class TestScheduler:
    def test_scheduler_exists(self):
        from feeds.scheduler import FeedScheduler
        scheduler = FeedScheduler()
        assert scheduler is not None
        assert hasattr(scheduler, 'poll_all')

    @patch("feeds.scheduler.FeedScheduler.poll_all")
    def test_scheduler_poll_all(self, mock_poll):
        from feeds.scheduler import FeedScheduler
        scheduler = FeedScheduler()
        mock_poll.return_value = 10
        result = scheduler.poll_all()
        assert result == 10
