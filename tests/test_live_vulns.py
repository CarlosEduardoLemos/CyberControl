import unittest
from unittest.mock import patch

import app_modules.live_vulns as live_vulns
from app_modules.live_vulns import filter_live_vulnerabilities, summarize_live_vulnerabilities


class LiveVulnsTests(unittest.TestCase):
    def setUp(self):
        live_vulns.LIVE_VULNS_CACHE = []
        live_vulns.LIVE_VULNS_ERROR = None
        live_vulns.LIVE_VULNS_FETCHED_AT = None

    def test_summarize_live_vulnerabilities_counts_by_source_and_severity(self):
        items = [
            {"source": "CISA KEV", "severity": "Alta"},
            {"source": "CISA KEV", "severity": "Alta"},
            {"source": "NVD", "severity": "Crítica"},
        ]
        summary = summarize_live_vulnerabilities(items)
        self.assertEqual(summary["total"], 3)
        self.assertEqual(summary["by_source"]["CISA KEV"], 2)
        self.assertEqual(summary["by_severity"]["Alta"], 2)
        self.assertEqual(summary["by_severity"]["Crítica"], 1)

    def test_filter_live_vulnerabilities_by_severity(self):
        items = [
            {"title": "CVE-1", "severity": "Alta"},
            {"title": "CVE-2", "severity": "Crítica"},
            {"title": "CVE-3", "severity": "Média"},
        ]
        filtered = filter_live_vulnerabilities(items, severity_filter="Crítica")
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]["title"], "CVE-2")

    @patch("app_modules.live_vulns._fetch_live_vulnerabilities")
    def test_cached_data_is_filtered_per_request(self, fetch_mock):
        fetch_mock.return_value = (
            [
                {"id": "CVE-A", "title": "Alpha", "description": "", "source": "NVD", "severity": "Alta", "link": "#"},
                {"id": "CVE-B", "title": "Beta", "description": "", "source": "NVD", "severity": "Alta", "link": "#"},
            ],
            None,
        )
        first, _ = live_vulns.refresh_live_vulnerabilities(force=True, search_term="alpha")
        second, _ = live_vulns.refresh_live_vulnerabilities(search_term="beta")
        self.assertEqual([item["id"] for item in first], ["CVE-A"])
        self.assertEqual([item["id"] for item in second], ["CVE-B"])
        self.assertEqual(fetch_mock.call_count, 1)


if __name__ == "__main__":
    unittest.main()
