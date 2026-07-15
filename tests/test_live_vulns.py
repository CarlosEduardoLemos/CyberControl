import unittest

from app_modules.live_vulns import filter_live_vulnerabilities, summarize_live_vulnerabilities


class LiveVulnsTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
