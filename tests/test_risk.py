import unittest

from app_modules.risk import calculate_risk_score, risk_level


class RiskTests(unittest.TestCase):
    def test_cvss_only(self):
        self.assertEqual(calculate_risk_score(7.5), 7.5)
        self.assertEqual(risk_level(7.5), "Alto")

    def test_critical_asset_increases_risk(self):
        self.assertGreater(calculate_risk_score(7.5, "Crítica"), 7.5)

    def test_exposure_and_kev_increase_risk(self):
        base = calculate_risk_score(6.0)
        enriched = calculate_risk_score(6.0, "Média", True, True)
        self.assertGreater(enriched, base)
        self.assertEqual(risk_level(enriched), "Alto")

    def test_score_is_capped(self):
        self.assertEqual(calculate_risk_score(10, "Crítica", True, True), 10.0)


if __name__ == "__main__":
    unittest.main()
