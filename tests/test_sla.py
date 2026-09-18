import unittest
from datetime import date

from app_modules.sla import default_due_date, sla_status


class SlaTests(unittest.TestCase):
    def test_default_due_date_uses_severity_policy(self):
        self.assertEqual(default_due_date("2026-01-01", "Crítica"), "2026-01-08")
        self.assertEqual(default_due_date("2026-01-01", "Alta"), "2026-01-16")

    def test_sla_status(self):
        today = date(2026, 1, 10)
        self.assertEqual(sla_status("2026-01-09", "Aberta", today=today), "Vencido")
        self.assertEqual(sla_status("2026-01-12", "Aberta", today=today), "Próximo do vencimento")
        self.assertEqual(sla_status("2026-02-01", "Aberta", today=today), "Dentro do SLA")
        self.assertEqual(sla_status("2026-01-01", "Resolvida", today=today), "Resolvida")


if __name__ == "__main__":
    unittest.main()
