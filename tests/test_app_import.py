import unittest

from cybercontrol import app


class AppImportTestCase(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_login_page_loads(self):
        response = self.client.get("/login")
        self.assertEqual(response.status_code, 200)


if __name__ == "__main__":
    unittest.main()
