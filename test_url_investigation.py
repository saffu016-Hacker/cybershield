"""Regression tests for CyberShield AI's URL investigation parser and analyzer.

Run from the project directory with: python -m unittest -v test_url_investigation.py
These tests do not contact reputation providers or visit submitted URLs.
"""
import ast
import os
import re
import unittest
from unittest.mock import patch
import socket
from pathlib import Path

from url_validation import normalize_and_parse_url

APP_PATH = Path(__file__).with_name("app.py")


class _Secrets(dict):
    def get(self, key, default=""):
        return super().get(key, default)


class _FakeStreamlit:
    secrets = _Secrets()


def _load_investigate_url():
    """Load only the analyzer function, without executing Streamlit UI code."""
    source = APP_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(APP_PATH))
    function_node = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "investigate_url"
    )
    isolated_module = ast.Module(body=[function_node], type_ignores=[])
    namespace = {"st": _FakeStreamlit(), "re": re, "normalize_and_parse_url": normalize_and_parse_url}
    exec(compile(isolated_module, str(APP_PATH), "exec"), namespace)
    return namespace["investigate_url"]


investigate_url = _load_investigate_url()


class URLParsingTests(unittest.TestCase):
    def test_flipkart_https(self):
        parsed = normalize_and_parse_url("https://flipkart.com")
        self.assertTrue(parsed["valid"], parsed["error"])
        self.assertEqual(parsed["host"], "flipkart.com")
        self.assertEqual(parsed["scheme"], "https")
        self.assertEqual(parsed["path"], "/")
        self.assertEqual(parsed["port"], 443)
        self.assertIsNone(parsed["explicit_port"])

    def test_surrounding_whitespace_is_trimmed(self):
        parsed = normalize_and_parse_url("  \t https://flipkart.com/path?q=1 \n")
        self.assertTrue(parsed["valid"], parsed["error"])
        self.assertEqual(parsed["url"], "https://flipkart.com/path?q=1")
        self.assertEqual(parsed["path"], "/path")

    def test_embedded_control_character_rejected(self):
        for url in ("https://flip\nkart.com", "https://example.com/\x00path", "https://example.com/\tpath"):
            with self.subTest(url=repr(url)):
                parsed = normalize_and_parse_url(url)
                self.assertFalse(parsed["valid"])
                self.assertIn("control character", parsed["error"].lower())

    def test_embedded_plain_space_rejected(self):
        parsed = normalize_and_parse_url("https://example.com/a b")
        self.assertFalse(parsed["valid"])
        self.assertIn("whitespace", parsed["error"].lower())

    def test_missing_scheme_rejected(self):
        parsed = normalize_and_parse_url("flipkart.com")
        self.assertFalse(parsed["valid"])
        self.assertIn("HTTP or HTTPS", parsed["error"])

    def test_unsupported_scheme_rejected(self):
        parsed = normalize_and_parse_url("ftp://example.com/file")
        self.assertFalse(parsed["valid"])

    def test_malformed_urls_rejected(self):
        for url in (
            "https:///missing-host",
            "https://example.com:99999/",
            "https://[not-ipv6]/",
            "https://999.999.999.999/",
            "https://bad host.example/",
        ):
            with self.subTest(url=url):
                self.assertFalse(normalize_and_parse_url(url)["valid"])

    def test_http_and_https_default_ports(self):
        http = normalize_and_parse_url("http://example.com")
        https = normalize_and_parse_url("https://example.com")
        self.assertEqual(http["port"], 80)
        self.assertEqual(https["port"], 443)

    def test_explicit_port_and_ipv6(self):
        custom = normalize_and_parse_url("https://example.com:8443/a")
        self.assertTrue(custom["valid"], custom["error"])
        self.assertEqual(custom["port"], 8443)
        self.assertEqual(custom["explicit_port"], 8443)
        ipv6 = normalize_and_parse_url("http://[2001:4860:4860::8888]:8080/")
        self.assertTrue(ipv6["valid"], ipv6["error"])
        self.assertEqual(ipv6["host"], "2001:4860:4860::8888")
        self.assertEqual(ipv6["port"], 8080)

    def test_url_shapes(self):
        cases = [
            "https://flipkart.com",
            "https://www.flipkart.com/search?q=phone&page=2",
            "http://example.org/login?next=%2Fhome#section",
            "https://127.0.0.1:8443/admin",
            "https://bit.ly/abc123",
            "https://sub.example.co.in/a/b?x=1&y=two",
            "https://user:pass@example.com/path",
            "https://xn--pple-43d.com/",
        ]
        for url in cases:
            with self.subTest(url=url):
                parsed = normalize_and_parse_url(url)
                self.assertTrue(parsed["valid"], parsed["error"])
                self.assertTrue(parsed["host"])
                self.assertIn(parsed["scheme"], ("http", "https"))
                self.assertTrue(parsed["path"].startswith("/"))
                self.assertIsInstance(parsed["port"], int)


class AnalyzerIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.old_google = os.environ.pop("GOOGLE_SAFE_BROWSING_API_KEY", None)
        self.old_vt = os.environ.pop("VIRUSTOTAL_API_KEY", None)

    def tearDown(self):
        if self.old_google is not None:
            os.environ["GOOGLE_SAFE_BROWSING_API_KEY"] = self.old_google
        if self.old_vt is not None:
            os.environ["VIRUSTOTAL_API_KEY"] = self.old_vt

    def test_flipkart_analyzes_without_invalid_input(self):
        result = investigate_url("https://flipkart.com")
        self.assertTrue(result["url_valid"])
        self.assertEqual(result["host"], "flipkart.com")
        self.assertEqual(result["scheme"], "https")
        self.assertEqual(result["path"], "/")
        self.assertEqual(result["port"], 443)
        self.assertNotEqual(result["verdict"], "Invalid input")
        # A parse success is explicitly not a safety certification.
        self.assertIn("does not prove", result["recommendation"].lower())

    def test_surrounding_whitespace_reaches_analysis(self):
        result = investigate_url("  https://flipkart.com  ")
        self.assertTrue(result["url_valid"])
        self.assertEqual(result["url"], "https://flipkart.com")

    def test_control_character_is_rejected_with_specific_error(self):
        result = investigate_url("https://flip\nkart.com")
        self.assertFalse(result["url_valid"])
        self.assertEqual(result["verdict"], "Invalid input")
        self.assertIn("control character", result["evidence"][0].lower())


    def test_live_inspection_extracts_page_details_with_mock_response(self):
        class FakeResponse:
            status_code = 200
            headers = {
                "Content-Type": "text/html; charset=utf-8",
                "Content-Security-Policy": "default-src 'self'",
                "X-Content-Type-Options": "nosniff",
            }
            is_redirect = False
            is_permanent_redirect = False
            encoding = "utf-8"

            def iter_content(self, chunk_size=8192):
                yield b"<html><head><title>Test Site</title></head><body><input type=\"password\"></body></html>"

            def close(self):
                pass

        public_dns = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
        with patch("socket.getaddrinfo", return_value=public_dns), patch("requests.get", return_value=FakeResponse()):
            result = investigate_url("https://example.com", check_live=True)
        live = result["website_check"]
        self.assertTrue(live["performed"])
        self.assertEqual(live["http_status"], 200)
        self.assertEqual(live["page_title"], "Test Site")
        self.assertTrue(any("password input" in item for item in live["findings"]))

    def test_live_inspection_blocks_private_destination(self):
        with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]), patch("requests.get") as mock_get:
            result = investigate_url("https://example.test", check_live=True)
        self.assertEqual(result["website_check"]["status"], "Blocked")
        self.assertIn("private", result["website_check"]["error"].lower())
        mock_get.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
