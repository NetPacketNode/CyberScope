import unittest

from cyberscope.core import ScanError, parse_nmap_xml, validate_ports, validate_target
from cyberscope.report import render_html

SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <hostnames><hostname name="lab.local" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9"/></port>
      <port protocol="tcp" portid="23"><state state="closed"/>
        <service name="telnet"/></port>
      <port protocol="tcp" portid="80"><state state="open"/>
        <service name="http" product="nginx"/></port>
    </ports>
  </host>
  <host>
    <status state="down"/>
    <address addr="192.168.1.11" addrtype="ipv4"/>
  </host>
</nmaprun>
"""


class ValidateTargetTests(unittest.TestCase):
    def test_accepts_ip_cidr_and_host(self):
        self.assertEqual(validate_target("10.0.0.5"), "10.0.0.5")
        self.assertEqual(validate_target("10.0.0.0/24"), "10.0.0.0/24")
        self.assertEqual(validate_target("Example.COM"), "example.com")

    def test_rejects_option_injection_and_garbage(self):
        for bad in ("-oX /tmp/x", "--script=x", "bad host", "", "a..b"):
            with self.subTest(bad=bad), self.assertRaises(ScanError):
                validate_target(bad)


class ValidatePortsTests(unittest.TestCase):
    def test_accepts_lists_and_ranges(self):
        self.assertEqual(validate_ports("22,80,443"), "22,80,443")
        self.assertEqual(validate_ports("1-1000"), "1-1000")

    def test_rejects_shell_and_option_characters(self):
        for bad in ("22; rm -rf", "-p", "80 -sS", ""):
            with self.subTest(bad=bad), self.assertRaises(ScanError):
                validate_ports(bad)


class ParseNmapTests(unittest.TestCase):
    def test_keeps_only_up_hosts_and_open_ports(self):
        hosts = parse_nmap_xml(SAMPLE_XML)
        self.assertEqual(len(hosts), 1)
        host = hosts[0]
        self.assertEqual(host.address, "192.168.1.10")
        self.assertEqual(host.hostname, "lab.local")
        self.assertEqual([p.number for p in host.ports], [22, 80])
        self.assertEqual(host.ports[0].product, "OpenSSH 8.9")
        self.assertEqual(host.ports[1].product, "nginx")


class ReportTests(unittest.TestCase):
    def test_escapes_html_in_target_and_rows(self):
        hosts = parse_nmap_xml(SAMPLE_XML)
        hosts[0].ports[0] = hosts[0].ports[0].__class__(
            number=22, proto="tcp", service="<script>", product="x"
        )
        page = render_html("<img src=x>", hosts, [])
        self.assertIn("&lt;img src=x&gt;", page)
        self.assertIn("&lt;script&gt;", page)
        self.assertNotIn("<script>", page)


class ExportTests(unittest.TestCase):
    def test_json_contains_hosts_and_ports(self):
        import json

        from cyberscope.core import DomainResult
        from cyberscope.report import to_json

        hosts = parse_nmap_xml(SAMPLE_XML)
        data = json.loads(to_json("192.168.1.10", hosts, [DomainResult("www.x.com", ["1.2.3.4"])]))
        self.assertEqual(data["hosts"][0]["ports"][0]["number"], 22)
        self.assertEqual(data["subdomains"][0]["name"], "www.x.com")

    def test_summary_shows_service_chart(self):
        hosts = parse_nmap_xml(SAMPLE_XML)
        page = render_html("192.168.1.10", hosts, [])
        self.assertIn("живых хостов", page)
        self.assertIn('<div class="bar">', page)


class WordlistTests(unittest.TestCase):
    def test_loads_labels_skipping_comments_and_duplicates(self):
        import os
        import tempfile

        from cyberscope.core import load_wordlist

        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as fh:
            fh.write("# comment\nwww\nAPI\nwww\n\n")
        try:
            self.assertEqual(load_wordlist(fh.name), ("www", "api"))
        finally:
            os.remove(fh.name)

    def test_rejects_invalid_labels(self):
        import os
        import tempfile

        from cyberscope.core import load_wordlist

        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as fh:
            fh.write("good\nbad label;rm\n")
        try:
            with self.assertRaises(ScanError):
                load_wordlist(fh.name)
        finally:
            os.remove(fh.name)


if __name__ == "__main__":
    unittest.main()
