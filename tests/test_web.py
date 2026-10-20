import json
import threading
import unittest
import urllib.error
import urllib.request

from cyberscope.web import Job, make_server

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class WebTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = make_server(0, Job())
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def _post(self, payload, content_type="application/json"):
        data = json.dumps(payload).encode() if not isinstance(payload, bytes) else payload
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/api/scan",
            data=data,
            headers={"Content-Type": content_type},
            method="POST",
        )
        try:
            with OPENER.open(req) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, json.loads(exc.read())

    def test_index_served(self):
        with OPENER.open(f"http://127.0.0.1:{self.port}/") as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn(b"CyberScope", resp.read())

    def test_scan_requires_permission(self):
        status, body = self._post({"target": "127.0.0.1", "permission": False})
        self.assertEqual(status, 403)
        self.assertIn("разрешение", body["error"])

    def test_rejects_wrong_content_type(self):
        status, _ = self._post({"target": "127.0.0.1", "permission": True}, content_type="text/plain")
        self.assertEqual(status, 415)

    def test_rejects_option_injection_target(self):
        status, body = self._post({"target": "-oX /tmp/x", "permission": True})
        self.assertEqual(status, 400)

    def test_rejects_bad_ports(self):
        status, _ = self._post({"target": "127.0.0.1", "ports": "80; rm", "permission": True})
        self.assertEqual(status, 400)

    def test_rejects_invalid_json(self):
        status, _ = self._post(b"{not json")
        self.assertEqual(status, 400)

    def test_unknown_route_404(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            OPENER.open(f"http://127.0.0.1:{self.port}/nope")
        with ctx.exception:
            self.assertEqual(ctx.exception.code, 404)


if __name__ == "__main__":
    unittest.main()
