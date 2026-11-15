#!/usr/bin/env python3
# Copyright (C) 2026, Leo Galambos
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# 3. All advertising materials mentioning features or use of this software must
#    display the following acknowledgement:
#    This product includes software developed by the Egothor project.
#
# 4. Neither the name of the copyright holder nor the names of its contributors
#    may be used to endorse or promote products derived from this software without
#    specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""Real localhost HTTPS coverage for extracted shared transport additions.

Existing test_exercise_pki transport coverage also runs against this exact class
through its compatibility re-export, including request/json/backup_transfer.
"""
import base64
import hashlib
import http.server
from pathlib import Path
import ssl
import tempfile
import threading
import unittest
from unittest.mock import patch
import pki_http as transport
import exercise_pki


class SharedTransportTest(unittest.TestCase):
    def test_compatibility_reexports_use_shared_class_and_failure(self):
        self.assertIs(transport.Api, exercise_pki.Api)
        self.assertIs(transport.ExerciseFailure, exercise_pki.ExerciseFailure)

    def test_download_no_clobber_truncation_and_private_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            certificate, key = root / "tls.pem", root / "tls.key"
            transport._openssl(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=Loopback fixture", "-addext", "subjectAltName=IP:127.0.0.1", "-addext", "extendedKeyUsage=serverAuth,clientAuth", "-keyout", key, "-out", certificate])
            binary = b"\x00\xff\x80DER\x00"
            calls = []
            deadline_observed = threading.Event()
            producer_observed = threading.Event()
            stopped_before_tail = []
            timeout_observed = threading.Event()
            timeout_producer_observed = threading.Event()
            timeout_stopped_before_tail = []

            class Handler(http.server.BaseHTTPRequestHandler):
                def do_GET(self):
                    calls.append(self.path)
                    if self.path in ("/json", "/invalid-json", "/redirect"):
                        raw = b'{"ok":true}' if self.path == "/json" else b'{"duplicate":1,"duplicate":2}'
                        self.send_response(302 if self.path == "/redirect" else 200)
                        self.send_header("Content-Length", str(len(raw)))
                        self.end_headers()
                        self.wfile.write(raw)
                        return
                    self.send_response(200)
                    self.send_header("Content-Disposition", 'attachment; filename="file.der"')
                    if "missing-length" not in self.path:
                        self.send_header("Content-Length", str(0 if "late-eof" in self.path else len(binary) + (2 if "truncated" in self.path else 0)))
                    digest = hashlib.sha256(b"wrong" if "bad-digest" in self.path else binary).digest()
                    self.send_header("Content-Digest", "sha-256=:" + base64.b64encode(digest).decode("ascii") + ":")
                    self.end_headers()
                    if "receive-timeout" in self.path:
                        timeout_stopped_before_tail.append(timeout_observed.wait(timeout=2))
                        timeout_producer_observed.set()
                        if not timeout_stopped_before_tail[-1]:
                            self.wfile.write(binary)
                    elif "deadline" in self.path:
                        self.wfile.write(binary[:1])
                        self.wfile.flush()
                        stopped_before_tail.append(deadline_observed.wait(timeout=2))
                        producer_observed.set()
                        if not stopped_before_tail[-1]:
                            self.wfile.write(binary[1:])
                    elif "late-eof" not in self.path:
                        self.wfile.write(binary)
                    self.close_connection = True

                def log_message(self, format, *args):
                    pass

            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certificate, key)
            context.load_verify_locations(certificate)
            context.verify_mode = ssl.CERT_REQUIRED
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                api = transport.Api("https://127.0.0.1:" + str(server.server_port), certificate, certificate, key)
                self.assertEqual(hashlib.sha256(certificate.read_bytes()).hexdigest(), api.client_identity_sha256)
                target = root / "artifact.der"
                path = "/admin/v1/certificate-artifacts/id/content?representation=original"
                api.download(path, target, overwrite=False, maximum=len(binary))
                self.assertEqual(binary, target.read_bytes())
                self.assertEqual(0o600, target.stat().st_mode & 0o777)
                with self.assertRaisesRegex(transport.ExerciseFailure, "already exists"):
                    api.download(path, target, overwrite=False)
                link = root / "link.der"
                link.symlink_to(root / "absent")
                with self.assertRaisesRegex(transport.ExerciseFailure, "already exists"):
                    api.download(path, link, overwrite=False)
                self.assertEqual(1, len(calls))
                status, document = api.json("GET", "/json")
                self.assertEqual((200, {"ok": True}), (status, document))
                with self.assertRaisesRegex(transport.ExerciseFailure, "Duplicate"):
                    api.json("GET", "/invalid-json")
                with self.assertRaisesRegex(transport.ExerciseFailure, "HTTP_302"):
                    api.request("GET", "/redirect")
                with self.assertRaisesRegex(transport.ExerciseFailure, "Invalid API path"):
                    api.request("GET", "//outside.invalid/path")
                with self.assertRaisesRegex(transport.ExerciseFailure, "truncated"):
                    api.download(path + "&truncated=1", root / "truncated.der", overwrite=False)
                with self.assertRaisesRegex(transport.ExerciseFailure, "byte bound"):
                    api.download(path, root / "oversize.der", maximum=len(binary) - 1, overwrite=False)
                with self.assertRaisesRegex(transport.ExerciseFailure, "byte bound"):
                    api.download(path, root / "zero.der", maximum=0, overwrite=False)
                for query, diagnostic in (("bad-digest", "digest"), ("missing-length", "length")):
                    with self.assertRaisesRegex(transport.ExerciseFailure, diagnostic):
                        api.download(path + "&" + query + "=1", root / (query + ".der"), overwrite=False)
                    self.assertFalse((root / (query + ".der")).exists())
                try:
                    with patch.object(transport.time, "monotonic", side_effect=[0] + [179.95] * 20):
                        with self.assertRaisesRegex(transport.ExerciseFailure, "transport failed"):
                            api.download(path + "&receive-timeout=1", root / "receive-timeout.der", overwrite=False)
                finally:
                    timeout_observed.set()
                self.assertTrue(timeout_producer_observed.wait(timeout=2))
                self.assertEqual([True], timeout_stopped_before_tail)
                self.assertFalse((root / "receive-timeout.der").exists())
                clock_calls = []

                def deadline_clock():
                    clock_calls.append(None)
                    if len(clock_calls) >= 3:
                        deadline_observed.set()
                        return 181
                    return 0

                # The producer withholds its tail until the client observes expiry.
                # Aggregating read() deadlocks this handshake until the safety timeout.
                with patch.object(transport.time, "monotonic", side_effect=deadline_clock):
                    with self.assertRaisesRegex(transport.ExerciseFailure, "time bound"):
                        api.download(path + "&deadline=1", root / "deadline.der", overwrite=False)
                self.assertTrue(producer_observed.wait(timeout=2))
                self.assertEqual([True], stopped_before_tail)
                with patch.object(transport.time, "monotonic", side_effect=[0, 0, 181]):
                    with self.assertRaisesRegex(transport.ExerciseFailure, "time bound"):
                        api.download(path + "&late-eof=1", root / "late-eof.der", overwrite=False)
                self.assertFalse((root / "deadline.der").exists())
                self.assertFalse((root / "late-eof.der").exists())
                self.assertEqual(binary, target.read_bytes())
                self.assertFalse((root / "truncated.der").exists())
                self.assertFalse((root / "oversize.der").exists())
                self.assertFalse(list(root.glob(".*.download")))
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
