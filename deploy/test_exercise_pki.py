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

"""Validation, real TLS generation and systemd contracts for rootless installation."""
import json
import http.server
import threading
import os
from pathlib import Path
import ssl
import tempfile
import unittest
from unittest.mock import patch

import exercise_pki as exercise


def envelope(operation, result, status="SUCCEEDED"):
    return {"version": 1, "operation": operation, "status": status, "failure": None, "requestId": "wire", "result": result}


class FakeApi:
    origin = "https://pki.invalid:8443"

    def __init__(self, *, lost=False, denied=False, terminal=None):
        self.calls, self.records = [], {}
        self.lost, self.denied, self.terminal = lost, denied, terminal

    def json(self, method, path, document=None):
        self.calls.append((method, path, document))
        if path == "/admin/v1/schema":
            return 200, [{"operationId": "ca.create", "scope": "realm", "fields": [{"name": "subjectRef", "required": True, "type": "text"}]},
                         {"operationId": "security.approval.approve", "scope": "realm", "fields": [{"name": name, "required": True, "type": "text"} for name in ("approvalId", "justification")]}]
        if path == "/admin/v1/operations":
            return 200, envelope("operation.list", {"operations": [{"operation": "ca.create", "durableRequest": True}, {"operation": "security.approval.approve", "durableRequest": False}]})
        if method == "POST" and path == "/admin/v1/requests":
            record = {"requestId": document["requestId"], "operation": document["operation"], "state": self.terminal or "WAITING_APPROVAL", "approvalId": "approval-one"}
            self.records[document["requestId"]] = record
            if self.lost:
                self.lost = False
                raise exercise.ExerciseFailure("Acknowledgement lost")
            return 202, envelope("administrative.request.submit", record, "PENDING")
        if method == "GET" and path.startswith("/admin/v1/requests/"):
            identity = path.rsplit("/", 1)[1]
            if identity not in self.records:
                raise exercise.ExerciseFailure("Not found", 404)
            return 200, envelope("administrative.request.inspect", self.records[identity])
        if path.endswith("/security.approval.approve"):
            if self.denied:
                raise exercise.ExerciseFailure("AUTHORIZATION_DENIED", 403)
            for record in self.records.values():
                record.update(state="SUCCEEDED", result={"caId": "ca:new", "credentialId": "cert:new"})
            return 200, envelope("security.approval.approve", {"value": {"state": "APPROVED"}})
        raise AssertionError((method, path))


class DurableExerciseTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name) / "results"
        self.instances = []

    def tearDown(self):
        for instance in self.instances:
            instance.close()
        self.temporary.cleanup()

    def instance(self, api):
        value = exercise.Exercise(api, self.directory, sleep=lambda seconds: None)
        self.instances.append(value)
        value.discover()
        return value

    def test_canonical_ocsp_id_is_retained_and_observed_without_reposting(self):
        canonical='ocsp-prov:'+'a'*64+':r1'
        api=FakeApi()
        original=api.json
        def json_call(method,path,document=None):
            if method=='POST' and path=='/admin/v1/requests':
                api.calls.append((method,path,document))
                api.records[canonical]={'requestId':canonical,'operation':document['operation'],
                    'state':'SUCCEEDED','result':{'credentialId':'responder-cert'}}
                return 202,envelope('administrative.request.submit',api.records[canonical])
            if method=='GET' and path.endswith(canonical.replace(':','%3A')):
                api.calls.append((method,path,document))
                return 200,envelope('administrative.request.inspect',api.records[canonical])
            return original(method,path,document)
        api.json=json_call
        run=self.instance(api)
        operation='ocsp.responder.issue-certificate'
        run.schema[operation]={'fields':[],'scope':'realm'}
        run.descriptors[operation]={'durableRequest':True}
        self.assertEqual({'credentialId':'responder-cert'},run.job('responder',operation,{}))
        run.job('responder',operation,{})
        self.assertEqual(canonical,run.state['jobs']['responder']['canonicalRequestId'])
        self.assertNotEqual(canonical,run.state['jobs']['responder']['intent']['requestId'])
        self.assertEqual(1,sum(m=='POST' and p=='/admin/v1/requests' for m,p,_ in api.calls))
        self.assertIn(('GET','/admin/v1/requests/'+canonical.replace(':','%3A'),None),api.calls)

    def test_provisioning_lost_ack_remains_unknown_without_get_or_repost(self):
        api=FakeApi(lost=True)
        run=self.instance(api)
        operation='ocsp.responder.issue-certificate'
        run.schema[operation]={'fields':[],'scope':'realm'}
        run.descriptors[operation]={'durableRequest':True}
        for _ in range(2):
            with self.assertRaisesRegex(exercise.ExerciseFailure,'acknowledgement unknown'):
                run.job('responder',operation,{})
        self.assertEqual(1,sum(m=='POST' and p=='/admin/v1/requests' for m,p,_ in api.calls))
        self.assertFalse(any(m=='GET' and p.startswith('/admin/v1/requests/') for m,p,_ in api.calls))

    def test_canonical_exception_rejects_malformed_changed_and_other_operation_ids(self):
        for canonical,operation in (('ocsp-prov:'+'A'*64+':r1','ocsp.responder.issue-certificate'),
                ('ocsp-prov:'+'a'*64+':r0','ocsp.responder.issue-certificate'),
                ('ocsp-prov:'+'a'*64+':r9223372036854775808','ocsp.responder.issue-certificate'),
                ('ocsp-prov:'+'a'*64+':r1','ca.create')):
            with self.subTest(canonical=canonical,operation=operation):
                with tempfile.TemporaryDirectory() as directory:
                    api=FakeApi()
                    original=api.json
                    def json_call(method,path,document=None):
                        if method=='POST' and path=='/admin/v1/requests':
                            return 202,envelope('administrative.request.submit',{'requestId':canonical,
                                'operation':document['operation'],'state':'SUCCEEDED','result':{'credentialId':'cert'}})
                        return original(method,path,document)
                    api.json=json_call
                    run=exercise.Exercise(api,Path(directory)/'run')
                    self.addCleanup(run.close)
                    if run:
                        run.discover()
                        run.schema[operation]={'fields':[],'scope':'realm'}
                        run.descriptors[operation]={'durableRequest':True}
                        with self.assertRaises(exercise.ExerciseFailure): run.job('target',operation,{})
        api=FakeApi()
        run=self.instance(api)
        operation='ocsp.responder.issue-certificate'
        run.schema[operation]={'fields':[],'scope':'realm'}
        run.descriptors[operation]={'durableRequest':True}
        name='changed'
        intent={'version':1,'requestId':'exercise-'+run.state['runId']+'-'+name,'operation':operation,'arguments':{}}
        run.state['jobs'][name]={'intent':intent,'attempted':True,'decisionAttempted':False,
            'canonicalRequestId':'ocsp-prov:'+'a'*64+':r1'}
        api.json=lambda *args: (200,envelope('administrative.request.inspect',{'requestId':'ocsp-prov:'+'b'*64+':r1',
            'operation':operation,'state':'SUCCEEDED','result':{'credentialId':'cert'}}))
        with self.assertRaisesRegex(exercise.ExerciseFailure,'retained target'):run.job(name,operation,{})

    def test_submits_once_with_explicit_reason_and_terminal_receipt(self):
        api = FakeApi()
        run = self.instance(api)
        self.assertEqual("ca:new", run.job("ca", "ca.create", {"subjectRef": "CN=Demo"})["caId"])
        run.job("ca", "ca.create", {"subjectRef": "CN=Demo"})
        self.assertEqual(1, sum(method == "POST" and path == "/admin/v1/requests" for method, path, _ in api.calls))
        decision = next(body for _, path, body in api.calls if path.endswith("/security.approval.approve"))
        self.assertIn(run.state["runId"], decision["arguments"]["justification"])
        self.assertEqual("EXECUTED", run.state["coverage"]["ca.create"]["state"])
        self.assertEqual(3, run.report(strict=True))
        self.assertEqual(set(exercise.CATALOG_IDS), set(json.loads((self.directory / "report.json").read_text())["coverage"]))

    def test_lost_acknowledgement_recovers_by_get_without_second_mutation(self):
        api = FakeApi(lost=True)
        run = self.instance(api)
        run.job("ca", "ca.create", {"subjectRef": "CN=Demo"})
        self.assertEqual(1, sum(path == "/admin/v1/requests" for _, path, _ in api.calls))
        self.assertTrue(any(method == "GET" for method, path, _ in api.calls if path.startswith("/admin/v1/requests/")))

    def test_missing_own_approval_grant_is_blocked_and_can_resume_after_external_decision(self):
        api = FakeApi(denied=True)
        run = self.instance(api)
        with self.assertRaisesRegex(exercise.ExerciseFailure, "externally"):
            run.job("ca", "ca.create", {"subjectRef": "CN=Demo"})
        self.assertEqual("BLOCKED", run.state["coverage"]["ca.create"]["state"])
        run.close()
        record = next(iter(api.records.values()))
        record.update(state="SUCCEEDED", result={"caId": "ca:new"})
        resumed = self.instance(api)
        self.assertEqual("ca:new", resumed.job("ca", "ca.create", {"subjectRef": "CN=Demo"})["caId"])
        self.assertEqual(1, sum(path == "/admin/v1/requests" for _, path, _ in api.calls))

    def test_rejected_and_expired_requests_preserve_receipts_and_do_not_resubmit(self):
        for terminal in ("REJECTED", "EXPIRED"):
            with self.subTest(terminal=terminal), tempfile.TemporaryDirectory() as location:
                api = FakeApi(terminal=terminal)
                run = exercise.Exercise(api, Path(location) / "results", sleep=lambda seconds: None)
                try:
                    run.discover()
                    for attempt in range(2):
                        with self.assertRaisesRegex(exercise.ExerciseFailure, terminal):
                            run.job("ca", "ca.create", {"subjectRef": "CN=Demo"})
                    self.assertEqual(1, sum(path == "/admin/v1/requests" for _, path, _ in api.calls))
                    self.assertEqual("FAILED", run.state["coverage"]["ca.create"]["state"])
                finally:
                    run.close()

    def test_schema_mismatch_and_changed_target_never_send_another_post(self):
        api = FakeApi()
        run = self.instance(api)
        with self.assertRaises(exercise.ExerciseFailure):
            run.job("ca", "ca.create", {"unknown": "value"})
        self.assertFalse(any(path == "/admin/v1/requests" for _, path, _ in api.calls))
        run.job("ca", "ca.create", {"subjectRef": "CN=Demo"})
        with self.assertRaisesRegex(exercise.ExerciseFailure, "target changed"):
            run.job("ca", "ca.create", {"subjectRef": "CN=Different"})
        self.assertEqual(1, sum(path == "/admin/v1/requests" for _, path, _ in api.calls))

    def test_preflight_detects_missing_status_grant_without_any_mutation(self):
        class Preflight:
            def __init__(self, denied=False):
                self.calls=[]
                self.denied=denied
            def operation(self, operation, arguments):
                self.calls.append((operation,arguments))
                if operation == "security.grant.list":
                    return {"items":[{"principalId":"admin","enabled":True,"effect":"ALLOW","action":"APPROVAL_DECIDE_OWN"}],"hasMore":False}
                return {"allowed": not (self.denied and arguments["action"] == "CRL_DOWNLOAD")}
        ready=Preflight()
        exercise._preflight_access(ready,"admin")
        self.assertEqual(4,len(ready.calls))
        denied=Preflight(True)
        with self.assertRaisesRegex(exercise.ExerciseFailure,"--status-access"):
            exercise._preflight_access(denied,"admin")
        self.assertEqual(3,len(denied.calls))
        unknown=Preflight()
        with self.assertRaisesRegex(exercise.ExerciseFailure,"--principal-id"):
            exercise._preflight_access(unknown,None)
        self.assertFalse(unknown.calls)

    def test_dedicated_mutation_reuses_its_exact_acknowledged_receipt(self):
        api=FakeApi()
        run=self.instance(api)
        arguments={"approvalId":"owned","justification":"Explicit local test"}
        first=run.dedicated("decision","security.approval.approve",arguments)
        self.assertEqual(first,run.dedicated("decision","security.approval.approve",arguments))
        self.assertEqual(1,sum(path.endswith("/security.approval.approve") for _,path,_ in api.calls))
        with self.assertRaisesRegex(exercise.ExerciseFailure,"action changed"):
            run.dedicated("decision","security.approval.approve",dict(arguments,justification="Different intent"))

    def test_one_time_capability_never_reaches_any_receipt_or_checkpoint(self):
        token="cap-sensitive-fixture-bearer"
        class CapabilityApi(FakeApi):
            def json(self,method,path,document=None):
                if path.endswith("/security.disclosure.capability.issue"):
                    self.calls.append((method,path,document))
                    return 200,envelope("security.disclosure.capability.issue",{"capabilityId":"safe-id","token":token})
                return super().json(method,path,document)
        api=CapabilityApi()
        run=self.instance(api)
        run.schema["security.disclosure.capability.issue"]={"scope":"realm","fields":[]}
        run.descriptors["security.disclosure.capability.issue"]={"durableRequest":False}
        response=run.dedicated("capability","security.disclosure.capability.issue",{})
        self.assertEqual(token,response["token"])
        retained=run.dedicated("capability","security.disclosure.capability.issue",{})
        self.assertNotIn("token",retained)
        self.assertEqual("safe-id",retained["capabilityId"])
        self.assertEqual(1,sum(path.endswith("/security.disclosure.capability.issue") for _,path,_ in api.calls))
        run.report()
        for path in self.directory.iterdir():
            if path.is_file(): self.assertNotIn(token.encode(),path.read_bytes(),str(path))

    def test_concurrent_output_and_unsafe_url_are_rejected(self):
        run = self.instance(FakeApi())
        with self.assertRaisesRegex(exercise.ExerciseFailure, "Another exercise"):
            exercise.Exercise(FakeApi(), self.directory)
        for url in ("http://pki.invalid", "https://user:secret@pki.invalid", "https://pki.invalid/path", "https://pki.invalid/?token=secret"):
            with self.assertRaises(exercise.ExerciseFailure):
                exercise.Api(url, "absent", "absent", "absent")
        self.assertEqual(0o600, (self.directory / "checkpoint.json").stat().st_mode & 0o777)


class OpenSslExerciseIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.mask = os.umask(0o077)
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()
        os.umask(self.mask)

    def test_system_random_client_key_and_csr_are_private_and_retainable(self):
        first = self.root / "one"
        second = self.root / "two"
        first.mkdir(); second.mkdir()
        key, csr, der = exercise._generate_client(first, "first")
        other, _, _ = exercise._generate_client(second, "second")
        self.assertNotEqual(key.read_bytes(), other.read_bytes())
        self.assertEqual(0o600, key.stat().st_mode & 0o777)
        before = key.read_bytes()
        exercise._generate_client(first, "first")
        self.assertEqual(before, key.read_bytes())
        self.assertIn(b"spiffe://zeroecho.invalid/demo/first", exercise._openssl(["req", "-in", csr, "-text", "-noout"]))
        self.assertTrue(der.read_bytes())

    def test_missing_retained_client_key_or_csr_fails_before_generating_an_unrelated_identity(self):
        (self.root / "client.csr").write_text("retained CSR")
        with patch.object(exercise, "_openssl") as openssl:
            with self.assertRaisesRegex(exercise.ExerciseFailure, "private key is missing"):
                exercise._generate_client(self.root, "retained")
            openssl.assert_not_called()
        (self.root / "client.csr").unlink()
        (self.root / "client.key").write_text("retained private key")
        exercise._atomic_json(self.root / "checkpoint.json", {"clientKeySha256": "retained"})
        with patch.object(exercise, "_openssl") as openssl:
            with self.assertRaisesRegex(exercise.ExerciseFailure, "CSR is missing"):
                exercise._generate_client(self.root, "retained")
            openssl.assert_not_called()

    def test_real_certificates_key_match_full_and_delta_crl_verification(self):
        key, csr, _ = exercise._generate_client(self.root, "integration")
        exercise._openssl(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=Demo CA", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-keyout", self.root / "ca.key", "-out", self.root / "ca.pem"])
        (self.root / "index").write_text("")
        (self.root / "serial").write_text("01\n")
        (self.root / "number").write_text("01\n")
        (self.root / "certs").mkdir()
        configuration = self.root / "openssl.cnf"
        configuration.write_text(f"""[ca]
default_ca=main
[main]
database={self.root}/index
new_certs_dir={self.root}/certs
certificate={self.root}/ca.pem
private_key={self.root}/ca.key
serial={self.root}/serial
crlnumber={self.root}/number
default_md=sha256
default_days=2
default_crl_days=2
policy=policy
x509_extensions=client
copy_extensions=copy
[policy]
commonName=supplied
[client]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
[delta]
authorityKeyIdentifier=keyid:always
2.5.29.27=critical,DER:02:01:01
""")
        exercise._openssl(["ca", "-batch", "-config", configuration, "-in", csr, "-out", self.root / "client.pem"])
        for name in ("ca", "client"):
            exercise._openssl(["x509", "-in", self.root / (name + ".pem"), "-outform", "DER", "-out", self.root / (name + ".der")])
        serial = exercise._verify_certificates(self.root)
        exercise._openssl(["ca", "-gencrl", "-config", configuration, "-out", self.root / "full.pem"])
        exercise._openssl(["ca", "-config", configuration, "-revoke", self.root / "client.pem", "-crl_reason", "keyCompromise"])
        exercise._openssl(["ca", "-gencrl", "-config", configuration, "-crlexts", "delta", "-out", self.root / "delta.pem"])
        exercise._openssl(["ca", "-gencrl", "-config", configuration, "-out", self.root / "full-after.pem"])
        for name in ("full", "delta", "full-after"):
            exercise._openssl(["crl", "-in", self.root / (name + ".pem"), "-outform", "DER", "-out", self.root / (name + ".der")])
        exercise._verify_crls(self.root, serial)
        with self.assertRaisesRegex(exercise.ExerciseFailure, "serial"):
            exercise._verify_crls(self.root, "FFFFFF")
        exercise._openssl(["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", key])
        with self.assertRaisesRegex(exercise.ExerciseFailure, "private key"):
            exercise._verify_certificates(self.root)

    def test_pkcs12_password_is_stdin_only_and_extracted_files_are_private(self):
        exercise._openssl(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=Local identity", "-keyout", self.root / "identity.key", "-out", self.root / "identity.pem"])
        password = "fixture-only password ! unicode č"
        p12 = self.root / "identity.p12"
        exercise._openssl(["pkcs12", "-export", "-inkey", self.root / "identity.key", "-in", self.root / "identity.pem", "-out", p12, "-passout", "stdin"], secret=password)
        actual = exercise.subprocess.run
        commands = []
        def observed(arguments, **kwargs):
            commands.append((arguments, kwargs))
            return actual(arguments, **kwargs)
        with patch.object(exercise.subprocess, "run", side_effect=observed):
            identity, key = exercise._identity(self.root, p12, password)
        self.assertEqual(0o600, identity.stat().st_mode & 0o777)
        self.assertEqual(0o600, key.stat().st_mode & 0o777)
        for arguments, options in commands:
            self.assertNotIn(password, repr(arguments))
            self.assertNotIn("env", options)
            self.assertEqual(password.encode() + b"\n", options["input"])
        with self.assertRaises(exercise.ExerciseFailure):
            exercise._identity(self.root, p12, "wrong password")


class HttpsTransportIntegrationTest(unittest.TestCase):
    def test_real_tls_separates_admin_and_anonymous_clients_and_preserves_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            certificate, key = root / "tls.pem", root / "tls.key"
            exercise._openssl(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=Loopback fixture", "-addext", "subjectAltName=IP:127.0.0.1", "-addext", "extendedKeyUsage=serverAuth,clientAuth", "-keyout", key, "-out", certificate])
            peers = []
            posts = []
            binary = b"\x00\xff\x80DER\x00"
            class Handler(http.server.BaseHTTPRequestHandler):
                def do_GET(self):
                    peers.append(bool(self.connection.getpeercert()))
                    self.send_response(200)
                    self.send_header("Content-Disposition", 'attachment; filename="file.der"')
                    self.send_header("Content-Length", str(len(binary)))
                    self.end_headers()
                    self.wfile.write(binary)
                def do_POST(self):
                    received=self.rfile.read(int(self.headers["Content-Length"]))
                    posts.append((self.path,received))
                    if b"lost" in received:
                        self.close_connection=True
                        return
                    if self.path.endswith("/upload"):
                        raw=json.dumps(envelope("backup.stream.upload",{"value":{"state":"READY","length":len(received),"sha256":exercise.hashlib.sha256(received).hexdigest()}})).encode()
                        self.send_response(200);self.send_header("Content-Length",str(len(raw)));self.end_headers();self.wfile.write(raw)
                        return
                    self.send_response(200)
                    self.send_header("Content-Length",str(len(binary)+(2 if b"truncated" in received else 0)))
                    self.end_headers();self.wfile.write(binary)
                    if b"truncated" in received:self.close_connection=True
                def log_message(self, format, *args):
                    pass
            try:
                server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            except PermissionError as unavailable:
                self.skipTest("Native loopback sockets are denied by the execution environment: " + str(unavailable))
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certificate, key)
            context.load_verify_locations(certificate)
            context.verify_mode = ssl.CERT_OPTIONAL
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            origin = "https://127.0.0.1:" + str(server.server_port)
            try:
                admin = exercise.Api(origin, certificate, certificate, key)
                public = exercise.Api(origin, certificate)
                target = root / "attachment.der"
                admin.download("/admin/v1/certificate-artifacts/id/content?representation=original", target)
                self.assertEqual(binary, target.read_bytes())
                public.request("GET", "/public/v1/status/id")
                self.assertEqual([True, False], peers)
                with self.assertRaisesRegex(exercise.ExerciseFailure, "byte bound"):
                    admin.download("/admin/v1/status-artifacts/id/content?representation=original", root / "oversize.der", maximum=3)
                self.assertFalse((root / "oversize.der").exists())
                copied=root/"backup.zip"
                downloaded=admin.backup_transfer("download","owned-handle",target=copied)
                self.assertEqual(binary,copied.read_bytes())
                self.assertEqual(len(binary),downloaded["length"])
                uploaded=admin.backup_transfer("upload","upload-handle",source=copied)
                self.assertEqual(exercise.hashlib.sha256(binary).hexdigest(),uploaded["sha256"])
                for handle,bound,expected in (("truncated",100,"truncated"),("owned-handle",3,"byte bound"),("lost",100,"unknown")):
                    destination=root/(handle+".zip")
                    before=len(posts)
                    with self.assertRaisesRegex(exercise.ExerciseFailure,expected):
                        admin.backup_transfer("download",handle,target=destination,maximum=bound)
                    self.assertEqual(before+1,len(posts))
                    self.assertFalse(destination.exists())
                with patch.object(exercise.time,"monotonic",side_effect=[0,181]):
                    with self.assertRaisesRegex(exercise.ExerciseFailure,"total deadline"):
                        admin.backup_transfer("download","deadline",target=root/"deadline.zip")
                self.assertFalse((root/"deadline.zip").exists())
                self.assertFalse(list(root.glob("*.download")))
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)


class QualificationEvidenceTest(unittest.TestCase):
    def test_full_requires_positive_protocol_issuance_independently(self):
        with tempfile.TemporaryDirectory() as temporary:
            run=exercise.Exercise(FakeApi(),Path(temporary)/"results")
            try:
                run.state.update(mode="isolated-full",demoVerified=True,publicArtifacts={"state":"EXECUTED"},isolated={"kind":"native-component"})
                run.descriptors={"ca.create":{}}
                run.state["coverage"]={operation:{"state":"NOT_APPLICABLE" if operation in exercise.CATALOG_UNAVAILABLE else "EXECUTED"} for operation in exercise.CATALOG_IDS}
                self.assertEqual(3,run.report(strict=True))
                report=json.loads((run.directory/"report.json").read_text())
                self.assertTrue(report["catalogueQualified"])
                self.assertFalse(report["protocolQualified"])
                run.state["protocolWireProofs"]={protocol:{"state":"VERIFIED","issuanceVerified":True,"keyMatchVerified":True,"chainVerified":True} for protocol in ("acme","est","scep","cmp")}
                self.assertEqual(0,run.report(strict=True))
                run.state["isolated"]["kind"]="rootless-podman"
                self.assertEqual(0,run.report(strict=True))
                run.state["protocolWireProofs"]["cmp"]={"state":"VERIFIED","response":"signed discovery response"}
                self.assertEqual(3,run.report(strict=True))
            finally:run.close()

if __name__ == "__main__":
    unittest.main()
