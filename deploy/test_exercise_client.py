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

"""Host-only qualification, realm binding and external restart boundaries."""
import ast
import base64
import json
import contextlib
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import exercise_pki as client
import exercise_catalog as catalog
from test_exercise_pki import FakeApi, envelope


class TargetApi(FakeApi):
    def __init__(self, realm):
        super().__init__()
        self.realm=realm
    def json(self,method,path,document=None):
        if path=="/admin/v1/realm":
            self.calls.append((method,path,document))
            return 200,envelope("realm.inspect",{"realmId":self.realm})
        return super().json(method,path,document)


class HostClientTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)
        self.artifacts=self.root/"client";self.artifacts.mkdir(mode=0o700)
        for name in ("admin.p12","trust.pem"):
            (self.artifacts/name).write_bytes(b"placeholder");(self.artifacts/name).chmod(0o600)
        self.config=self.root/"connection.json"
        self.document={"version":1,"purpose":"qualification","environmentId":"a"*32,"realmId":"zeroecho-exercise-"+"a"*32,
            "adminUrl":FakeApi.origin,"adminPrincipalId":"operator","adminP12":"client/admin.p12","trustFile":"client/trust.pem","clientDirectory":"client"}
        self.write()
    def tearDown(self):self.temp.cleanup()
    def write(self):self.config.write_text(json.dumps(self.document));self.config.chmod(0o600)

    def test_private_connection_schema_and_no_server_fields(self):
        self.assertEqual(self.artifacts,client._connection(self.config)["clientDirectory"])
        for name,value in [("serverRoot","/denied/server"),("images",{}),("keyringPassword","DO-NOT-READ")]:
            self.document[name]=value;self.write()
            with self.assertRaisesRegex(client.ExerciseFailure,"CLIENT"):client._connection(self.config)
            del self.document[name]
        self.document["purpose"]="production";self.write()
        with self.assertRaises(client.ExerciseFailure):client._connection(self.config)
        self.document["purpose"]="qualification";self.document["realmId"]="other";self.write()
        with self.assertRaisesRegex(client.ExerciseFailure,"environment identity"):client._connection(self.config)
        self.document["realmId"]="zeroecho-exercise-"+"a"*32;self.write();self.config.chmod(0o644)
        with self.assertRaises(client.ExerciseFailure):client._connection(self.config)

    def test_target_guard_blocks_every_mutation_after_realm_change(self):
        api=TargetApi(self.document["realmId"])
        run=client.Exercise(api,self.root/"results")
        try:
            connection=client._connection(self.config)
            run.target_guard=client._target_guard(run,connection)
            run.discover()
            api.realm="different"
            with self.assertRaisesRegex(client.ExerciseFailure,"realm differs"):run.job("ca","ca.create",{"subjectRef":"CN=Test"})
            self.assertFalse(any(method=="POST" for method,_,_ in api.calls))
        finally:run.close()

    def test_host_full_driver_has_no_container_or_server_import_or_process(self):
        import exercise_protocols
        api=TargetApi(self.document["realmId"])
        run=client.Exercise(api,self.root/"results")
        connection=client._connection(self.config);connection["clientPassword"]=lambda:"SECRET-ONLY-IN-MEMORY"
        run.state["failure"]="Earlier transport error"
        run.state["coverage"]["credential.inspect"]={"state":"FAILED","reason":"Retained failed receipt"}
        from types import SimpleNamespace
        options=SimpleNamespace()
        def basic(exercise,unused):exercise.state["demoVerified"]=True
        def graph(exercise,context):exercise.job("test-ca","ca.create",{"subjectRef":"CN=Test"})
        try:
            with patch.object(client,"_live",side_effect=basic),patch.object(exercise_protocols,"prepare_client_context",return_value={}),patch.object(catalog,"run",side_effect=graph),patch.object(subprocess,"run",side_effect=AssertionError("Container/process execution forbidden")):
                self.assertEqual(3,client._full_client(run,options,connection))
            self.assertTrue(any(method=="POST" for method,_,_ in api.calls))
            self.assertNotIn("failure",run.state)
            self.assertEqual("FAILED",run.state["coverage"]["credential.inspect"]["state"])
            self.assertNotIn("SECRET-ONLY-IN-MEMORY",(run.directory/"checkpoint.json").read_text())
            self.assertEqual("host-https-client",json.loads((run.directory/"report.json").read_text())["transportKind"])
        finally:run.close()
        for name in ("exercise_pki.py","exercise_catalog.py","exercise_protocols.py","exercise_legacy_protocols.py"):
            source=(Path(__file__).parent/name).read_text();tree=ast.parse(source)
            imported=[node.module for node in ast.walk(tree) if isinstance(node,ast.ImportFrom)]+[alias.name for node in ast.walk(tree) if isinstance(node,ast.Import) for alias in node.names]
            self.assertFalse(set(imported)&{"exercise_fixture","exercise_native","rootless_pki"},name)

    def test_full_failure_retains_report_and_prints_client_artifact_path(self):
        api=TargetApi("WRONG-REALM")
        run=client.Exercise(api,self.root/"failed-results")
        connection=client._connection(self.config)
        output,error=io.StringIO(),io.StringIO()
        try:
            with contextlib.redirect_stdout(output),contextlib.redirect_stderr(error),patch.object(subprocess,"run",side_effect=AssertionError("No server process")):
                self.assertEqual(2,client._full_client(run,None,connection))
            report=json.loads((run.directory/"report.json").read_text())
            state=json.loads((run.directory/"checkpoint.json").read_text())
            self.assertFalse(report["qualified"])
            self.assertEqual("FAILED",report["executionState"])
            self.assertIn("realm differs",state["failure"])
            self.assertIn(str(run.directory),output.getvalue())
            self.assertFalse(any(method=="POST" for method,_,_ in api.calls))
        finally:run.close()

    def test_old_isolated_command_stops_before_any_process(self):
        with patch.object(subprocess,"run",side_effect=AssertionError("must not execute")):
            with self.assertRaises(SystemExit) as failure:client.main(["--mode","isolated-full"])
        self.assertEqual(2,failure.exception.code)


class BackupApi:
    origin="https://localhost:8443"
    def __init__(self):self.calls=[];self.phase="STAGED"
    def json(self,method,path,document=None):
        self.calls.append((method,path,document))
        operation=path.rsplit('/',1)[1]
        if operation=="backup.stream.status" or operation=="backup.stream.restore":result={"state":self.phase,"restoreId":"restore-one"}
        elif operation=="backup.stream.acknowledge":result={"value":"ACKNOWLEDGED"}
        else:result={"state":"APPROVED"}
        return 200,envelope(operation,result)


class ExternalRestartTest(unittest.TestCase):
    def test_catalog_stops_at_staged_and_resume_observes_then_acknowledges_once(self):
        with tempfile.TemporaryDirectory() as temporary:
            api=BackupApi();run=client.Exercise(api,Path(temporary)/"results")
            schemas={
                "security.approval.request":[("approvalId","text"),("targetOperation","text"),("targetArguments","object")],
                "security.approval.approve":[("approvalId","text"),("justification","text")],
                "backup.stream.restore":[("artifactHandle","text")],"backup.stream.status":[("artifactHandle","text")],"backup.stream.acknowledge":[("artifactHandle","text")]}
            run.schema={operation:{"operationId":operation,"scope":"realm","mutating":operation!="backup.stream.status","fields":[{"name":name,"type":kind,"required":True} for name,kind in fields]} for operation,fields in schemas.items()}
            run.descriptors={name:{"durableRequest":False} for name in schemas}
            receipts={name:{} for name in ("backup.stream.export","backup.stream.download","backup.stream.reserve","backup.stream.upload","backup.stream.verify")}
            run.state["backupScenario"]={"receipts":receipts,"export":{"artifactHandle":"old"},"exportReady":{"artifactHandle":"old"},"download":{"length":1,"sha256":"f"*64},"upload":{"artifactHandle":"handle"}}
            context={"assert_disposable":lambda origin,identity:None,"scenarios":{"backup_transfer":client._backup_transfer}}
            step={"operation":"backup.stream.restore","phase":101,"special":"backup_transfer","expected":{},"captures":{},"authority":False,"arguments":{}}
            graph={"steps":[step],"not_discovered":[],"unavailable":[],"schemaSha256":"x"}
            try:
                with patch.object(catalog,"plan",return_value=graph):
                    with self.assertRaises(client.ExternalRestartRequired):catalog.run(run,context)
                self.assertEqual("restore-one",run.state["waitingExternalRestart"]["restoreId"])
                count=lambda name:sum(path.endswith('/'+name) for _,path,_ in api.calls)
                self.assertEqual(1,count("backup.stream.restore"));self.assertEqual(0,count("backup.stream.acknowledge"))
                before=len(api.calls);api.phase="ACTIVATED"
                client._backup_transfer(run,"backup.stream.restore",{},context)
                self.assertEqual(1,count("backup.stream.restore"));self.assertEqual(1,count("backup.stream.acknowledge"))
                self.assertEqual({"backup.stream.status","backup.stream.acknowledge"},{path.rsplit('/',1)[1] for _,path,_ in api.calls[before:]})
                client._backup_transfer(run,"backup.stream.restore",{},context)
                self.assertEqual(1,count("backup.stream.acknowledge"))
            finally:run.close()

    def test_prepared_publication_uses_only_http_state_and_hash(self):
        from types import SimpleNamespace
        calls=[]
        expected="f"*64
        class Adapter:
            api=SimpleNamespace(origin="https://localhost")
            schema={name:{"scope":"authority","mutating":name=="publication.retry"} for name in ("publication.inspect","status.inspect","publication.retry")}
            descriptors={name:{"durableRequest":name=="publication.retry"} for name in schema}
            state={"runId":"a"*32}
            def save(self):pass
            def operation(self,name,args,authority=None):
                calls.append((name,args,authority))
                if name=="publication.inspect":return {"publicationId":"prepared-id","sourceType":"STATUS_OBJECT","sourceId":"prepared-source","status":"RETRYABLE_FAILURE"}
                return {"contentSha256":expected}
            def job(self,label,name,args,authority=None):
                calls.append((name,args,authority));return {"publicationId":"prepared-id","status":"SUCCEEDED"}
        run=Adapter()
        context={"assert_disposable":lambda origin,identity:None,"preparedPublications":{"retry":{"publicationId":"prepared-id","sourceSha256":expected,"authorityId":"prepared-ca"}}}
        with patch.object(Path,"read_bytes",side_effect=AssertionError("Server filesystem access forbidden")):
            result=catalog._publication_recovery(run,"publication.retry",{},context)
        self.assertEqual("SUCCEEDED",result["status"])
        self.assertEqual(["publication.inspect","status.inspect","publication.retry"],[item[0] for item in calls])
        self.assertEqual("prepared-id",calls[-1][1]["publicationId"])
        self.assertEqual(expected,run.state["publicationEvidence"]["prepared-id"]["sourceSha256"])

    def test_missing_prepared_publication_is_blocked_without_server_access(self):
        from types import SimpleNamespace
        run=SimpleNamespace(state={},api=SimpleNamespace(origin="https://localhost"))
        with self.assertRaisesRegex(catalog.CatalogFailure,"BLOCKED"):
            catalog._publication_recovery(run,"publication.retry",{}, {})


if __name__=="__main__":unittest.main()
