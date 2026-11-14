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

"""Optional protocol configuration and real wire prerequisites for nonce-owned disposable realms."""
import base64
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
import exercise_protocols as protocols
import exercise_environment as deployment
from exercise_pki import ExerciseFailure

class ProtocolFixtureTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name);self.root.chmod(0o700);(self.root/"config").mkdir()
        self.nonce="a"*32
        (self.root/".exercise-owner.json").write_text(json.dumps({"nonce":self.nonce}))
        self.configuration={"realm":{"realmId":"zeroecho-exercise-"+self.nonce,"approvalPolicy":{"eligibleApprovers":["exercise-admin","exercise-approver"]}},"listener":{"tlsProvider":{"id":"test","properties":{}}},"execution":{}}
    def test_all_protocols_explicit_and_companion_starts_empty_without_reset(self):
        environment=deployment.prepare(self.root,self.configuration)
        self.assertEqual({"ZEROECHO_ENROLLMENT_CONFIG":"/deployment/config/enrollment-runtime.json"},environment)
        for name,port in (("acme",8445),("est",8446),("scep",8447),("cmp",8448)):
            self.assertTrue(self.configuration[name+"Listener"]["enabled"]);self.assertEqual(port,self.configuration[name+"Listener"]["port"])
        self.assertEqual([],json.loads((self.root/"config/enrollment-runtime.json").read_text())["credentialSets"])
        self.assertEqual(0o600,(self.root/"config/enrollment-runtime.json").stat().st_mode&0o777)
        with self.assertRaises(ExerciseFailure):deployment.prepare(self.root,self.configuration)
    def test_foreign_realm_refused_without_writing_runtime(self):
        self.configuration["realm"]["realmId"]="existing-installation"
        with self.assertRaises(ExerciseFailure):deployment.prepare(self.root,self.configuration)
        self.assertFalse((self.root/"config/enrollment-runtime.json").exists())
    def test_real_p256_jws_account_nonce_scope_and_receipt(self):
        exercise=SimpleNamespace(directory=self.root)
        fixture=SimpleNamespace(directory=self.root,trust_file=self.root/"web-ca.pem",acme_origin="https://localhost:8445",protocol_urls={"acme":"https://localhost:12345"})
        calls=[]
        def request(api,method,path,body=None,*args,**kwargs):
            calls.append((method,path,body))
            if method=="GET":return 200,{},json.dumps({"newAccount":"https://localhost:8445/acme/owned/new-account","newNonce":"https://localhost:8445/acme/owned/new-nonce"}).encode()
            if method=="HEAD":return 204,{"replay-nonce":"one-use-nonce"},b""
            document=json.loads(body);protected=json.loads(base64.urlsafe_b64decode(document["protected"]+"=="))
            self.assertEqual("one-use-nonce",protected["nonce"]);self.assertEqual("ES256",protected["alg"])
            self.assertEqual("https://localhost:8445/acme/owned/new-account",protected["url"])
            self.assertTrue(document["signature"]);self.assertEqual("EC",protected["jwk"]["kty"]);self.assertEqual(64,len(base64.urlsafe_b64decode(document["signature"]+"==")))
            return 201,{"location":"https://localhost:8445/acme/owned/account/account-one"},b"{}"
        with patch.object(protocols,"Api",return_value=SimpleNamespace()),patch.object(protocols,"_raw",side_effect=request):
            self.assertEqual("account-one",protocols._wire_account(exercise,fixture,{"directoryAlias":"owned"}))
        self.assertEqual(["GET","HEAD","POST"],[row[0] for row in calls]);self.assertEqual(0o600,(self.root/"protocol-account.key").stat().st_mode&0o777)
    def test_acme_foreign_directory_url_rejected_before_mutation(self):
        with patch.object(protocols,"Api",return_value=SimpleNamespace()),patch.object(protocols,"_raw",return_value=(200,{},b'{"newAccount":"https://foreign.invalid/acme/owned/new-account","newNonce":"https://localhost:8445/acme/owned/new-nonce"}')) as wire:
            with self.assertRaises(ExerciseFailure):protocols._wire_account(SimpleNamespace(directory=self.root),SimpleNamespace(directory=self.root,trust_file=self.root/"web-ca.pem",acme_origin="https://localhost:8445",protocol_urls={"acme":"https://localhost:12345"}),{"directoryAlias":"owned"})
            self.assertEqual(1,wire.call_count)

    def test_ocsp_queries_the_actually_revoked_lifecycle_credential(self):
        exercise=SimpleNamespace(directory=self.root,state={},save=lambda:None)
        values={"responderId":"responder","responderAlias":"alias","authorityId":"ca","caCredentialId":"ca-cert","credentialId":"clear-leaf","lifecycleCredentialId":"revoked-leaf"}
        context={"publicApi":SimpleNamespace(client_authenticated=False)}
        with patch("exercise_catalog._call",return_value={"active":True}),patch.object(protocols,"_artifact") as artifact,patch.object(protocols,"_raw",return_value=(200,{},b"response")),patch.object(protocols,"_verified_openssl",return_value=b"ocsp-client.pem: revoked"):
            (self.root/"protocol-ocsp-request.der").write_bytes(b"request")
            protocols._ocsp_wire(exercise,"ocsp.responder.activate",values,context)
        self.assertEqual("revoked-leaf",artifact.call_args_list[1].args[2])
        self.assertEqual("revoked-leaf",exercise.state["protocolWireProofs"]["ocsp"]["credentialId"])

    def test_acme_authorization_url_is_fetched_as_authenticated_post_as_get(self):
        url="https://localhost:8445/acme/owned/challenge/one"
        with patch.object(protocols,"_acme_post",return_value=(200,{},json.dumps({"type":"dns-01","url":url,"token":"a"*32}).encode())) as post:
            result=protocols._dns_challenge("api","/acme/owned",{"challenges":[url]},self.root/"private-account.key","account-kid")
        self.assertEqual("dns-01",result["type"])
        post.assert_called_once_with("api","/acme/owned",url,None,self.root/"private-account.key","account-kid")
    def test_acme_challenge_selection_rejects_missing_ambiguous_or_malformed_records(self):
        with patch.object(protocols,"_acme_post",return_value=(200,{},b'{"type":"dns-01"}')):
            for authorization in ({"challenges":[]},{"challenges":["one","two"]},{"challenges":[{"type":"dns-01"}]}):
                with self.assertRaises(ExerciseFailure):protocols._dns_challenge(None,"/acme/owned",authorization,None,"kid")
        with patch.object(protocols,"_acme_post",return_value=(200,{},b'[]')):
            with self.assertRaises(ExerciseFailure):protocols._dns_challenge(None,"/acme/owned",{"challenges":["one"]},None,"kid")

class HostProtocolClientTests(unittest.TestCase):
    """Host client preparation uses only public metadata and client-owned credentials."""
    def setUp(self):
        """Prepare a private client bundle without any server tree or container control."""
        self.temporary=tempfile.TemporaryDirectory();self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name);self.root.chmod(0o700)
        for name in ('public','protocol-client','dns'):(self.root/name).mkdir(mode=0o700)
        for name in ('public/authority.der','public/scep-ra.der','public/cmp-ra.der','public/cmp-client.der','protocol-client/client.zek','requester.crt','requester.key','trust.pem','helper.jar'):
            path=self.root/name;path.write_bytes(b'client-only-material');path.chmod(0o600)
        self.connection={'version':1,'purpose':'qualification','environmentId':'a'*32,'realmId':'qualification-realm',
            'clientDirectory':str(self.root),'trustFile':str(self.root/'trust.pem'),'protocolUrls':{key:'https://localhost:'+str(port) for key,port in [('acme',18445),('est',18446),('scep',18447),('cmp',18448)]},
            'protocolAuthorityId':'protocol-ca','protocolEnrollmentProfileId':'protocol-policy','protocolPublicKeyAlgorithms':['RSA'],
            'protocolX509BindingPolicies':['STANDARD_ONLY'],'challengeProviderIds':['dns-provider'],
            'clientJavaClasspath':[str(self.root/'helper.jar')],'acmeDnsChallengeFile':'dns/protocol-dns.json','acmeDnsNamespace':'example.invalid'}
        path=self.root/'client-config.json';path.write_text(json.dumps(self.connection));path.chmod(0o600)
        self.guard_calls=[]
        self.connection.update(assert_disposable=lambda origin,run:self.guard_calls.append((origin,run)),clientPassword=lambda:'hidden-client-password')
        self.exercise=SimpleNamespace(api=SimpleNamespace(origin='https://localhost:18443'),state={'runId':'b'*32},directory=self.root/'output')
    def test_preparation_and_java_invocation_are_host_only_and_password_stdin_only(self):
        """No deployment RPC or server path is needed to prepare actual Java process arguments."""
        context=protocols.prepare_client_context(self.exercise,self.connection)
        self.assertEqual({'seed_enrollment','seed_acme_account','ocsp_wire','approve_enrollment'},set(context['scenarios']))
        with patch.object(protocols.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout=b'LEGACY_CLIENT_READY',stderr=b'')) as run:
            context['legacy_client']('scep','initial')
        arguments=run.call_args.args[0];options=run.call_args.kwargs
        self.assertEqual('java',arguments[0]);self.assertNotIn('hidden-client-password',arguments)
        self.assertEqual(b'hidden-client-password\n',options['input']);self.assertNotIn('env',options)
        self.assertFalse((self.root/'config').exists());self.assertGreaterEqual(len(self.guard_calls),2)
    def test_manifest_mismatch_and_escaped_client_files_fail_before_execution(self):
        """Private files cannot be replaced by a server path or another environment's bundle."""
        self.connection['environmentId']='c'*32
        with self.assertRaises(ExerciseFailure):protocols.prepare_client_context(self.exercise,self.connection)
        self.connection['environmentId']='a'*32;self.connection['requesterKey']='../server-keyring.zek'
        with self.assertRaises(ExerciseFailure):protocols.prepare_client_context(self.exercise,self.connection)
    def test_missing_client_material_is_incomplete_not_synthesized(self):
        """The host client never provisions replacement identities or starts a service."""
        (self.root/'public/cmp-ra.der').unlink()
        with patch.object(protocols.subprocess,'run') as command:
            with self.assertRaises(ExerciseFailure):protocols.prepare_client_context(self.exercise,self.connection)
            command.assert_not_called()
        self.assertFalse((self.root/'public/cmp-ra.der').exists())
    def test_java_failure_does_not_expose_password_or_stderr(self):
        """Only bounded safe phase diagnostics cross the client subprocess boundary."""
        context=protocols.prepare_client_context(self.exercise,self.connection)
        with patch.object(protocols.subprocess,'run',return_value=SimpleNamespace(returncode=1,stdout=b'',stderr=b'private details')):
            with self.assertRaises(ExerciseFailure) as failure:context['legacy_client']('cmp','verify')
        self.assertNotIn('hidden-client-password',str(failure.exception));self.assertNotIn('private details',str(failure.exception))

class AcmeValidityBoundaryTests(unittest.TestCase):
    """Normal OpenSSL verification must respect the actual encoded validity start."""
    @classmethod
    def setUpClass(cls):
        cls.temporary=tempfile.TemporaryDirectory();cls.root=Path(cls.temporary.name)
        cls.ca=cls.root/'ca.pem';cls.other=cls.root/'other.pem'
        for name in ('ca','other'):
            protocols._openssl(['req','-x509','-newkey','rsa:2048','-nodes','-days','2','-subj','/CN='+name,'-keyout',cls.root/(name+'.key'),'-out',cls.root/(name+'.pem')])
        protocols._openssl(['req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=client','-keyout',cls.root/'leaf.key','-out',cls.root/'leaf.csr'])
        (cls.root/'index').write_text('');(cls.root/'serial').write_text('1000\n');(cls.root/'issued').mkdir()
        (cls.root/'ca.cnf').write_text('[ca]\ndefault_ca=local\n[local]\ndatabase='+str(cls.root/'index')+'\nserial='+str(cls.root/'serial')+'\nprivate_key='+str(cls.root/'ca.key')+'\ncertificate='+str(cls.ca)+'\nnew_certs_dir='+str(cls.root/'issued')+'\ndefault_md=sha256\npolicy=names\nunique_subject=no\n[names]\ncommonName=supplied\n')
    @classmethod
    def tearDownClass(cls):cls.temporary.cleanup()
    def leaf(self, epoch, name):
        from datetime import datetime,timezone
        path=self.root/name
        date=lambda value:datetime.fromtimestamp(value,timezone.utc).strftime('%Y%m%d%H%M%SZ')
        protocols._openssl(['ca','-batch','-notext','-config',self.root/'ca.cnf','-in',self.root/'leaf.csr','-out',path,'-startdate',date(epoch),'-enddate',date(epoch+3600)])
        return path
    def test_real_future_certificate_waits_then_passes_normal_strict_verify(self):
        import math,time
        epoch=math.ceil(time.time())+1
        certificate=self.leaf(epoch,'future.pem')
        exercise=SimpleNamespace(directory=self.root,clock=time.monotonic,sleep=time.sleep)
        result=protocols._verify_acme_chain(exercise,self.ca,certificate)
        self.assertIn(b'OK',result)
        self.assertGreaterEqual(time.time(),epoch)
    def test_valid_now_needs_no_sleep_and_future_wait_is_bounded_by_both_clocks(self):
        import ssl
        raw=b'notBefore=Nov 14 12:00:01 2026 GMT\n'
        start=ssl.cert_time_to_seconds('Nov 14 12:00:01 2026 GMT')
        clock={'wall':start-.25,'monotonic':0.0};pauses=[]
        def pause(delay):pauses.append(delay);clock['wall']+=delay;clock['monotonic']+=delay
        exercise=SimpleNamespace(clock=lambda:clock['monotonic'],sleep=pause)
        with patch.object(protocols,'_openssl',return_value=raw):
            with patch.object(protocols.time,'time',return_value=start):
                protocols._wait_not_before(exercise,self.root/'public.pem')
            self.assertEqual([],pauses)
            with patch.object(protocols.time,'time',side_effect=lambda:clock['wall']):
                protocols._wait_not_before(exercise,self.root/'public.pem')
            self.assertGreater(len(pauses),0);self.assertLessEqual(sum(pauses),2.0)
            pauses.clear()
            with patch.object(protocols.time,'time',return_value=start-3):
                with self.assertRaisesRegex(ExerciseFailure,'exceeds'):
                    protocols._wait_not_before(exercise,self.root/'public.pem')
            self.assertEqual([],pauses)
            clock['monotonic']=0
            def stalled_wall_pause(delay):pauses.append(delay);clock['monotonic']+=delay
            exercise.sleep=stalled_wall_pause
            with patch.object(protocols.time,'time',return_value=start-.25):
                with self.assertRaisesRegex(ExerciseFailure,'bounded wait'):
                    protocols._wait_not_before(exercise,self.root/'public.pem')
            self.assertLessEqual(sum(pauses),2.000001)
        with patch.object(protocols,'_openssl',return_value=b'bad-date'):
            with self.assertRaisesRegex(ExerciseFailure,'malformed'):
                protocols._wait_not_before(exercise,self.root/'public.pem')

    def test_invalid_chain_still_fails_normal_verification(self):
        import time
        certificate=self.leaf(time.time()-5,'invalid-chain.pem')
        exercise=SimpleNamespace(directory=self.root,clock=time.monotonic,sleep=time.sleep)
        with self.assertRaises(ExerciseFailure):protocols._verify_acme_chain(exercise,self.other,certificate)
        self.assertIn('command=verify returnCode=',(self.root/'protocol-acme-openssl.log').read_text())

if __name__=="__main__":unittest.main()
