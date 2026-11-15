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

"""Executable catalog runner contracts; fake only its HTTP/ownership collaborators."""
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest

MODULE = Path(__file__).with_name('exercise_catalog.py')


class CatalogContracts(unittest.TestCase):
    """Verify graph completeness, owned-target safeguards and receipt oracles."""

    @classmethod
    def setUpClass(cls):
        """Load the actual module without invoking any network or host actions."""
        spec = importlib.util.spec_from_file_location('exercise_catalog', MODULE)
        cls.module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = cls.module
        spec.loader.exec_module(cls.module)
        cls.schema = json.loads((MODULE.parents[1] / 'pki-server/build/generated/schema/operationSchema.json').read_text())

    def test_every_static_available_operation_has_concrete_recipe(self):
        """A newly added available operation must make the suite fail closed."""
        registered = self.module.recipe_ids()
        expected = {row['operationId'] for row in self.schema if row['available']}
        self.assertEqual(expected, registered)
        with self.assertRaises(self.module.CatalogFailure):
            self.module.plan(self.schema + [{'operationId':'future.mutation','available':True,'mutating':True}],
                             {'future.mutation':{}}, {})

    def test_runtime_omission_has_evidence_and_is_not_a_pass(self):
        """An undiscovered operation cannot increase the executed denominator."""
        graph = self.module.plan(self.schema, {}, {})
        self.assertFalse(graph['steps'])
        self.assertEqual(152, len(graph['not_discovered']))
        self.assertEqual(['backup.restore'], graph['unavailable'])

    def test_mutation_requires_live_disposable_check_before_api(self):
        """Checkpoint booleans alone never authorize a mutation."""
        exercise = FakeExercise()
        exercise.schema = {'security.principal.register': next(row for row in self.schema if row['operationId']=='security.principal.register')}
        exercise.descriptors = {'security.principal.register':{'durableRequest':True}}
        with self.assertRaises(self.module.CatalogFailure):
            self.module.run(exercise, {'objects':{}, 'isolated':True})
        self.assertEqual([], exercise.calls)

    def test_oracle_rejects_success_without_matching_state(self):
        """HTTP success alone is not a state-transition proof."""
        with self.assertRaises(self.module.CatalogFailure):
            self.module.assert_result({'state':'PENDING'}, {'state':'ACTIVE'}, 'mutation')
        with self.assertRaises(self.module.CatalogFailure):
            self.module.assert_result({}, {}, 'empty')
        self.module.assert_result({'nested':{'enabled':False}}, {'enabled':False}, 'disable')

    def test_all_read_steps_use_read_transport_and_checkpoint(self):
        """Known discovery reads execute through the adapter rather than a static report."""
        exercise = FakeExercise()
        exercise.schema = {'configuration.validate': next(row for row in self.schema if row['operationId']=='configuration.validate')}
        exercise.descriptors = {'configuration.validate':{}}
        result = self.module.run(exercise, {})
        self.assertEqual(['configuration.validate'], result['executed'])
        self.assertEqual([('read','configuration.validate',{})], exercise.calls)
        self.assertTrue(exercise.saved)

    def test_failed_receipt_is_retained_and_never_counted_executed(self):
        """A collaborator failure yields a strict nonqualified result."""
        exercise = FakeExercise(fail=True)
        exercise.schema = {'configuration.validate': next(row for row in self.schema if row['operationId']=='configuration.validate')}
        exercise.descriptors = {'configuration.validate':{}}
        result = self.module.run(exercise, {})
        self.assertFalse(result['qualified'])
        self.assertEqual([], result['executed'])
        self.assertIn('configuration.validate', result['failed'])

    def test_primary_demo_targets_are_never_fallback_mutation_targets(self):
        """A failed catalog creation cannot reuse the baseline CA or private leaf."""
        exercise = FakeExercise()
        exercise.state['objects'] = {'authorityId':'primary-ca', 'credentialId':'private-leaf', 'issuerId':'primary-issuer'}
        values = self.module._initial_values(exercise, {'objects':exercise.state['objects']})
        self.assertNotIn('authorityId', values)
        self.assertNotIn('credentialId', values)
        self.assertNotIn('issuerId', values)

    def test_partial_runtime_never_qualifies_global_full_mode(self):
        """A genuinely omitted supported family remains incomplete, never positive PASS."""
        exercise = FakeExercise()
        exercise.schema = {'configuration.validate': next(row for row in self.schema if row['operationId']=='configuration.validate')}
        exercise.descriptors = {'configuration.validate':{}}
        result = self.module.run(exercise, {})
        self.assertFalse(result['qualified'])
        self.assertEqual(151, len(result['not_discovered']))

    def test_managed_key_recipe_retains_explicit_generation_and_public_result(self):
        recipe = self.module._RECIPES['key.generate']
        exercise = FakeExercise()
        values = self.module._initial_values(exercise, {})
        row = next(row for row in self.schema if row['operationId']=='key.generate')
        arguments = self.module._arguments(recipe, row, values)
        self.assertEqual({'generationId':'exercise-'+'a'*32+'-managed-key',
                          'parameters':'ECDSA_P384'}, arguments)
        self.assertIsNone(self.module._authority(arguments, recipe, values, row))
        self.assertEqual({'managedKeyRef':'keyRef', 'managedGenerationId':'generationId',
                          'managedPublicKeyInfo':'subjectPublicKeyInfo'}, recipe['captures'])

    def test_managed_key_receipt_rejects_changed_generation_and_private_material(self):
        values = {'managedGenerationId':'owned-generation', 'managedParameters':'ECDSA_P384'}
        good = {'generationId':'owned-generation','parameters':'ECDSA_P384',
                'keyRef':'provider:managed-key.priv','subjectPublicKeyInfo':'c3BraQ=='}
        self.module._postconditions(FakeExercise(), {}, 'key.generate', good, values)
        for invalid in ({**good, 'generationId':'other'}, {**good, 'parameters':'RSA_4096'},
                        {**good, 'privateKey':'forbidden'}, {**good, 'subjectPublicKeyInfo':'?'}):
            with self.subTest(invalid=invalid):
                with self.assertRaises(self.module.CatalogFailure):
                    self.module._postconditions(FakeExercise(), {}, 'key.generate', invalid, values)

    def test_managed_responder_freezes_exact_roles_profile_generation_and_validity(self):
        calls=[]
        cached={}
        bad_signature=[False]
        module=self.module
        exercise=FakeExercise()
        operations=('key.generate','profile.register','profile.activate','ca.create','ca.list',
                    'issuer.generation.inspect','ca.inspect','issuer.path.inspect',
                    'ocsp.responder.issue-certificate','credential.inspect')
        for operation in operations:
            exercise.schema[operation]={'scope':'authority' if operation in ('profile.activate','ocsp.responder.issue-certificate','credential.inspect','ca.inspect') else 'realm',
                'mutating':operation in ('key.generate','profile.register','profile.activate','ca.create','ocsp.responder.issue-certificate')}
            exercise.descriptors[operation]={'durableRequest':True}
        def invoke(operation,arguments,authority=None):
            calls.append((operation,arguments,authority))
            exercise.state['coverage'][operation]={'state':'EXECUTED'}
            if operation=='key.generate':
                return {**arguments,'keyRef':arguments['generationId']+'.priv','subjectPublicKeyInfo':'c3BraQ=='}
            if operation=='profile.register':return {'canonicalSha256':'f'*64}
            if operation=='profile.activate':return {'active':True}
            if operation=='ca.create':return {'credentialId':'issuer-cert'}
            if operation=='ca.list':return {'authorities':[{'caId':'hybrid-ca','currentIssuanceIssuerId':'exact-issuer'}]}
            if operation=='issuer.generation.inspect':
                prefix='exercise-'+'a'*32+'-ocsp-'
                def role(name,signature):return {'keyRef':prefix+name+'.priv','signatureAlgorithmId':'unexpected' if bad_signature[0] else signature,
                    'subjectSpkiSha256':hashlib.sha256(b'spki').hexdigest()}
                return {'authorityId':'hybrid-ca','issuerId':'exact-issuer','credentialId':'issuer-cert',
                    'cryptographicBinding':{'primary':role('issuer',module._OCSP_PRIMARY_SIGNATURE),
                        'alternative':role('issuer-alt',module._OCSP_ALTERNATIVE_SIGNATURE)}}
            if operation=='ca.inspect':return {'selectedPathId':'exact-path'}
            if operation=='issuer.path.inspect':return {'issuerId':'exact-issuer','pathId':'exact-path','pathCommitment':'b'*64}
            if operation=='ocsp.responder.issue-certificate':return {'credentialId':'responder-cert'}
            if operation=='credential.inspect':return {'credentialId':'responder-cert'}
            raise AssertionError(operation)
        def job(name,operation,arguments,authority=None):
            if name not in cached:cached[name]=(arguments,authority,invoke(operation,arguments,authority))
            self.assertEqual((arguments,authority),cached[name][:2])
            exercise.state['coverage'][operation]={'state':'EXECUTED'}
            return cached[name][2]
        exercise.job=job
        exercise.operation=invoke
        values={'authorityId':'catalog-ca'}
        context={'assert_disposable':lambda *_:None}
        first=module._issue_managed_responder(exercise,'ocsp.responder.issue-certificate',values,context)
        module._issue_managed_responder(exercise,'ocsp.responder.issue-certificate',values,context)
        target=values['managedResponderTarget']
        self.assertEqual({'credentialId':'responder-cert'},first)
        self.assertEqual(('hybrid-ca','exact-issuer','exact-path','b'*64),
                         tuple(target[k] for k in ('authorityId','issuerId','chainPathId','chainPathCommitment')))
        self.assertEqual('f'*64,target['profileSha256'])
        self.assertNotEqual(target['primaryKeyRef'],target['alternativeKeyRef'])
        self.assertNotIn('expectedPredecessorCredentialId',target)
        self.assertEqual(1,sum(op=='ocsp.responder.issue-certificate' for op,_,_ in calls))
        profiles=[json.loads(base64.b64decode(args['document'])) for op,args,_ in calls if op=='profile.register']
        responder=profiles[1]
        self.assertEqual(['1.3.6.1.5.5.7.3.9'],responder['leafCertificate']['extendedKeyUsage'])
        self.assertEqual('SINGLE',responder['approvalRequirement'])
        self.assertEqual(target['alternativeKeyRef'],responder['hybridMode']['altKeyRef'])
        self.assertFalse(any(op=='ocsp.responder.register' for op,_,_ in calls))
        bad_signature[0]=True
        with self.assertRaisesRegex(module.CatalogFailure,'selected managed signing roles'):
            module._issue_managed_responder(exercise,'ocsp.responder.issue-certificate',values,context)

    def test_protocol_recipes_use_frozen_protocol_authority(self):
        """Catalog rollover cannot retarget an RA capability bound to the baseline issuer."""
        for operation in ('est.endpoint.register','scep.endpoint.register','cmp.endpoint.register','acme.directory.register'):
            recipe = self.module._RECIPES[operation]
            self.assertEqual('@protocolAuthorityId', recipe['arguments']['authorityId'])
            self.assertEqual('server-tls', recipe['arguments']['profileId'])


    def test_rollover_receipt_requires_actual_current_generation(self):
        """A terminal signing receipt alone cannot prove a CA switched to that certificate."""
        exercise=FakeExercise()
        observations=[]
        def read(operation,arguments,authority=None):
            observations.append(operation)
            return {'currentIssuanceIssuerId':'issuer-new'} if operation=='ca.inspect' else {'credentialId':'other-cert'}
        exercise.operation=read
        exercise.schema={'issuer.generation.inspect':{'scope':'realm','mutating':False},'ca.inspect':{'scope':'authority','mutating':False}}
        exercise.descriptors={'issuer.generation.inspect':{},'ca.inspect':{}}
        with self.assertRaises(self.module.CatalogFailure):
            self.module._postconditions(exercise,{},'ca.rollover',{'credentialId':'issued-cert'},{'authorityId':'owned-ca'})
        self.assertEqual(['ca.inspect','issuer.generation.inspect'],observations)

    def test_changed_root_rotation_verifies_candidate_without_advancing_active_head(self):
        exercise=FakeExercise()
        head={'caId':'owned-ca','kind':'ROOT','currentIssuanceIssuerId':'active-issuer',
              'selectedPathId':'active-path','headEpoch':7}
        role=lambda digest,key: {'keyRef':key,'subjectSpkiSha256':digest,'publicKeyAlgorithmId':'rsa',
            'signatureAlgorithmId':'rsa-sha256','signatureAlgorithmIdentifierDer':'canonical-der'}
        candidate={'issuerId':'candidate-issuer','authorityId':'owned-ca','credentialId':'candidate-cert',
            'activationState':'PENDING_ACTIVATION','cryptographicBinding':{'primary':role('new-spki','fixture:rotated.prv')}}
        exercise.schema={name:{'scope':'realm','mutating':False} for name in ('ca.inspect','issuer.generation.inspect','issuer.path.inspect')}
        exercise.descriptors={name:{} for name in exercise.schema}
        def read(operation,arguments,authority=None):
            if operation=='ca.inspect':return head
            if operation=='issuer.generation.inspect':
                self.assertEqual({'issuerId':'candidate-issuer'},arguments)
                return candidate
            if operation=='issuer.path.inspect':return {'pathId':'candidate-path','issuerId':'candidate-issuer',
                'orderedCredentialIds':['candidate-cert']}
            raise AssertionError(operation)
        exercise.operation=read
        result={'credentialId':'candidate-cert','candidateCredentialId':'candidate-cert','candidateIssuerId':'candidate-issuer',
            'candidatePathId':'candidate-path','activationState':'PENDING_ACTIVATION'}
        values={'authorityId':'owned-ca','rotationKeyRef':'fixture:rotated.prv','rotationHeadBefore':dict(head),
            'rotationBindingBefore':{'primary':role('old-spki','fixture:root.prv')}}
        self.module._postconditions(exercise,{},'ca.rotate',result,values)
        for invalid in ({**head,'headEpoch':8},{**head,'currentIssuanceIssuerId':'candidate-issuer'}):
            saved=dict(head);head.update(invalid)
            with self.assertRaises(self.module.CatalogFailure):self.module._postconditions(exercise,{},'ca.rotate',result,values)
            head.clear();head.update(saved)
        candidate['cryptographicBinding']['primary']['keyRef']='wrong-key'
        with self.assertRaises(self.module.CatalogFailure):self.module._postconditions(exercise,{},'ca.rotate',result,values)

    def test_same_key_alias_rotation_uses_active_result_but_changed_tuple_cannot(self):
        exercise=FakeExercise()
        role={'keyRef':'canonical:key','subjectSpkiSha256':'same-spki','publicKeyAlgorithmId':'rsa',
              'signatureAlgorithmId':'rsa-sha256','signatureAlgorithmIdentifierDer':'canonical-der'}
        head={'caId':'owned-ca','kind':'ROOT','currentIssuanceIssuerId':'new-issuer',
              'selectedPathId':'new-path','headEpoch':8}
        generation={'issuerId':'new-issuer','authorityId':'owned-ca','credentialId':'new-cert',
                    'cryptographicBinding':{'primary':dict(role)}}
        exercise.schema={name:{'scope':'realm','mutating':False} for name in ('ca.inspect','issuer.generation.inspect','issuer.path.inspect')}
        exercise.descriptors={name:{} for name in exercise.schema}
        def read(operation,arguments,authority=None):
            if operation=='ca.inspect':return head
            if operation=='issuer.generation.inspect':return generation
            return {'pathId':'new-path','issuerId':'new-issuer','orderedCredentialIds':['new-cert']}
        exercise.operation=read
        values={'authorityId':'owned-ca','rotationKeyRef':'alias:same-key',
            'rotationHeadBefore':{**head,'currentIssuanceIssuerId':'old-issuer','headEpoch':7},
            'rotationBindingBefore':{'primary':{**role,'keyRef':'different:old-alias'}}}
        self.module._postconditions(exercise,{},'ca.rotate',{'credentialId':'new-cert'},values)
        for field in ('subjectSpkiSha256','publicKeyAlgorithmId','signatureAlgorithmId','signatureAlgorithmIdentifierDer'):
            generation['cryptographicBinding']['primary'][field]='changed-tuple'
            with self.subTest(field=field):
                with self.assertRaises(self.module.CatalogFailure):
                    self.module._postconditions(exercise,{},'ca.rotate',{'credentialId':'new-cert'},values)
            generation['cryptographicBinding']['primary'][field]=role[field]
        generation['cryptographicBinding']['alternative']=dict(role)
        with self.assertRaises(self.module.CatalogFailure):
            self.module._postconditions(exercise,{},'ca.rotate',{'credentialId':'new-cert'},values)

    def test_signing_result_without_unique_credential_never_passes(self):
        """Missing output identity cannot be replaced by a successful HTTP status."""
        with self.assertRaises(self.module.CatalogFailure):
            self.module._postconditions(FakeExercise(),{},'credential.issue',{'kind':'ISSUE_CREDENTIAL'},{'authorityId':'owned-ca'})


    def test_object_reference_never_becomes_authority_context(self):
        """The schema authorityFrom may identify a credential, not its owning CA."""
        values={'authorityId':'catalog-ca'}
        self.assertEqual('catalog-ca',self.module._authority({'issuerId':'issuer-object'},{'authority':True},values))
        self.assertEqual('protocol-ca',self.module._authority({'authorityId':'protocol-ca'},{'authority':True},values))
        self.assertIsNone(self.module._authority({'requestId':'request-object'},{'authority':False},values))
        self.assertIsNone(self.module._authority({'issuerId':'issuer-object'},{'authority':True},values,{'scope':'realm'}))
        self.assertEqual('catalog-ca',self.module._authority({'profileId':'profile'},{'authority':False},values,{'scope':'authority'}))



class FakeExercise:
    """Minimal owned API collaborator; never substitutes the catalog under test."""

    def __init__(self, fail=False):
        """Record transport calls and inject an explicit receipt failure."""
        self.api = type('Api',(),{'origin':'https://fixture.invalid:8443'})()
        self.state = {'runId':'a'*32,'coverage':{},'objects':{}}
        self.schema, self.descriptors, self.calls = {}, {}, []
        self.saved, self.fail = False, fail

    def operation(self, operation, arguments, authority=None):
        """Return a known valid configuration result, or fail before acknowledgement."""
        self.calls.append(('read',operation,arguments))
        if self.fail:
            raise RuntimeError('fixture transport failure')
        self.state['coverage'][operation] = {'state':'EXECUTED'}
        return {'valid':True}

    def save(self):
        """Mark a checkpoint write without touching the filesystem."""
        self.saved = True


if __name__ == '__main__':
    unittest.main()
