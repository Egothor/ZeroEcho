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

"""Client orchestration failure tests; actual cryptography belongs to native wire gates."""
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import exercise_legacy_protocols as legacy
from exercise_pki import ExerciseFailure


class LegacyEnrollmentContracts(unittest.TestCase):
    """Prove ownership and uncertain-ack safeguards without pretending to issue certificates."""

    def test_unknown_protocol_has_no_transport_or_client_side_effects(self):
        """Reject unsupported families before accessing any supplied collaborators."""
        with self.assertRaises(legacy.LegacyProtocolFailure):
            legacy.qualify(None, {}, {}, "invented")

    def test_missing_live_verifier_cannot_start_owned_client(self):
        """A checkpoint flag cannot substitute for a current runtime ownership check."""
        with self.assertRaises(legacy.LegacyProtocolFailure):
            legacy.qualify(None, {"isolated": True}, {}, "scep")

    def test_public_or_symlink_client_message_is_rejected(self):
        """Private client-file checks reject permission boundaries and link substitution."""
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); target=root/'message.der'; target.write_bytes(b'public')
            target.chmod(0o644)
            with self.assertRaises(legacy.LegacyProtocolFailure): legacy._private_file(target)
            target.chmod(0o600)
            link=root/'link.der'; link.symlink_to(target)
            with self.assertRaises(legacy.LegacyProtocolFailure): legacy._private_file(link)
            self.assertEqual(b'public',legacy._private_file(target))

    def test_unknown_admission_ack_is_never_automatically_posted_twice(self):
        """A lost binary response retains attempted intent and blocks automatic POST replay."""
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); directory=root/'protocol-client'; directory.mkdir(mode=0o700)
            state={'runId':'a'*32}
            exercise=SimpleNamespace(state=state,api=SimpleNamespace(origin='https://localhost:1234'),save=lambda:None,
                operation=lambda *args,**kwargs:{'items':[]})
            checks=[]
            def guard(origin,run):
                """Record each actual fixture ownership consultation."""
                checks.append((origin,run))
            def client(protocol,phase):
                """Retain exactly one deterministic public initial request."""
                self.assertEqual(('scep','initial'),(protocol,phase))
                path=directory/'scep-request.der'
                if not path.exists(): path.write_bytes(b'opaque-initial-wire'); path.chmod(0o600)
            context={'assert_disposable':guard,'legacy_client':client,'clientDirectory':str(root),'trustFile':str(root/'trust.pem'),'protocolUrls':{'scep':'https://localhost:1235'}}
            api=SimpleNamespace(client_authenticated=False)
            with patch.object(legacy,'Api',return_value=api),patch('exercise_protocols._raw',side_effect=ExerciseFailure('uncertain wire')) as raw:
                with self.assertRaises(ExerciseFailure): legacy.qualify(exercise,context,{'endpointLabel':'owned'},'scep')
                self.assertTrue(state['legacyEnrollment']['scep']['requests']['initial']['attempted'])
                with self.assertRaises(legacy.LegacyProtocolFailure): legacy.qualify(exercise,context,{'endpointLabel':'owned'},'scep')
                self.assertEqual(1,raw.call_count)
                self.assertGreaterEqual(len(checks),4)
            self.assertNotIn('scep',state.get('protocolWireProofs',{}))


if __name__=='__main__': unittest.main()
