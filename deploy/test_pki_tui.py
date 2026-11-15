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

"""C06 typed forms, keyboard safety and controller/shared-client integration tests."""
import base64
import copy
import curses
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from pki_http import ExerciseFailure
from pki_operator import Operator, UnknownAcceptance
from pki_tui import (_Controller, _Ui, _BackCatalog, _CANCEL, _form, _run,
                     _artifact_links, _settings)
from pki_tui_forms import (_field, _object, _operation_fields, _profile_template,
                           _profile_value, _file_value, _validate)


def _envelope(operation, result, status="SUCCEEDED"):
    return dict(version=1, operation=operation, status=status, result=result)


def _schemas():
    return [dict(operationId="ca.create", fields=[_field("formatId"), _field("subjectRef"), _field("profileId"), _field("keyRef")],
                 mutating=True, available=True, scope="realm", family="SIGNING_OPERATION"),
            dict(operationId="profile.register", fields=[_field("document", "base64")], mutating=True, available=True, scope="realm"),
            dict(operationId="profile.validate", fields=[_field("document", "base64")], mutating=False, available=True, scope="realm"),
            dict(operationId="security.approval.approve", fields=[_field("approvalId"), _field("justification")], mutating=True, available=True, scope="realm"),
            dict(operationId="request.list", fields=[_field("limit", "integer"), _field("offset", "integer", False)], mutating=False, available=True, scope="realm")]


class _Api:
    client_authenticated = True
    client_identity_sha256 = "fixture-identity"
    origin = "https://fixture.invalid:8443"

    def __init__(self):
        self.calls, self.records = [], {}
        self.lost, self.missing, self.denied = False, False, False
        self.realm = "realm"
        self.schema = _schemas()

    def json(self, method, path, document=None):
        self.calls.append((method, path, copy.deepcopy(document)))
        if path == "/admin/v1/realm":
            return 200, _envelope("realm.inspect", dict(realmId=self.realm))
        if path == "/admin/v1/schema":
            return 200, copy.deepcopy(self.schema)
        if path == "/admin/v1/operations":
            return 200, _envelope("operation.list", dict(operations=[dict(operation=item["operationId"], durableRequest=item["operationId"] in ("ca.create", "profile.register"),
                family=item.get("family", "PKI_OPERATION"), available=True, mutating=item["mutating"]) for item in self.schema]))
        if path == "/admin/v1/requests":
            if self.denied:
                raise ExerciseFailure("denied", 403)
            identity = document["requestId"]
            self.records[identity] = dict(requestId=identity, operation=document["operation"], state="WAITING_APPROVAL", approvalId="approval-" + identity)
            if self.lost:
                raise ExerciseFailure("lost")
            return 202, _envelope("administrative.request.submit", self.records[identity])
        if path.startswith("/admin/v1/requests/"):
            if self.missing:
                raise ExerciseFailure("unknown", 404)
            return 200, _envelope("administrative.request.inspect", self.records[path.rsplit("/", 1)[1]])
        operation = path.rsplit("/", 1)[1]
        if operation == "credential.inspect":
            if document.get("authorityId") != "issuer-authority":
                raise ExerciseFailure("INVALID_OPERATION_REQUEST", 400)
            return 200, _envelope(operation, {"credentialId": document["arguments"]["credentialId"]})
        if operation == "profile.validate":
            profile = json.loads(base64.b64decode(document["arguments"]["document"]))
            if profile["profileVersion"] <= 0:
                raise ExerciseFailure("invalid profile", 400)
            return 200, _envelope(operation, dict(valid=True))
        if operation == "security.approval.approve":
            if self.denied:
                raise ExerciseFailure("denied", 403)
            return 200, _envelope(operation, dict(approvalId=document["arguments"]["approvalId"]))
        return 200, _envelope(operation, dict(items=[]))


class _Screen:
    def __init__(self, keys):
        self.keys = iter(keys)
        self.frames = []

    def keypad(self, enabled):
        self.enabled = enabled

    def getmaxyx(self):
        return 24, 120

    def erase(self):
        self.frames.append([])

    def addnstr(self, row, column, text, maximum, *attributes):
        self.frames[-1].append(text[:maximum])

    def refresh(self):
        pass

    def get_wch(self):
        return next(self.keys)


def _ui(keys):
    with patch("pki_tui.curses.curs_set"):
        return _Ui(_Screen(keys), "https://fixture.invalid realm=realm")


class TuiControllerTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.api = _Api()
        self.operator = Operator(self.api, "realm", self.root / "checkpoint")
        self.addCleanup(self.operator.close)
        self.settings = dict(url=self.api.origin, realm="realm", trust="trust.pem", p12="identity.p12", checkpoint=str(self.operator.directory))
        self.controller = _Controller(self.settings, self.operator)

    def _root(self):
        self.controller.drafts["ca.create"] = dict(formatId="x509", subjectRef="CN=Example", profileId="root", keyRef="managed")
        return self.controller._prepare("ca.create")

    def test_tree_and_az_keep_exact_identity_set(self):
        original = {identity for identity, _ in self.controller._catalog() if identity}
        self.controller.selected = "ca.create"
        self.controller.flat = True
        self.assertEqual(original, {identity for identity, _ in self.controller._catalog()})
        self.assertEqual("ca.create", self.controller.selected)

    def test_defaults_only_apply_to_applicable_fields_and_preserve_explicit_override(self):
        self.controller.defaults.update(profileId="default-profile", unrelated="never")
        self.assertEqual("default-profile", self.controller._arguments("ca.create")["profileId"])
        self.controller._arguments("ca.create")["profileId"] = "explicit"
        self.controller.defaults["profileId"] = "changed"
        self.assertEqual("explicit", self.controller._arguments("ca.create")["profileId"])
        self.assertEqual({"limit": 100, "offset": 0}, self.controller._arguments("request.list"))
        self.assertNotIn("unrelated", self.controller._arguments("ca.create"))

    def test_no_send_without_explicit_confirmation_and_review_is_snapshot(self):
        intent = self._root()
        self.controller.drafts["ca.create"]["keyRef"] = "later-edit"
        with self.assertRaises(ExerciseFailure):
            self.controller._send(False)
        result = self.controller._send(True)
        sent = next(document for method, path, document in self.api.calls if path == "/admin/v1/requests")
        self.assertEqual(intent, sent)
        self.assertEqual("managed", sent["arguments"]["keyRef"])
        self.assertEqual(3, result["exit"])
        self.assertNotIn("ca.create", self.controller.drafts)
        with self.assertRaises(ExerciseFailure):
            self.controller._send(True)

    def test_worklist_survives_reopen_observes_get_only_and_retains_linked_ids(self):
        intent = self._root()
        first = self.controller._send(True)
        self.operator.close()
        with Operator(self.api, "realm", self.operator.directory) as reopened:
            controller = _Controller(self.settings, reopened)
            entry = controller._worklist()[0]
            self.assertEqual(intent, entry["intent"])
            before = len([call for call in self.api.calls if call[1] == "/admin/v1/requests"])
            self.api.records[intent["requestId"]].update(state="SUCCEEDED", result=dict(credentialId="issued"), signingOperationId="signing")
            result = controller._open_work(entry, observe=True)
            self.assertEqual(0, result["exit"])
            self.assertEqual(first["result"]["approvalId"], result["result"]["approvalId"])
            self.assertEqual(before, len([call for call in self.api.calls if call[1] == "/admin/v1/requests"]))
            self.assertIn(("certificate", "issued"), _artifact_links(result["result"]))

    def test_unknown_acknowledgement_is_retained_not_replayed(self):
        self.api.lost = self.api.missing = True
        intent = self._root()
        result = self.controller._send(True)
        self.assertEqual(4, result["exit"])
        self.assertEqual(intent, self.controller._worklist()[0]["intent"])
        self.controller._open_work(self.controller._worklist()[0], observe=True)
        self.assertEqual(1, len([call for call in self.api.calls if call[1] == "/admin/v1/requests"]))

    def test_authorization_refusal_remains_failure_and_checkpoint_is_retained(self):
        self._root()
        self.api.denied = True
        with self.assertRaises(ExerciseFailure):
            self.controller._send(True)
        self.assertEqual(1, len(self.controller._worklist()))
        self.assertIsNone(self.controller.review)

    def test_retained_definitive_refusal_is_failed_for_durable_and_dedicated_work(self):
        for identity in ("ca.create", "security.approval.approve"):
            if identity == "ca.create":
                self._root()
            else:
                self.controller.drafts[identity] = dict(approvalId="refused-approval", justification="Explicit decision")
                self.controller._prepare(identity)
            self.api.denied = True
            with self.assertRaises(ExerciseFailure):
                self.controller._send(True)
        entries = self.controller._worklist()
        self.assertEqual(2, len(entries))
        for entry in entries:
            before = len(self.api.calls)
            projected = self.controller._open_work(entry, observe=True)
            self.assertEqual(2, projected["exit"])
            self.assertEqual(403, projected["refusal"]["status"])
            self.assertEqual(entry["intent"], projected["intent"])
            self.assertEqual(before, len(self.api.calls))
        from pki_tui import _worklist
        ui = _ui(["\x1b"])
        _worklist(ui, self.controller)
        self.assertTrue(any("FAILED" in line and "403" in line for frame in ui.screen.frames for line in frame))

    def test_approval_prefills_retained_identity_and_is_not_execution_success(self):
        self._root()
        result = self.controller._send(True)
        identity = self.controller._approval("approve")
        self.assertEqual(result["result"]["approvalId"], self.controller.drafts[identity]["approvalId"])
        with self.assertRaises(ExerciseFailure):
            self.controller._prepare(identity)
        self.controller.drafts[identity]["justification"] = "Reviewed exact retained target"
        self.controller._prepare(identity)
        self.assertEqual(3, self.controller._send(True)["exit"])
        self.assertEqual(2, len(self.controller._worklist()))

    def test_profile_semantic_preflight_precedes_any_mutation(self):
        profile = _profile_template("root-ca")
        profile["profileVersion"] = 0
        self.controller.drafts["profile.register"] = {"document": _profile_value(profile)}
        with self.assertRaises(ExerciseFailure):
            self.controller._prepare("profile.register")
        self.assertFalse(any(path == "/admin/v1/requests" for _, path, _ in self.api.calls))

    def test_target_invalidation_removes_all_stale_state(self):
        self._root()
        self.controller.defaults["authorityId"] = "old-authority"
        self.controller.result = {"approvalId": "old"}
        self.controller._invalidate()
        self.assertIsNone(self.controller.operator)
        self.assertEqual({}, self.controller.schemas)
        self.assertEqual({}, self.controller.drafts)
        self.assertIsNone(self.controller.review)
        self.assertIsNone(self.controller.result)
        self.assertEqual({"limit": 100, "offset": 0}, self.controller.defaults)

    def test_changed_target_settings_reconnect_and_clear_old_context(self):
        self._root()
        self.controller.defaults["authorityId"] = "old-authority"
        self.controller.result = {"approvalId": "old-approval"}
        target = dict(self.settings, url="https://other.invalid:8443", realm="other", checkpoint=str(self.root / "other-checkpoint"))
        target.pop("crypto_classpath", None)
        class SettingsUi:
            endpoint = "old"
            def _menu(self, *args):
                return 1
            def _object_form(self, *args):
                return target
            def _input(self, *args, **kwargs):
                return "fixture-password"
        new_api = _Api()
        new_api.origin, new_api.realm = target["url"], target["realm"]
        new_operator = Operator(new_api, "other", Path(target["checkpoint"]))
        self.addCleanup(new_operator.close)
        replacement = type("Connection", (), {"operator": new_operator, "close": lambda _: new_operator.close()})()
        old = type("Connection", (), {"operator": self.operator, "close": lambda _: self.operator.close()})()
        ui = SettingsUi()
        with patch("pki_tui._Connection", return_value=replacement) as factory:
            returned = _settings(ui, self.controller, old)
        self.assertIs(replacement, returned)
        self.assertIs(new_operator, self.controller.operator)
        self.assertEqual({}, self.controller.drafts)
        self.assertIsNone(self.controller.review)
        self.assertIsNone(self.controller.result)
        self.assertEqual({"limit": 100, "offset": 0}, self.controller.defaults)
        self.assertEqual(target["url"] + " realm=other", ui.endpoint)
        self.assertEqual(target["url"], factory.call_args.args[0]["url"])
        self.assertTrue(self.controller.schemas)

    def test_unchanged_connection_settings_keep_explicit_draft_and_skip_password(self):
        self._root()
        class SettingsUi:
            def _menu(self, *args):
                return 1
            def _object_form(inner, *args):
                return dict(self.settings)
            def _input(self, *args, **kwargs):
                raise AssertionError("unchanged connection must not ask for a password")
        old = type("Connection", (), {"operator": self.operator})()
        self.assertIs(old, _settings(SettingsUi(), self.controller, old))
        self.assertEqual("managed", self.controller.drafts["ca.create"]["keyRef"])

    def test_failed_target_discovery_leaves_no_stale_usable_connection(self):
        self._root()
        target = dict(self.settings, url="https://other.invalid:8443", realm="expected", checkpoint=str(self.root / "other-checkpoint"))
        class SettingsUi:
            endpoint = "old"
            def _menu(self, *args):
                return 1
            def _object_form(self, *args):
                return target
            def _input(self, *args, **kwargs):
                return "fixture-password"
        new_api = _Api()
        new_api.origin = target["url"]
        new_operator = Operator(new_api, "expected", Path(target["checkpoint"]))
        self.addCleanup(new_operator.close)
        replacement = type("Connection", (), {"operator": new_operator, "close": lambda _: new_operator.close()})()
        old = type("Connection", (), {"operator": self.operator, "close": lambda _: self.operator.close()})()
        with patch("pki_tui._Connection", return_value=replacement):
            with self.assertRaises(ExerciseFailure):
                _settings(SettingsUi(), self.controller, old)
        self.assertIsNone(self.controller.operator)
        self.assertEqual({}, self.controller.schemas)
        self.assertEqual({}, self.controller.drafts)
        self.assertIsNone(self.controller.review)

    def test_authority_context_is_only_injected_for_applicable_scope(self):
        self.controller.defaults["authorityId"] = "context-authority"
        self.controller.drafts["request.list"] = {"limit": 100}
        self.assertNotIn("authorityId", self.controller._prepare("request.list"))
        self.controller.schemas["request.list"]["scope"] = "authority"
        self.assertEqual("context-authority", self.controller._prepare("request.list")["authorityId"])
        self.controller.schemas["ca.create"].update(scope="authority", authorityFrom="keyRef")
        self._root()
        self.assertEqual("managed", self.controller.review["authorityId"])

    def test_known_profile_format_mismatch_cannot_be_sent_for_approval(self):
        self.controller.choices["profiles"] = [{"profileId": "root", "formatId": "custom"}]
        with self.assertRaises(ExerciseFailure):
            self._root()
        self.assertIsNone(self.controller.review)

    def test_result_metadata_preserves_required_authority_context(self):
        from pki_tui import _issued_artifacts
        self.api.schema.append(dict(operationId="credential.inspect", fields=[_field("credentialId")], mutating=False, available=True, scope="authority", authorityFrom=""))
        self.controller._discover()
        self.controller.result = {"exit": 0, "intent": {"authorityId": "issuer-authority"}, "result": {"credentialId": "issued"}}
        _issued_artifacts(_ui(["\n", "\n", "\x1b"]), self.controller)
        sent = next(document for _, path, document in self.api.calls if path.endswith("/credential.inspect"))
        self.assertEqual("issuer-authority", sent["authorityId"])

    def test_missing_metadata_authority_is_explicit_and_cancellation_does_not_read(self):
        from pki_tui import _issued_artifacts
        self.api.schema.append(dict(operationId="credential.inspect", fields=[_field("credentialId")], mutating=False, available=True, scope="authority", authorityFrom=""))
        self.controller._discover()
        self.controller.result = {"exit": 0, "result": {"credentialId": "issued"}}
        before = len(self.api.calls)
        _issued_artifacts(_ui(["\n", "\n", "\x1b"]), self.controller)
        self.assertEqual(before, len(self.api.calls))
        keys = ["\n", "\n"] + list("issuer-authority") + ["\n", "\x1b"]
        _issued_artifacts(_ui(keys), self.controller)
        sent = next(document for _, path, document in self.api.calls if path.endswith("/credential.inspect"))
        self.assertEqual("issuer-authority", sent["authorityId"])

    def test_keyboard_catalog_return_and_escape_never_submit(self):
        for key in ("\x1b", curses.KEY_F2):
            ui = _ui([key])
            if key == curses.KEY_F2:
                with self.assertRaises(_BackCatalog):
                    _form(ui, self.controller, "ca.create")
            else:
                _form(ui, self.controller, "ca.create")
        self.assertFalse(any(path == "/admin/v1/requests" for _, path, _ in self.api.calls))

    def test_keyboard_review_cancel_is_not_submission(self):
        self._root()
        ui = _ui(["\n", "\x1b", "\n", "\x1b"])
        _form(ui, self.controller, "ca.create")
        self.assertFalse(any(path == "/admin/v1/requests" for _, path, _ in self.api.calls))

    def test_keyboard_confirm_moves_to_pending_result_once(self):
        self._root()
        ui = _ui(["\n", "\x1b", curses.KEY_DOWN, "\n", "\x1b"])
        _form(ui, self.controller, "ca.create")
        self.assertEqual(3, self.controller.result["exit"])
        self.assertEqual(1, len([call for call in self.api.calls if call[1] == "/admin/v1/requests"]))
        self.assertTrue(any("INCOMPLETE" in line for frame in ui.screen.frames for line in frame))

    def test_keyboard_toggle_preserves_highlighted_operation(self):
        connection = type("Connection", (), {"operator": self.operator, "close": lambda _: None})()
        screen = _Screen([curses.KEY_DOWN, "a", "\n", curses.KEY_F2, "q"])
        with patch("pki_tui.curses.curs_set"):
            self.assertEqual(0, _run(screen, self.settings, connection))
        self.assertTrue(any("A–Z" in line for frame in screen.frames for line in frame))
        self.assertFalse(any(path == "/admin/v1/requests" for _, path, _ in self.api.calls))


class TypedFormsTest(unittest.TestCase):
    def test_all_shipped_profiles_round_trip_as_typed_objects_and_lists(self):
        for name in ("root-ca", "intermediate-ca", "server-tls", "vpn-client", "vpn-server"):
            profile = _profile_template(name)
            profile["subject"]["rules"].append(dict(oid="2.5.4.10", source="PROFILE_FIXED", minimumOccurrences=1, maximumOccurrences=1, maximumUtf8Bytes=100, fixedValue="Example"))
            self.assertEqual(profile, json.loads(base64.b64decode(_profile_value(profile))))

    def test_unknown_profile_field_or_format_is_rejected(self):
        profile = _profile_template("root-ca")
        profile["unknown"] = True
        with self.assertRaises(ExerciseFailure):
            _profile_value(profile)
        profile.pop("unknown")
        profile["formatId"] = "custom"
        with self.assertRaises(ExerciseFailure):
            _profile_value(profile)

    def test_explicit_nested_contracts_and_unknown_extension_fail_closed(self):
        for name in ("keygen", "requesterTrustPolicy", "expectedHead", "hybridSdk", "subject"):
            spec = dict(operationId="test", fields=[_field(name, "object")])
            self.assertTrue(_operation_fields(spec, {})[0]["children"])
        spec = dict(operationId="custom", fields=[_field("providerExtension", "object")])
        field = _operation_fields(spec, {})[0]
        with self.assertRaisesRegex(ExerciseFailure, "Missing typed form"):
            _validate(field, {})

    def test_nested_approval_target_uses_selected_operation_schema(self):
        schemas = {item["operationId"]: item for item in _schemas()}
        spec = dict(operationId="security.approval.request", fields=[_field("targetArguments", "object")])
        field = _operation_fields(spec, schemas, dict(targetOperation="ca.create"))[0]
        _validate(field, dict(formatId="x509", subjectRef="CN=Example", profileId="root", keyRef="managed"))
        with self.assertRaises(ExerciseFailure):
            _validate(field, dict(keyRef="managed"))

    def test_unique_sets_boolean_integer_and_bounds(self):
        for field, value in [(_field("number", "integer"), True), (_field("flag", "boolean"), 1),
                             (_field("conditions", "enum-set", choices=["ALLOWED"]), ["OTHER"]),
                             (_field("items", "text-set"), ["duplicate", "duplicate"]),
                             (_field("items", "text-set"), [str(i) for i in range(129)])]:
            with self.assertRaises(ExerciseFailure):
                _validate(field, value)
        _validate(_field("items", "text-set"), [])
        _validate(_field("items", "text-set"), [str(i) for i in range(128)])

    def test_typed_confirmation_edits_derive_commitment_and_cover_all_disclosures(self):
        from pki_tui_forms import _PROFILE
        policy_field = next(field for field in _PROFILE if field["name"] == "confirmationPolicy")
        disclosure = next(field for field in policy_field["children"] if field["name"] == "disclosurePolicy")
        self.assertIn("RESTRICTED", disclosure["choices"])
        self.assertIn("NOT_PUBLISHED", disclosure["choices"])
        profile = _profile_template("server-tls")
        unchanged = json.loads(base64.b64decode(_profile_value(profile)))
        self.assertEqual(profile["confirmationPolicy"]["policyCommitment"], unchanged["confirmationPolicy"]["policyCommitment"])
        profile["confirmationPolicy"]["confirmationWindow"] = "PT48H"
        edited = json.loads(base64.b64decode(_profile_value(profile)))
        self.assertNotEqual(profile["confirmationPolicy"]["policyCommitment"], edited["confirmationPolicy"]["policyCommitment"])
        self.assertEqual(profile["confirmationPolicy"]["policyCommitment"], unchanged["confirmationPolicy"]["policyCommitment"])

    def test_review_long_scalar_tail_is_inspectable_before_confirmation(self):
        ui = _ui([curses.KEY_END, "\x1b"])
        ui._notice("Exact request", {"subjectRef": "CN=" + "x" * 400 + "UNIQUE-REVIEW-TAIL"})
        self.assertTrue(any("UNIQUE-REVIEW-TAIL" in line for frame in ui.screen.frames for line in frame))

    def test_review_keeps_exact_wire_and_exposes_decoded_typed_profile(self):
        from pki_tui import _review_document
        profile = _profile_template("root-ca")
        profile["subject"]["rules"][0]["maximumUtf8Bytes"] = 194
        encoded = _profile_value(profile)
        intent = dict(operation="profile.register", arguments={"document": encoded})
        reviewed = _review_document(intent, {"url": "https://exact.invalid", "realm": "exact"})
        self.assertEqual(intent, reviewed["wireRequest"])
        self.assertEqual(profile, reviewed["decodedProfileDocuments"][0]["document"])
        self.assertEqual("arguments.document", reviewed["decodedProfileDocuments"][0]["path"])
        self.assertEqual("https://exact.invalid", reviewed["connection"]["url"])

    def test_keyboard_nested_object_list_and_enum_controls(self):
        field = _object("policy", [_field("enabled", "boolean")])
        ui = _ui([curses.KEY_DOWN, "\n", "\n", curses.KEY_DOWN, "\n", "\n"])
        self.assertEqual({"enabled": True}, ui._edit(field))
        ui = _ui([curses.KEY_DOWN, "\n", "a", "\n", "\n"])
        self.assertEqual(["a"], ui._edit(_field("names", "text-set")))

    def test_keyboard_named_artifact_actions_dispatch_and_cancel_without_write(self):
        from types import SimpleNamespace
        from pki_tui import _artifact, _issued_artifacts
        calls = []
        class Artifacts:
            def download(self, kind, identity, representation, output):
                calls.append((kind, identity, representation, output))
                return {"signatureVerified": False}
            def ca(self, identity, representation, output):
                calls.append(("ca", identity, representation, output))
                return {"signatureVerified": False}
            def chain(self, identity, output, representation):
                calls.append(("chain", identity, representation, output))
                return {"signatureVerified": True}
            def read(self, operation, arguments, authority=None):
                calls.append((operation, arguments))
                return {"credentialId": arguments["credentialId"]}
        controller = SimpleNamespace(operator=Artifacts(), result={"result": {"credentialId": "issued"}},
            schemas={"credential.inspect": {"scope": "realm"}}, defaults={})
        ui = _ui(["\n", "\n", "\x1b"])
        _issued_artifacts(ui, controller)
        self.assertEqual(("credential.inspect", {"credentialId": "issued"}), calls.pop())
        for kind in ("certificate", "ca", "crl", "chain"):
            _artifact(_ui(["\x1b"]), controller, (kind, "retained-id"))
            self.assertEqual([], calls)
            keys = [curses.KEY_DOWN, curses.KEY_DOWN, "\n", "\n"]
            if kind != "chain":
                keys += [curses.KEY_DOWN]
            keys += ["\n"]
            keys += [curses.KEY_DOWN] * 3 + ["\n", "\n"] + list("new-output") + ["\n", "\n", "\x1b", curses.KEY_DOWN, "\n", "\x1b"]
            _artifact(_ui(keys), controller, (kind, "retained-id"))
            self.assertEqual((kind, "retained-id", "pem", Path("new-output")), calls.pop())
            self.assertEqual([], calls)

    def test_result_metadata_scope_is_correct_for_every_artifact_family(self):
        from types import SimpleNamespace
        from pki_tui import _issued_artifacts
        calls = []
        class Metadata:
            def read(self, operation, arguments, authority):
                calls.append((operation, arguments, authority))
                return arguments
        cases = [("credentialId", "credential.inspect", "authority", "", "original-authority"),
                 ("caId", "ca.inspect", "authority", "caId", "selected-object"),
                 ("statusObjectId", "status.inspect", "realm", "", None),
                 ("pathId", "issuer.path.inspect", "realm", "", None)]
        for field, operation, scope, authority_from, expected in cases:
            controller = SimpleNamespace(operator=Metadata(), result={"intent": {"authorityId": "original-authority"}, "result": {field: "selected-object"}},
                schemas={operation: {"scope": scope, "authorityFrom": authority_from}}, defaults={"authorityId": "different-default"})
            _issued_artifacts(_ui(["\n", "\n", "\x1b"]), controller)
            self.assertEqual((operation, {field: "selected-object"}, expected), calls.pop())

    def test_file_selection_exact_bytes_pem_decode_and_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input"
            path.write_bytes(b"\x30\x01\x00")
            path.chmod(0o600)
            self.assertEqual(path.read_bytes(), base64.b64decode(_file_value(path)))
            path.write_bytes(b"-----BEGIN CERTIFICATE REQUEST-----\nMAEA\n-----END CERTIFICATE REQUEST-----\n")
            self.assertEqual(b"\x30\x01\x00", base64.b64decode(_file_value(path, True)))
            path.chmod(0o644)
            with self.assertRaises(ExerciseFailure):
                _file_value(path)

    def test_format_specific_subject_help_does_not_force_x509_dn(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        with Operator(_Api(), "realm", Path(temp.name) / "checkpoint") as operator:
            controller = _Controller(dict(url=operator.api.origin, realm="realm"), operator)
            field = next(field for field in controller._fields("ca.create", {"formatId": "custom"}) if field["name"] == "subjectRef")
            self.assertNotIn("CN=", field["help"])


if __name__ == "__main__":
    unittest.main()


def exercise_live_tui(operator, root, realm, origin, variant, credential):
    """Exercise C06 keyboard/controller and real curses against an actual localhost server.

    Called by CertificateScenarioHttpTest for each approved algorithm scenario;
    credentials stay client-local, and no deployment action is performed here.
    """
    import fcntl
    import pty
    import select
    import struct
    import subprocess
    import termios
    import time
    from pki_operator import result_exit

    settings = dict(url=origin, realm=realm, trust=str(root / "trust.pem"),
                    p12=str(root / "operator-login.p12"), checkpoint=str(operator.directory))
    controller = _Controller(settings, operator)
    profile = _profile_template("server-tls")
    disclosures = ("PUBLIC", "PUBLIC_UNLISTED", "AUTHENTICATED", "OWNER_ONLY", "RESTRICTED", "NOT_PUBLISHED")
    confirmation_vectors = []
    for disclosure in disclosures:
        candidate = copy.deepcopy(profile)
        candidate["confirmationPolicy"].update(disclosurePolicy=disclosure, confirmationWindow="PT48H")
        document = _profile_value(candidate)
        assert operator.read("profile.validate", {"document": document})["valid"] is True
        confirmation_vectors.append(json.loads(base64.b64decode(document))["confirmationPolicy"])
    candidate = copy.deepcopy(profile)
    candidate["confirmationPolicy"]["confirmationWindow"] = "PT0.000000001S"
    assert operator.read("profile.validate", {"document": _profile_value(candidate)})["valid"] is True
    profile["profileId"] = "c06-typed-profile"
    profile["confirmationPolicy"].update(disclosurePolicy="RESTRICTED", confirmationWindow="PT48H")
    controller.drafts["profile.register"] = {"document": _profile_value(profile)}
    controller._prepare("profile.register")
    assert controller.review["arguments"]["document"] == _profile_value(profile)
    ui = _ui(["\n", "\x1b", curses.KEY_DOWN, "\n", "\x1b"])
    _form(ui, controller, "profile.register")
    request_id = controller.result["requestId"]
    record = controller.result["result"]
    if record["state"] == "WAITING_APPROVAL":
        identity = controller._approval("approve")
        assert controller.drafts[identity]["approvalId"] == record["approvalId"]
        controller.drafts[identity]["justification"] = "C06 explicit review of retained localhost profile target"
        ui = _ui(["\n", "\x1b", curses.KEY_DOWN, "\n", "\x1b"])
        _form(ui, controller, identity)
        assert controller.result["exit"] == 3
    deadline = time.monotonic() + 30
    while record["state"] != "SUCCEEDED" and time.monotonic() < deadline:
        record = operator.observe(request_id)
        assert result_exit(record) in (0, 3), record
    assert record["state"] == "SUCCEEDED", record
    entry = next(entry for entry in controller._worklist() if entry["intent"]["requestId"] == request_id)
    assert entry["intent"]["arguments"]["document"] == _profile_value(profile)
    controller._open_work(entry, observe=True)
    assert controller.result["exit"] == 0
    evidence = Path(__file__).resolve().parent.parent / "build/c06-evidence/live" / variant
    evidence.mkdir(parents=True, exist_ok=True)
    (evidence / "confirmation-vectors.json").write_text(json.dumps(confirmation_vectors))
    (evidence / "tui-receipt.json").write_text(json.dumps(dict(requestId=request_id, state=record["state"], approvalId=record.get("approvalId"))))

    from pki_tui import _issued_artifacts
    authority = json.loads((root / "client-output/algorithm-report.json").read_text())["generations"]["intermediate"]["authorityId"]
    controller.result = {"exit": 0, "intent": {"authorityId": authority}, "result": {"credentialId": credential}}
    _issued_artifacts(_ui(["\n", "\n", "\x1b"]), controller)
    output_path = root / "c06-tui-issued.pem"
    keys = ["\n", curses.KEY_DOWN, "\n", curses.KEY_DOWN, curses.KEY_DOWN, "\n", "\n", curses.KEY_DOWN, "\n"]
    keys += [curses.KEY_DOWN] * 3 + ["\n", "\n"] + list(str(output_path)) + ["\n", "\n", "\x1b", curses.KEY_DOWN, "\n", "\x1b"]
    _issued_artifacts(_ui(keys), controller)
    assert output_path.read_bytes() == (root / "operator-client.pem").read_bytes()

    read_fd, write_fd = os.pipe()
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 120, 0, 0))
    command = ["python3", str(Path(__file__).with_name("pki_tui.py")), "--url", origin,
        "--realm", realm, "--trust", str(root / "trust.pem"), "--p12", str(root / "operator-login.p12"),
        "--password-fd", str(read_fd), "--checkpoint", str(root / "tui-pty-state")]
    environment = dict(os.environ, TERM="xterm-256color")
    process = subprocess.Popen(command, stdin=slave, stdout=slave, stderr=slave, pass_fds=(read_fd,), env=environment)
    os.close(slave)
    os.close(read_fd)
    os.write(write_fd, b"local-c05-test-password\n")
    os.close(write_fd)
    output = b""
    try:
        deadline = time.monotonic() + 30
        while b"Operation catalog" not in output and time.monotonic() < deadline and process.poll() is None:
            if select.select([master], [], [], 1)[0]:
                try:
                    output += os.read(master, 65536)
                except OSError:
                    break
        assert b"Operation catalog" in output, output.decode(errors="replace")
        os.write(master, b"as")
        deadline = time.monotonic() + 5
        while b"Session settings" not in output and time.monotonic() < deadline:
            if select.select([master], [], [], 1)[0]:
                output += os.read(master, 65536)
        assert b"Session settings" in output, output.decode(errors="replace")
        os.write(master, b"\x1b")
        # A separate input write follows acknowledgement of the settings screen.
        os.write(master, b"q")
        assert process.wait(timeout=10) == 0
        assert (root / "tui-pty-state/session.json").is_file()
        assert not list((root / "tui-pty-state").glob("[a-f0-9]" * 64 + ".json"))
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        os.close(master)
        (evidence / "tui-pty.log").write_bytes(output)
    print("C06 real localhost HTTPS: typed profile, explicit approval, GET-only result, actual curses PTY catalog/A-Z/settings/exit PASS", flush=True)
