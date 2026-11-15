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

"""Host Python/curses operator over the shared HTTP client, never a deployment tool.

All mutations require review and explicit confirmation. C05 owns durable identity,
submit-once recovery, authorization transport and verified artifact publication.
"""
import argparse
import base64
import copy
import curses
import getpass
import json
import os
from pathlib import Path
import sys
import tempfile
import textwrap
import uuid

from pki_http import Api, ExerciseFailure, _identity, _private_file, _json_bytes
from pki_operator import Operator, UnknownAcceptance, result_exit, action_exit
from pki_tui_forms import (_field, _object, _PROFILE, _operation_fields, _validate,
                           _file_value, _profile_value, _profile_template)

_CANCEL = object()


class _BackCatalog(Exception):
    pass


def _display(value):
    text = json.dumps(value, ensure_ascii=True, sort_keys=True) if not isinstance(value, str) else value
    return "".join(character if character.isprintable() else "?" for character in text)


class _Connection:
    def __init__(self, settings, password):
        self.directory = tempfile.TemporaryDirectory(prefix="zeroecho-tui-")
        self.operator = None
        try:
            _private_file(Path(settings["p12"]))
            cert, key = _identity(Path(self.directory.name), Path(settings["p12"]), password)
            api = Api(settings["url"], Path(settings["trust"]), cert, key)
            self.operator = Operator(api, settings["realm"], Path(settings["checkpoint"]), settings.get("crypto_classpath"))
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.operator:
            self.operator.close()
        self.directory.cleanup()


class _Controller:
    def __init__(self, settings, operator):
        self.settings = dict(settings)
        self.operator = operator
        self.defaults = {"limit": 100, "offset": 0}
        self.flat = False
        self.selected = None
        self.drafts = {}
        self.result = None
        self.review = None
        self.schemas = {}
        self.descriptors = {}
        self.choices = {}
        self._discover()

    def _discover(self):
        discovery = self.operator.discover()
        schemas = {item["operationId"]: item for item in discovery["schema"]}
        descriptors = {item["operation"]: item for item in discovery["operations"]}
        if len(schemas) != len(discovery["schema"]) or len(descriptors) != len(discovery["operations"]) or set(descriptors) - set(schemas):
            raise ExerciseFailure("Discovery identities are inconsistent")
        self.schemas = {identity: schemas[identity] for identity in descriptors}
        self.descriptors = descriptors
        if "configuration.choices" in descriptors:
            try:
                self.choices = self.operator.read("configuration.choices", {"limit": 100})
            except ExerciseFailure:
                self.choices = {}
        if "profile.list-all" in descriptors:
            try:
                profiles = self.operator.read("profile.list-all", {"limit": 100})
                self.choices["profiles"] = profiles.get("profiles", [])
            except ExerciseFailure:
                self.choices["profiles"] = []
        if self.selected not in descriptors:
            self.selected = next(iter(sorted(descriptors)), None)

    def _catalog(self):
        identities = sorted(self.descriptors)
        if self.flat:
            return [(identity, identity) for identity in identities]
        rows = []
        groups = sorted({self.descriptors[identity].get("family", "OTHER") for identity in identities})
        for group in groups:
            rows.append((None, group))
            rows.extend((identity, "  " + identity) for identity in identities if self.descriptors[identity].get("family", "OTHER") == group)
        return rows

    def _invalidate(self):
        self.schemas, self.descriptors, self.choices = {}, {}, {}
        self.defaults, self.drafts = {"limit": 100, "offset": 0}, {}
        self.selected, self.review, self.result = None, None, None
        self.operator = None

    def _arguments(self, identity):
        if identity not in self.drafts:
            fields = self.schemas[identity].get("fields", [])
            self.drafts[identity] = {field["name"]: copy.deepcopy(self.defaults[field["name"]]) for field in fields if field["name"] in self.defaults}
        return self.drafts[identity]

    def _fields(self, identity, arguments):
        fields = _operation_fields(self.schemas[identity], self.schemas, arguments)
        for field in fields:
            name = field["name"]
            source = {"formatId": ("formats", "formatId"), "profileId": ("profiles", "profileId"),
                      "signatureAlgorithmId": ("algorithms", "algorithmId"), "primarySignatureAlgorithmId": ("algorithms", "algorithmId"),
                      "alternativeSignatureAlgorithmId": ("algorithms", "algorithmId"), "keyRef": ("keys", "keyRef"),
                      "newKeyRef": ("keys", "keyRef"), "newAlternativeKeyRef": ("keys", "keyRef"),
                      "primaryKeyRef": ("keys", "keyRef"), "alternativeKeyRef": ("keys", "keyRef")}.get(name)
            if source:
                values = self.choices.get(source[0], [])
                if isinstance(values, dict):
                    values = values.get("items", [])
                field["suggestions"] = [item[source[1]] for item in values if source[1] in item]
            if name == "subjectRef":
                selected = arguments.get("formatId")
                metadata = next((item for item in self.choices.get("formats", []) if item.get("formatId") == selected), {})
                field["help"] = metadata.get("subjectInput", {}).get("help", "X.509 distinguished name" if selected == "x509" else "Use the selected format's subject syntax; no universal CN rule")
        return fields

    def _help(self, identity):
        arguments = self._arguments(identity)
        result = {"operation": identity, "formatId": arguments.get("formatId"), "profileId": arguments.get("profileId"),
                  "fields": [{"name": field["name"], "help": field.get("help", "")} for field in self._fields(identity, arguments)]}
        profile_id = arguments.get("profileId")
        if profile_id and "profile.list" in self.schemas and "profile.inspect" in self.schemas:
            versions = self.operator.read("profile.list", {"profileId": profile_id})
            version = arguments.get("profileVersion", versions.get("activeVersion"))
            if version:
                result["selectedProfile"] = self.operator.read("profile.inspect", {"profileId": profile_id, "profileVersion": version})
            else:
                result["selectedProfile"] = versions
        return result

    def _prepare(self, identity):
        descriptor = self.descriptors[identity]
        if descriptor.get("available") is not True or self.schemas[identity].get("available", True) is not True:
            raise ExerciseFailure("Operation is unavailable in this deployment")
        arguments = copy.deepcopy(self._arguments(identity))
        _validate(_object("arguments", self._fields(identity, arguments)), arguments)
        profile_arguments = arguments if identity == "profile.register" else arguments.get("targetArguments", {}) if identity == "security.approval.request" and arguments.get("targetOperation") == "profile.register" else None
        if profile_arguments is not None:
            validation = self.operator.read("profile.validate", {"document": profile_arguments["document"]})
            if validation.get("valid") is not True:
                raise ExerciseFailure("Profile semantic validation did not succeed")
        if "notBefore" in arguments or "notAfter" in arguments:
            if not all(name in arguments for name in ("notBefore", "notAfter")):
                raise ExerciseFailure("notBefore and notAfter must be supplied together")
        profile = next((profile for profile in self.choices.get("profiles", []) if profile.get("profileId") == arguments.get("profileId")), {})
        if profile.get("formatId") and arguments.get("formatId") and profile["formatId"] != arguments["formatId"]:
            raise ExerciseFailure("Selected profile belongs to a different certificate format")
        spec = self.schemas[identity]
        authority = arguments.get(spec.get("authorityFrom")) if spec.get("authorityFrom") else self.defaults.get("authorityId") if spec.get("scope") == "authority" else None
        if spec.get("scope") == "authority" and not authority:
            raise ExerciseFailure("Select an authority context before review")
        intent = {"version": 1, "requestId": "tui-" + uuid.uuid4().hex, "operation": identity, "arguments": arguments}
        if authority is not None:
            intent["authorityId"] = authority
        self.review = intent
        return copy.deepcopy(intent)

    def _send(self, confirmed):
        if confirmed is not True or self.review is None:
            raise ExerciseFailure("Submission requires explicit confirmation of reviewed input")
        intent, self.review = self.review, None
        self.result = None
        identity = intent["operation"]
        descriptor = self.descriptors[identity]
        self.drafts.pop(identity, None)
        try:
            if not self.schemas[identity].get("mutating", descriptor.get("mutating", True)):
                result = self.operator.read(identity, intent["arguments"], intent.get("authorityId"))
                code = 0
            elif descriptor.get("durableRequest") is True:
                result = self.operator.submit(intent)
                code = result_exit(result)
            else:
                result = self.operator.action(intent)
                code = action_exit(result)
            self.result = {"exit": code, "requestId": intent["requestId"], "operation": identity, "intent": intent, "result": result}
        except UnknownAcceptance:
            self.result = {"exit": 4, "requestId": intent["requestId"], "operation": identity, "intent": intent,
                "next": "Acceptance unknown. Retain checkpoint; observe GET only. Never repeat the mutation."}
        return self.result

    def _worklist(self):
        entries = []
        for path in sorted(self.operator.directory.glob("*.json")):
            if len(path.stem) != 64:
                continue
            document = _json_bytes(_private_file(path).read_bytes())
            if isinstance(document, dict) and "intent" in document:
                entries.append(document)
        return entries

    def _open_work(self, entry, observe=False):
        intent = entry["intent"]
        if "refusal" in entry:
            self.result = {"exit": 2, "requestId": intent["requestId"], "operation": intent["operation"],
                "intent": intent, "refusal": entry["refusal"],
                "next": "Definitive refusal retained. Resolve the stated prerequisite/permission before new reviewed work; never replay this intent."}
            return self.result
        dedicated = entry.get("mode") == "dedicated"
        if observe and not dedicated:
            try:
                record = self.operator.observe(intent["requestId"])
                self.result = {"exit": result_exit(record), "requestId": intent["requestId"], "operation": intent["operation"], "intent": intent, "result": record}
            except UnknownAcceptance:
                self.result = {"exit": 4, "requestId": intent["requestId"], "next": "Acceptance unknown; reconcile without replay"}
        elif dedicated:
            envelope = entry.get("envelope")
            self.result = {"exit": action_exit(envelope) if envelope else 4, "requestId": intent["requestId"],
                "operation": intent["operation"], "intent": intent, "result": envelope or {}, "next": "Dedicated action is never retried; observe its original durable target"}
        else:
            receipt = entry.get("receipt")
            self.result = {"exit": result_exit(receipt) if receipt else 4, "requestId": intent["requestId"], "operation": intent["operation"],
                "intent": intent, "result": receipt or {}, "next": "Observe GET only"}
        return self.result

    def _approval(self, decision):
        record = (self.result or {}).get("result", {})
        approval_id = record.get("approvalId")
        if not approval_id:
            raise ExerciseFailure("This retained result has no approval identity")
        identity = "security.approval." + decision
        if identity not in self.schemas:
            raise ExerciseFailure("Approval action is not offered to this identity")
        self.drafts[identity] = {"approvalId": approval_id}
        self.selected = identity
        return identity


class _Ui:
    def __init__(self, screen, endpoint):
        self.screen = screen
        self.endpoint = endpoint
        self.last_selected = 0
        screen.keypad(True)
        try:
            curses.curs_set(0)
        except curses.error:
            pass

    def _paint(self, title, lines, footer, selected=None, offset=0):
        self.screen.erase()
        height, width = self.screen.getmaxyx()
        for row, value in enumerate([self.endpoint, title]):
            try:
                self.screen.addnstr(row, 0, _display(value), max(0, width - 1))
            except curses.error:
                pass
        for index, line in enumerate(lines[offset:offset + max(1, height - 4)]):
            try:
                self.screen.addnstr(index + 2, 0, _display(line), max(0, width - 1), curses.A_REVERSE if selected == index + offset else 0)
            except curses.error:
                pass
        try:
            self.screen.addnstr(max(0, height - 1), 0, footer, max(0, width - 1))
        except curses.error:
            pass
        self.screen.refresh()

    def _key(self):
        key = self.screen.get_wch()
        if key == curses.KEY_F2:
            raise _BackCatalog()
        return key

    def _menu(self, title, labels, initial=0, shortcuts=None):
        if not labels:
            labels = ["(empty)"]
        selected = min(initial, len(labels) - 1)
        while True:
            height, _ = self.screen.getmaxyx()
            offset = max(0, selected - max(1, height - 5))
            footer = "↑↓ move  Enter select  Esc back  F2 catalog" + ("  " + "  ".join(shortcuts.values()) if shortcuts else "")
            self._paint(title, labels, footer, selected, offset)
            key = self._key()
            self.last_selected = selected
            if shortcuts and key in shortcuts:
                return key
            if key in ("\x1b",):
                return _CANCEL
            if key in (curses.KEY_UP, "k"):
                selected = max(0, selected - 1)
            elif key in (curses.KEY_DOWN, "j"):
                selected = min(len(labels) - 1, selected + 1)
            elif key == curses.KEY_HOME:
                selected = 0
            elif key == curses.KEY_END:
                selected = len(labels) - 1
            elif key == curses.KEY_NPAGE:
                selected = min(len(labels) - 1, selected + max(1, height - 4))
            elif key == curses.KEY_PPAGE:
                selected = max(0, selected - max(1, height - 4))
            elif key in ("\n", "\r", curses.KEY_ENTER):
                return selected

    def _input(self, title, value="", secret=False):
        value = str(value)
        while True:
            self._paint(title, ["*" * len(value) if secret else value], "Type value; Enter accept  Esc cancel  F2 catalog")
            key = self._key()
            if key == "\x1b":
                return _CANCEL
            if key in ("\n", "\r", curses.KEY_ENTER):
                return value
            if key in (curses.KEY_BACKSPACE, "\b", "\x7f"):
                value = value[:-1]
            elif key == "\x15":
                value = ""
            elif isinstance(key, str) and key.isprintable() and len(value.encode()) < 16384:
                value += key

    def _notice(self, title, value):
        width = max(1, self.screen.getmaxyx()[1] - 1)
        lines = []
        for line in json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True).splitlines():
            lines.extend(textwrap.wrap(line, width=width, expand_tabs=False,
                replace_whitespace=False, drop_whitespace=False) or [""])
        self._menu(title, lines)

    def _edit(self, field, value=None):
        kind, name = field["type"], field["name"]
        if field.get("readOnly"):
            self._notice("Derived field", {name: "Generated from typed policy fields when the profile is accepted"})
            return value
        title = name + (" — " + field.get("help", "") if field.get("help") else "")
        if kind == "object":
            if field.get("children") is None:
                raise ExerciseFailure("Missing typed form capability: " + name + "; select targetOperation first if applicable")
            return self._object_form(title, field["children"], value or {})
        if kind == "profile":
            if value:
                document = json.loads(base64.b64decode(value, validate=True))
            else:
                templates = ["root-ca", "intermediate-ca", "server-tls", "vpn-client", "vpn-server"]
                index = self._menu("Choose X.509 v5 profile template (then edit typed fields)", templates)
                if index is _CANCEL:
                    return _CANCEL
                document = _profile_template(templates[index])
            edited = self._object_form("X.509 profile — server semantic validation before registration", _PROFILE, document)
            return _CANCEL if edited is _CANCEL else _profile_value(edited)
        if kind == "file":
            encoding = self._menu("Input encoding", ["Exact binary bytes (DER CSR / backup payload)", "PEM certification request to DER"] if name == "encoded" else ["Exact binary backup bytes"])
            if encoding is _CANCEL:
                return _CANCEL
            path = self._input(title + " — owned mode-0600 local file; selected bytes encoded as Base64")
            return _CANCEL if path is _CANCEL else _file_value(path, pem_csr=encoding == 1)
        if kind in ("list", "text-set", "enum-set"):
            values = copy.deepcopy(value or [])
            item_field = field.get("item") or _field("item", "enum" if field.get("choices") else "text", choices=field.get("choices", []))
            while True:
                index = self._menu(title, ["Done", "Add item"] + [str(i + 1) + ": " + _display(item) for i, item in enumerate(values)])
                if index is _CANCEL:
                    return _CANCEL
                if index == 0:
                    _validate(field, values)
                    return values
                if index == 1:
                    if len(values) >= 128:
                        raise ExerciseFailure("List limit is 128 entries")
                    edited = self._edit(item_field)
                    if edited is not _CANCEL:
                        values.append(edited)
                else:
                    action = self._menu("List item", ["Edit", "Remove"])
                    if action == 1:
                        values.pop(index - 2)
                    elif action == 0:
                        edited = self._edit(item_field, values[index - 2])
                        if edited is not _CANCEL:
                            values[index - 2] = edited
        if kind == "boolean":
            index = self._menu(title, ["false", "true"], 1 if value is True else 0)
            return _CANCEL if index is _CANCEL else bool(index)
        if field.get("choices"):
            choices = field["choices"]
            index = self._menu(title, choices, choices.index(value) if value in choices else 0)
            return _CANCEL if index is _CANCEL else choices[index]
        if field.get("suggestions"):
            choices = field["suggestions"]
            index = self._menu(title, ["Enter explicit value"] + choices)
            if index is _CANCEL:
                return _CANCEL
            if index:
                return choices[index - 1]
        entered = self._input(title, "" if value is None else value)
        if entered is _CANCEL:
            return _CANCEL
        result = int(entered) if kind == "integer" else entered
        _validate(field, result)
        return result

    def _object_form(self, title, fields, initial):
        values = copy.deepcopy(initial)
        while True:
            labels = ["Done"] + [field["name"] + (" *" if field.get("required") else "") + ": " + _display(values.get(field["name"], "(not set)")) for field in fields]
            index = self._menu(title, labels)
            if index is _CANCEL:
                return _CANCEL
            if index == 0:
                _validate(_object(title, fields), values)
                return values
            field = fields[index - 1]
            action = self._menu(field["name"], ["Edit", "Omit (optional only)"])
            if action == 1:
                if field.get("required"):
                    raise ExerciseFailure("Required field cannot be omitted")
                values.pop(field["name"], None)
            elif action == 0:
                edited = self._edit(field, values.get(field["name"]))
                if edited is not _CANCEL:
                    values[field["name"]] = edited


def _review_document(intent, settings):
    decoded = []
    operation, arguments = intent.get("operation"), intent.get("arguments", {})
    path = "arguments.document"
    if operation == "security.approval.request":
        operation = arguments.get("targetOperation")
        arguments = arguments.get("targetArguments", {})
        path = "arguments.targetArguments.document"
    if operation in ("profile.register", "profile.validate") and "document" in arguments:
        decoded.append({"path": path, "document": json.loads(base64.b64decode(arguments["document"], validate=True))})
    return {"connection": {"url": settings["url"], "realm": settings["realm"]},
            "wireRequest": copy.deepcopy(intent), "decodedProfileDocuments": decoded}


def _form(ui, controller, identity):
    while True:
        arguments = controller._arguments(identity)
        fields = controller._fields(identity, arguments)
        labels = ["Review exact request"] + [field["name"] + (" *" if field.get("required") else "") + ": " + _display(arguments.get(field["name"], "(not set)")) for field in fields]
        index = ui._menu(identity + " — Enter edits; F2 catalog", labels, shortcuts={"h": "h: format/profile help"})
        if index == "h":
            ui._notice("Selected format/profile guidance", controller._help(identity))
            continue
        if index is _CANCEL:
            controller.review = None
            return
        if index == 0:
            intent = controller._prepare(identity)
            ui._notice("Review target at " + controller.settings["url"] + " realm=" + controller.settings["realm"], _review_document(intent, controller.settings))
            confirm = ui._menu("Send this exact reviewed request once?", ["Cancel — return to form", "CONFIRM SEND"])
            if confirm == 1:
                controller._send(True)
                _result_view(ui, controller)
                return
            controller.review = None
        else:
            field = fields[index - 1]
            action = ui._menu(field["name"], ["Edit", "Omit optional field"])
            if action == 1:
                if field.get("required"):
                    raise ExerciseFailure("Required field cannot be omitted")
                arguments.pop(field["name"], None)
            elif action == 0:
                edited = ui._edit(field, arguments.get(field["name"]))
                if edited is not _CANCEL:
                    if field["name"] == "targetOperation" and edited != arguments.get("targetOperation"):
                        arguments.pop("targetArguments", None)
                    arguments[field["name"]] = edited


def _artifact(ui, controller, preset=None):
    kinds = ["certificate", "ca", "crl", "chain"]
    selected = kinds.index(preset[0]) if preset else ui._menu("Authenticated artifact — possession ≠ private key custody or public access", kinds)
    if selected is _CANCEL:
        return
    kind = kinds[selected]
    value = ui._object_form("Download " + kind + " (new file only)", [_field("identity"),
        _field("representation", "enum", choices=["pem"] if kind == "chain" else ["original", "pem"]), _field("output")], {"identity": preset[1]} if preset else {})
    if value is _CANCEL:
        return
    ui._notice("Review local download (same authenticated target; no public fallback)", value)
    if ui._menu("Publish verified bytes to new local file?", ["Cancel", "CONFIRM DOWNLOAD"]) != 1:
        return
    operator = controller.operator
    if kind == "ca":
        result = operator.ca(value["identity"], value["representation"], Path(value["output"]))
    elif kind == "chain":
        result = operator.chain(value["identity"], Path(value["output"]), value["representation"])
    else:
        result = operator.download(kind, value["identity"], value["representation"], Path(value["output"]))
    ui._notice("Artifact result — inspect signatureVerified before inferring trust", result)


def _artifact_links(value):
    links = set()
    if isinstance(value, dict):
        for key, item in value.items():
            kind = {"credentialId": "certificate", "statusObjectId": "crl", "pathId": "chain", "caId": "ca", "authorityId": "ca"}.get(key)
            if kind and isinstance(item, str) and item:
                links.add((kind, item))
            elif isinstance(item, (dict, list)):
                links.update(_artifact_links(item))
    elif isinstance(value, list):
        for item in value:
            links.update(_artifact_links(item))
    return sorted(links)


def _issued_artifacts(ui, controller):
    links = _artifact_links(controller.result.get("result", {}))
    if not links:
        raise ExerciseFailure("No artifact identity in this result; use named authenticated download")
    index = ui._menu("Result objects — metadata or permitted download", [kind + " " + identity for kind, identity in links])
    if index is _CANCEL:
        return
    kind, identity = links[index]
    action = ui._menu("Selected result object " + identity, ["Inspect metadata", "Download"])
    if action == 1:
        _artifact(ui, controller, (kind, identity))
    elif action == 0:
        operation, field = {"certificate": ("credential.inspect", "credentialId"), "ca": ("ca.inspect", "caId"),
                            "crl": ("status.inspect", "statusObjectId"), "chain": ("issuer.path.inspect", "pathId")}[kind]
        spec = controller.schemas.get(operation)
        if spec is None:
            raise ExerciseFailure("Metadata operation is not offered to this identity")
        authority = None
        if spec.get("scope") == "authority":
            authority = identity if spec.get("authorityFrom") == field else (controller.result.get("intent", {}).get("authorityId")
                or controller.result.get("result", {}).get("authorityId") or controller.defaults.get("authorityId"))
            if not authority:
                authority = ui._input("Explicit authority context for this metadata read")
                if authority is _CANCEL:
                    return
                if not authority:
                    raise ExerciseFailure("Authority context is required for this metadata read")
        ui._notice("Authorized object metadata", controller.operator.read(operation, {field: identity}, authority))


def _result_view(ui, controller):
    while controller.result:
        code = controller.result["exit"]
        labels = ["Inspect retained request/result", "Observe GET only", "Approve retained approval", "Reject retained approval", "Artifact downloads", "Back to catalog", "Issued object metadata/downloads"]
        state = {0: "COMPLETED", 2: "FAILED", 3: "INCOMPLETE — pending/approval is not execution success", 4: "UNKNOWN — reconcile; never repeat mutation"}[code]
        index = ui._menu(state + " — " + controller.result.get("requestId", ""), labels)
        if index is _CANCEL or index == 5:
            return
        if index == 0:
            ui._notice("Exact receipt/result (may contain sensitive response values)", controller.result)
        elif index == 1:
            request_id = controller.result.get("requestId")
            entry = next((entry for entry in controller._worklist() if entry["intent"]["requestId"] == request_id), None)
            if not entry:
                raise ExerciseFailure("No durable checkpoint for this read-only result")
            controller._open_work(entry, observe=True)
        elif index in (2, 3):
            _form(ui, controller, controller._approval("approve" if index == 2 else "reject"))
            return
        elif index == 4:
            _artifact(ui, controller)
        elif index == 6:
            _issued_artifacts(ui, controller)


def _worklist(ui, controller):
    entries = controller._worklist()
    if not entries:
        ui._notice("Worklist", {"next": "No retained requests for this endpoint/realm/client checkpoint"})
        return
    labels = []
    for entry in entries:
        if "refusal" in entry:
            status = "FAILED — HTTP " + str(entry["refusal"]["status"])
        elif entry.get("mode") == "dedicated":
            status = "DEDICATED " + entry.get("envelope", {}).get("status", "UNKNOWN") + " — inspect original target"
        else:
            status = entry.get("receipt", {}).get("state", "UNKNOWN — reconcile without replay")
        labels.append(entry["intent"]["requestId"] + " " + entry["intent"]["operation"] + " " + status)
    index = ui._menu("Retained work — open without replay", labels)
    if index is not _CANCEL:
        controller._open_work(entries[index])
        _result_view(ui, controller)


def _settings(ui, controller, connection):
    index = ui._menu("Session settings — passwords are never preferences", ["Common context defaults", "Connection / endpoint"])
    if index == 0:
        defaults = ui._object_form("Applicable fields only; existing explicit overrides are preserved", [
            *[_field(name, required=False) for name in ("authorityId", "caId", "issuerCaId", "profileId", "formatId")],
            _field("limit", "integer", False), _field("offset", "integer", False)], controller.defaults)
        if defaults is not _CANCEL:
            controller.defaults = defaults
    elif index == 1:
        names = ("url", "realm", "trust", "p12", "checkpoint")
        selected = ui._object_form("Connection references; changed target requires fresh discovery/context", [_field(name) for name in names], {name: controller.settings[name] for name in names})
        if selected is _CANCEL or all(selected[name] == controller.settings[name] for name in names):
            return connection
        password = ui._input("New connection PKCS#12 password (never saved)", secret=True)
        if password is _CANCEL:
            return connection
        connection.close()
        controller._invalidate()
        controller.settings.update(selected)
        ui.endpoint = selected["url"] + " realm=" + selected["realm"]
        new_connection = _Connection(controller.settings, password)
        del password
        controller.operator = new_connection.operator
        try:
            controller._discover()
        except BaseException:
            new_connection.close()
            controller._invalidate()
            raise
        return new_connection
    return connection


def _run(screen, settings, connection):
    controller = _Controller(settings, connection.operator)
    ui = _Ui(screen, settings["url"] + " realm=" + settings["realm"])
    try:
        while True:
            try:
                rows = controller._catalog()
                selected = next((index for index, row in enumerate(rows) if row[0] == controller.selected), 0)
                labels = [label + (" [unavailable]" if identity and not controller.descriptors[identity].get("available") else "") for identity, label in rows]
                key = ui._menu("Operation catalog — " + ("A–Z" if controller.flat else "type tree"), labels, selected,
                    {"a": "a: A–Z/type", "s": "s: settings", "w": "w: worklist", "d": "d: artifacts", "q": "q: quit"})
                if key is _CANCEL or key == "q":
                    return 0
                if key == "a":
                    if rows and rows[ui.last_selected][0]:
                        controller.selected = rows[ui.last_selected][0]
                    controller.flat = not controller.flat
                elif key == "s":
                    connection = _settings(ui, controller, connection)
                elif key == "w":
                    _worklist(ui, controller)
                elif key == "d":
                    _artifact(ui, controller)
                elif type(key) is int and rows and rows[key][0]:
                    controller.selected = rows[key][0]
                    _form(ui, controller, controller.selected)
            except _BackCatalog:
                controller.review = None
            except (ExerciseFailure, OSError, ValueError, KeyError, TypeError) as error:
                controller.review = None
                ui._notice("Client refused action", {"error": str(error) if isinstance(error, ExerciseFailure) else "Invalid input or local client I/O failure"})
                if controller.operator is None:
                    return 2
    finally:
        connection.close()


def main(arguments=None):
    """Run the curses host operator and return process exit status.

    Args:
        arguments: Optional argument list; defaults to process arguments.
    Returns:
        Zero for normal UI exit, two for invalid connection/input or terminal error.
        Individual request/result screens retain C05's 0/2/3/4 semantics.
    Raises:
        KeyboardInterrupt: Caller interruption; attempted work remains checkpointed.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("url", "realm", "trust", "p12", "checkpoint"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--password-fd", type=int)
    parser.add_argument("--crypto-classpath")
    options = parser.parse_args(arguments)
    settings = vars(options).copy()
    settings.pop("password_fd")
    connection = None
    try:
        if not sys.stdin.isatty() or not sys.stdout.isatty():
            raise ExerciseFailure("TUI requires a normal interactive terminal")
        if options.password_fd is None:
            password = getpass.getpass("Operator PKCS#12 password: ")
        else:
            if options.password_fd < 0:
                raise ExerciseFailure("Invalid password descriptor")
            with os.fdopen(os.dup(options.password_fd), "rb") as source:
                raw = source.readline(4097)
            if len(raw) > 4096:
                raise ExerciseFailure("Password exceeds byte bound")
            password = raw.decode("utf-8").removesuffix("\n")
        connection = _Connection(settings, password)
        del password
        return curses.wrapper(_run, settings, connection)
    except (ExerciseFailure, OSError, ValueError, curses.error) as error:
        print(str(error) if isinstance(error, ExerciseFailure) else "TUI connection or terminal setup failed", file=sys.stderr)
        return 2
    finally:
        if connection:
            connection.close()


if __name__ == "__main__":
    sys.exit(main())
