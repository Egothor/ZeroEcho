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

"""Host-only packaged remote CLI smoke flow; never resubmit an issuance."""
import argparse
import json
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
IMPORT_LIMIT = 1_048_576
RESPONSE_LIMIT = 4 * 1_048_576
# HttpOperationCodec uses StrictJson's global string constraint, derived from
# PkiServerConfiguration.Listener.MAXIMUM_PROOF_RESPONSE_BASE64URL_CHARACTERS.
# PkiCliJson.ARGUMENT_FACTORY uses the same existing 21,846-character bound.
JSON_TEXT_LIMIT = 21_846


class SmokeFailure(Exception):
    def __init__(self, message, code=1):
        super().__init__(message)
        self.code = code


def log(message):
    print("[smoke] " + message, file=sys.stderr, flush=True)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON property")
        result[key] = value
    return result


def reject_number(value):
    raise ValueError("Only exact JSON integers are supported")


def read_json(path, limit):
    with Path(path).open("rb") as source:
        document = source.read(limit + 1)
    if len(document) > limit:
        raise ValueError("JSON document exceeds its bound")
    return json.loads(document.decode("utf-8"), object_pairs_hook=unique_object,
                      parse_float=reject_number, parse_constant=reject_number)


def text_value(value):
    if not isinstance(value, str) or not value.strip() or len(value.encode("utf-16-le")) // 2 > JSON_TEXT_LIMIT:
        raise ValueError("Expected a bounded nonempty JSON string")
    return value


def import_arguments(path):
    """Decode the existing realm-scoped request.import envelope without dropping fields."""
    document = read_json(path, IMPORT_LIMIT)
    if (not isinstance(document, dict) or set(document) - {"version", "arguments", "approvalId", "deadline"}
            or type(document.get("version")) is not int or document["version"] != 1):
        raise ValueError("Invalid request.import envelope")
    arguments = document.get("arguments")
    if not isinstance(arguments, dict) or set(arguments) != {"formatId", "encoded"}:
        raise ValueError("Invalid request.import arguments")
    result = ["--arg", "formatId=" + text_value(arguments["formatId"]),
              "--arg", "encoded=" + text_value(arguments["encoded"])]
    for field, option in [("approvalId", "--approval-id"), ("deadline", "--deadline")]:
        if field in document:
            result += [option, text_value(document[field])]
    return result


def configuration(environment, env_file):
    result = dict(environment)
    if env_file.is_file():
        if env_file.stat().st_size > IMPORT_LIMIT:
            raise SmokeFailure("Environment file is too large", 2)
        for line in env_file.read_text(encoding="utf-8").splitlines():
            match = re.match(r"^\s*(SMOKE_[A-Z0-9_]+)\s*=(.*)$", line)
            if match and match[1] not in result:
                values = shlex.split(match[2], comments=True, posix=True)
                if len(values) > 1:
                    raise SmokeFailure("Quote whitespace in SMOKE_* environment-file values", 2)
                result[match[1]] = values[0] if values else ""
    return result


def required(settings, name):
    value = settings.get(name, "")
    if not value.strip():
        raise SmokeFailure(name + " is required", 2)
    return value


def host_path(value):
    path = Path(value)
    return str(path if path.is_absolute() else HERE / path)


def cli_command(settings, operation):
    executable = settings.get("SMOKE_CLI", str(HERE.parent / "app/build/install/app/bin/app"))
    return [host_path(executable), "pki", operation, "--url", settings.get("SMOKE_BASE_URL", "https://localhost:8443"),
            "--client-cert", host_path(required(settings, "SMOKE_ADMIN_CERT")),
            "--client-key", host_path(required(settings, "SMOKE_ADMIN_KEY")),
            "--trust", host_path(required(settings, "SMOKE_CA_BUNDLE")), "--output", "json"]


def run_cli(command, receipt):
    # Files are retained on every outcome, including an interrupted child.
    with receipt.open("wb") as output, receipt.with_suffix(".stderr").open("wb") as errors:
        process = subprocess.Popen(command, stdout=output, stderr=errors, start_new_session=True)
        try:
            return process.wait()
        except KeyboardInterrupt:
            process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            return 130


def successful_result(receipt, operation, signing=False):
    document = read_json(receipt, RESPONSE_LIMIT)
    if (not isinstance(document, dict) or type(document.get("version")) is not int
            or document["version"] != 1 or document.get("mode") != "remote"
            or document.get("status") != "SUCCEEDED" or document.get("operation") != operation
            or not isinstance(document.get("result"), dict)):
        raise ValueError("Remote CLI did not report a successful result")
    if signing:
        text_value(document.get("operationId"))
    return document["result"]


def issuance_flow(settings, receipts, prepared_import=None):
    request_id = settings.get("SMOKE_REQUEST_ID", "")
    if prepared_import is not None:
        receipt = receipts / "request-import.json"
        code = run_cli(cli_command(settings, "request.import") + prepared_import, receipt)
        if code != 0:
            raise SmokeFailure("Request import failed; receipt retained", code if code > 0 else 130)
        request_id = text_value(successful_result(receipt, "request.import").get("requestId"))
    if not request_id:
        raise SmokeFailure("A request ID or import envelope is required", 2)
    authority = required(settings, "SMOKE_CA_ID")
    receipt = receipts / "credential-issue.json"
    command = cli_command(settings, "credential.issue") + [
        "--authority-id", authority, "--arg", "issuerCaId=" + authority,
        "--arg", "requestId=" + request_id, "--arg", "profileId=" + required(settings, "SMOKE_PROFILE_ID"),
        "--pending-wait", "120"]
    code = run_cli(command, receipt)
    if code != 0:
        raise SmokeFailure("Issuance did not complete; inspect the retained receipt, never resubmit blindly",
                           code if code > 0 else 130)
    text_value(successful_result(receipt, "credential.issue", signing=True).get("credentialId"))


def http_get(settings, path, output, timeout):
    command = ["curl", "--silent", "--show-error", "--connect-timeout", "3", "--max-time", str(timeout),
               "--max-filesize", str(IMPORT_LIMIT), "--output", str(output), "--write-out", "%{http_code}",
               "--cert", host_path(required(settings, "SMOKE_ADMIN_CERT")),
               "--key", host_path(required(settings, "SMOKE_ADMIN_KEY")),
               "--cacert", host_path(required(settings, "SMOKE_CA_BUNDLE")),
               settings.get("SMOKE_BASE_URL", "https://localhost:8443").rstrip("/") + path]
    with output.with_suffix(".stderr").open("wb") as errors:
        response = subprocess.run(command, stdout=subprocess.PIPE, stderr=errors, timeout=timeout + 1, check=False)
    return response.stdout == b"200" and response.returncode == 0


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-up", action="store_true")
    parser.add_argument("--no-down", action="store_true")
    options = parser.parse_args(arguments)
    os.umask(0o077)
    receipts = Path(tempfile.mkdtemp(prefix="zeroecho-pki-smoke-"))
    log("Private receipts retained at " + str(receipts))
    started = False
    result = 1
    compose = ["docker", "compose", "--env-file", str(HERE / ".env"), "-f", str(HERE / "compose/docker-compose.yml")]
    try:
        settings = configuration(os.environ, HERE / ".env")
        for field in ["SMOKE_ADMIN_CERT", "SMOKE_ADMIN_KEY", "SMOKE_CA_BUNDLE", "SMOKE_CA_ID", "SMOKE_PROFILE_ID"]:
            required(settings, field)
        if bool(settings.get("SMOKE_REQUEST_ID")) == bool(settings.get("SMOKE_IMPORT_ARGS_FILE")):
            raise SmokeFailure("Set exactly one of SMOKE_REQUEST_ID and SMOKE_IMPORT_ARGS_FILE", 2)
        prepared = import_arguments(host_path(settings["SMOKE_IMPORT_ARGS_FILE"])) if settings.get("SMOKE_IMPORT_ARGS_FILE") else None
        if not options.no_up:
            started = True
            subprocess.run(compose + ["up", "-d", "--build"], check=True)
        deadline = time.monotonic() + 120
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SmokeFailure("Server did not become ready within 120 seconds")
            if http_get(settings, "/health/ready", receipts / "ready.json", min(5, remaining)):
                break
            time.sleep(min(2, max(0, deadline - time.monotonic())))
        if not http_get(settings, "/admin/v1/realm", receipts / "realm.json", 5):
            raise SmokeFailure("Administrative identity was not accepted")
        issuance_flow(settings, receipts, prepared)
        log("PASS: one packaged remote CLI issuance completed over mTLS")
        result = 0
    except SmokeFailure as failure:
        log("FAIL: " + str(failure))
        result = failure.code
    except KeyboardInterrupt:
        log("Interrupted; retained receipts may contain an accepted operation ID")
        result = 130
    except (OSError, ValueError, RecursionError, subprocess.SubprocessError):
        log("FAIL: invalid input, CLI result or external command; inspect private receipts")
        result = 1
    finally:
        if started and not options.no_down:
            try:
                subprocess.run(compose + ["down", "--remove-orphans"], check=True, timeout=120)
            except (OSError, subprocess.SubprocessError, KeyboardInterrupt):
                log("Compose teardown failed; inspect the stack manually")
                if result == 0:
                    result = 1
    return result


if __name__ == "__main__":
    sys.exit(main())
