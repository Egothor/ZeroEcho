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
"""Exercise bounded release-process failure, timeout and descendant ownership contracts."""

import io
import os
from pathlib import Path
import signal
import selectors
import subprocess
import sys
import tempfile
import time
from unittest import mock
import unittest

from run_release_checks import BuildLimits, TEST_FAILURE_MARKER, run_bounded


@unittest.skipUnless(os.name == "posix", "Release process groups require POSIX")
class BoundedReleaseBuildTest(unittest.TestCase):
    """Use real isolated child processes; never invoke the product's full test suites."""

    def execute(self, program, limits=None):
        """Capture one short-lived Python child using explicit QA-only budgets."""
        output = io.StringIO()
        code = run_bounded([sys.executable, "-c", program],
                           limits or BuildLimits(4, 0.15, 0.15), output)
        return code, output.getvalue()

    def test_normal_and_failed_process_exit_codes_and_output_are_preserved(self):
        for expected in (0, 7):
            with self.subTest(exit_code=expected):
                code, output = self.execute(
                    f"import sys; print('stdout'); print('stderr', file=sys.stderr); sys.exit({expected})")
                self.assertEqual(expected, code)
                self.assertIn("stdout", output)
                self.assertIn("stderr", output)

    def test_failure_marker_cannot_be_masked_by_a_successful_child_exit(self):
        code, output = self.execute(f"print({TEST_FAILURE_MARKER!r} + ':test example failure', flush=True)")
        self.assertEqual(1, code)
        self.assertIn(TEST_FAILURE_MARKER, output)

    def test_failure_marker_survives_chunk_boundaries_and_bulk_output(self):
        code, output = self.execute(
            "import os; "
            "os.write(1, b'x' * 200000); "
            f"os.write(1, {TEST_FAILURE_MARKER[:8].encode()!r}); "
            f"os.write(1, {TEST_FAILURE_MARKER[8:].encode()!r})")
        self.assertEqual(1, code)
        self.assertIn(TEST_FAILURE_MARKER, output)
        self.assertTrue(output.startswith("x" * 200000))

    def test_healthy_work_may_exceed_failure_shutdown_grace(self):
        code, output = self.execute(
            "import threading; threading.Event().wait(0.3); print('healthy complete')",
            BuildLimits(4, 0.05, 0.15))
        self.assertEqual(0, code)
        self.assertIn("healthy complete", output)
        self.assertNotIn("TIMEOUT", output)

    def test_first_failure_starts_shutdown_grace_and_kills_resistant_child(self):
        code, output = self.execute(
            "import signal; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
            f"print({TEST_FAILURE_MARKER!r} + ':test blocked shutdown', flush=True); signal.pause()")
        self.assertEqual(124, code)
        self.assertIn("TEST_FAILURE_SHUTDOWN_TIMEOUT", output)
        self.assertIn("PROCESS_GROUP_SHUTDOWN_TIMEOUT", output)
        self.assertIn("SIGKILL", output)
        self.assertNotIn("::error::BUILD_TIMEOUT:", output)

    def test_silent_build_timeout_is_logged_without_a_prior_failure_marker(self):
        code, output = self.execute(
            "import signal; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
            "print('ready', flush=True); signal.pause()", BuildLimits(1, 0.15, 0.15))
        self.assertEqual(124, code)
        self.assertIn("ready", output)
        self.assertIn("BUILD_TIMEOUT:", output)
        self.assertIn("SIGKILL", output)
        self.assertNotIn(TEST_FAILURE_MARKER, output)

    def test_parent_exit_does_not_wait_forever_for_descendants_output_pipe(self):
        code, output = self.execute(r"""
import os
import signal
read_end, write_end = os.pipe()
if os.fork() == 0:
    os.close(read_end)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    os.write(write_end, b'1')
    os.close(write_end)
    print('descendant ready', flush=True)
    signal.pause()
else:
    os.close(write_end)
    os.read(read_end, 1)
    os.close(read_end)
    print('parent complete', flush=True)
""")
        self.assertEqual(124, code)
        self.assertIn("descendant ready", output)
        self.assertIn("parent complete", output)
        self.assertIn("PROCESS_GROUP_SHUTDOWN_TIMEOUT", output)

    def test_sigterm_to_wrapper_terminates_owned_processes_and_returns_143(self):
        tools = str(Path(__file__).resolve().parent)
        program = (
            f"import sys; sys.path.insert(0, {tools!r}); "
            "from run_release_checks import run_bounded, BuildLimits; "
            "sys.exit(run_bounded([sys.executable, '-c', "
            "\"import signal; print('cancel ready', flush=True); signal.pause()\"], "
            "BuildLimits(4, 0.15, 0.15)))")
        process = subprocess.Popen([sys.executable, "-c", program], stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True)
        try:
            with selectors.DefaultSelector() as ready:
                ready.register(process.stdout, selectors.EVENT_READ)
                self.assertTrue(ready.select(4), "Cancellation fixture did not become ready")
                line = os.read(process.stdout.fileno(), 4096).decode("utf-8")
            self.assertIn("cancel ready", line)
            process.send_signal(signal.SIGTERM)
            output, _ = process.communicate(timeout=4)
            self.assertEqual(143, process.returncode)
            self.assertIn("BUILD_INTERRUPTED", output)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=2)
            process.stdout.close()

    def test_repeated_cancellation_cannot_interrupt_process_group_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary:
            pid_file = Path(temporary) / "child.pid"
            tools = str(Path(__file__).resolve().parent)
            child = ("import os, signal; from pathlib import Path; "
                     f"Path({str(pid_file)!r}).write_text(str(os.getpid())); "
                     "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                     "print('cancel ready', flush=True); signal.pause()")
            program = (f"import sys; sys.path.insert(0, {tools!r}); "
                       "from run_release_checks import run_bounded, BuildLimits; "
                       f"sys.exit(run_bounded([sys.executable, '-c', {child!r}], BuildLimits(4, 0.15, 0.4)))")
            process = subprocess.Popen([sys.executable, "-c", program], stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT)
            received = bytearray()
            try:
                with selectors.DefaultSelector() as ready:
                    ready.register(process.stdout, selectors.EVENT_READ)
                    for expected in (b"cancel ready", b"BUILD_INTERRUPTED"):
                        until = time.monotonic() + 3
                        while expected not in received:
                            remaining = until - time.monotonic()
                            self.assertGreater(remaining, 0, "Cancellation fixture did not progress")
                            self.assertTrue(ready.select(remaining))
                            received.extend(os.read(process.stdout.fileno(), 4096))
                        if expected == b"cancel ready":
                            process.send_signal(signal.SIGTERM)
                    # The diagnostic establishes that the first cancellation is
                    # already being handled, rather than merely coalescing signals.
                    process.send_signal(signal.SIGTERM)
                    process.send_signal(signal.SIGINT)
                output, _ = process.communicate(timeout=3)
                self.assertEqual(143, process.returncode)
                self.assertIn(b"SIGKILL", received + output)
                child_state = Path("/proc") / pid_file.read_text() / "stat"
                if child_state.exists():
                    self.assertEqual("Z", child_state.read_text().rsplit(")", 1)[1].split()[0])
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=2)
                if pid_file.exists():
                    try:
                        os.killpg(int(pid_file.read_text()), signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                process.stdout.close()

    def test_blocked_runner_output_cannot_block_timeout_or_its_durable_diagnostic(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pid_file = root / "child.pid"
            diagnostic = root / "failure.log"
            tools = str(Path(__file__).resolve().parent)
            child = ("import os, signal; from pathlib import Path; "
                     f"Path({str(pid_file)!r}).write_text(str(os.getpid())); "
                     "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                     "os.write(1, b'x' * 500000); signal.pause()")
            program = (f"import sys; sys.path.insert(0, {tools!r}); from pathlib import Path; "
                       "from run_release_checks import run_bounded, BuildLimits; "
                       f"sys.exit(run_bounded([sys.executable, '-c', {child!r}], "
                       f"BuildLimits(1, 0.15, 0.15), diagnostic_log=Path({str(diagnostic)!r})))")
            process = subprocess.Popen([sys.executable, "-c", program], stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, start_new_session=True)
            try:
                # Deliberately leave stdout unread until supervision has exited.
                process.wait(timeout=5)
                self.assertEqual(124, process.returncode)
                output, errors = process.communicate(timeout=2)
                self.assertIn(b"BUILD_TIMEOUT", errors)
                self.assertIn("BUILD_TIMEOUT", diagnostic.read_text())
                self.assertTrue(output.startswith(b"x"))
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=2)
                if pid_file.exists():
                    try:
                        os.killpg(int(pid_file.read_text()), signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                process.stdout.close()
                process.stderr.close()

    def test_release_entrypoint_enables_markers_without_changing_normal_test_cache_policy(self):
        from run_release_checks import main
        with tempfile.TemporaryDirectory() as temporary, mock.patch(
                "run_release_checks.run_bounded", return_value=7) as execute:
            log = Path(temporary) / "failure.log"
            self.assertEqual(7, main(["--version", "1.2.3", "--diagnostic-log", str(log)]))
            command = execute.call_args.args[0]
            self.assertIn("--no-configuration-cache", command)
            self.assertIn("-PreleaseWatchdog=true", command)
            self.assertIn("-PreleaseVersion=1.2.3", command)
            self.assertNotIn("--continue", command)
            self.assertEqual(log, execute.call_args.kwargs["diagnostic_log"])

    def test_limits_are_finite_positive_and_release_defaults_are_distinct(self):
        self.assertEqual(BuildLimits(1800, 30, 10), BuildLimits())
        for invalid in (0, -1, float("nan"), float("inf")):
            for index in range(3):
                bounds = [4, 0.15, 0.15]
                bounds[index] = invalid
                with self.subTest(value=invalid, index=index), self.assertRaises(ValueError):
                    BuildLimits(*bounds)
        with self.assertRaises(ValueError):
            run_bounded([])


if __name__ == "__main__":
    unittest.main()
