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
"""Bound a POSIX release build and its process group without changing test deadlines.

The build has a thirty-minute wall-clock budget. A marker emitted after a failed
Gradle test starts a separate thirty-second shutdown grace period; it is not a
per-test execution limit. Expiry terminates the owned process group, escalating
to SIGKILL after ten seconds. Child output is streamed without waiting for EOF
from descendants. No release publication is performed by this command.
"""

import argparse
import codecs
from contextlib import contextmanager
from dataclasses import dataclass
import math
import io
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import time
import threading
from typing import Sequence, TextIO


TEST_FAILURE_MARKER = "ZEROECHO_TEST_FAILURE "


@dataclass(frozen=True)
class BuildLimits:
    """Define independent positive, finite process budgets in seconds.

    Attributes:
        build_seconds: Maximum duration of a healthy or silent build.
        failure_shutdown_grace_seconds: Time allowed for normal shutdown after
            the first reported test failure. Healthy tests do not use this limit.
        kill_grace_seconds: Time allowed after SIGTERM before SIGKILL is sent to
            remaining members of the owned process group.
    """

    build_seconds: float = 1800
    failure_shutdown_grace_seconds: float = 30
    kill_grace_seconds: float = 10

    def __post_init__(self):
        for value in (self.build_seconds, self.failure_shutdown_grace_seconds,
                      self.kill_grace_seconds):
            if not math.isfinite(value) or value <= 0:
                raise ValueError("Build limits must be positive, finite seconds")


class _OutputRelay:
    """Keep process supervision independent of child EOF and log-pipe backpressure."""

    def __init__(self, process, output, diagnostic_log):
        self.selector = selectors.DefaultSelector()
        self.pipe = process.stdout
        os.set_blocking(self.pipe.fileno(), False)
        self.selector.register(self.pipe, selectors.EVENT_READ)
        self.output = output
        self.diagnostic_log = diagnostic_log
        self.diagnostic_error = False
        self.recent_output = ""
        self.decoder = codecs.getincrementaldecoder("utf-8")("replace")
        self.tail = ""
        self.failed = False
        self.output_error = False
        self.pending = bytearray()
        try:
            self.output_fd = output.fileno()
        except (AttributeError, io.UnsupportedOperation):
            self.output_fd = None
        self.output_blocking = None
        if self.output_fd is not None:
            self.output_blocking = os.get_blocking(self.output_fd)
            os.set_blocking(self.output_fd, False)

    def write(self, text):
        """Queue text without allowing a full runner log pipe to stop deadlines."""
        if self.output_error:
            return
        if self.output_fd is None:
            try:
                self.output.write(text)
                self.output.flush()
            except (OSError, ValueError):
                self.output_error = True
        else:
            self.pending.extend(text.encode(getattr(self.output, "encoding", None) or "utf-8", "replace"))
            self.flush_output()

    def flush_output(self):
        """Write only bytes currently accepted by the nonblocking destination."""
        while self.pending and not self.output_error:
            try:
                count = os.write(self.output_fd, self.pending)
                del self.pending[:count]
            except BlockingIOError:
                break
            except OSError:
                self.output_error = True

    @staticmethod
    def emergency(message):
        """Try stderr independently when the ordinary output destination is blocked."""
        previous = None
        try:
            previous = os.get_blocking(2)
            os.set_blocking(2, False)
            os.write(2, message.encode("utf-8", "replace"))
        except OSError:
            pass
        finally:
            if previous is not None:
                try:
                    os.set_blocking(2, previous)
                except OSError:
                    pass

    def record(self, message):
        """Persist diagnostics independently of the runner's output pipe."""
        if self.diagnostic_log is not None and not self.diagnostic_error:
            try:
                self.diagnostic_log.write(message)
                self.diagnostic_log.flush()
            except OSError:
                self.diagnostic_error = True
                self.output_error = True
                self.emergency("\n::error::BUILD_DIAGNOSTIC_LOG_UNAVAILABLE: terminating build.\n")

    def diagnostic(self, message):
        """Persist a failure and attempt both normal and emergency diagnostic outlets."""
        self.record(message)
        if self.recent_output:
            self.record("Last observed build output:\n" + self.recent_output + "\n")
        self.write(message)
        if self.pending or self.output_error:
            self.emergency(message)

    def read_available(self, wait):
        """Relay one chunk while bounding pending output to a watermark plus one chunk."""
        self.flush_output()
        if len(self.pending) >= 1_048_576:
            # Backpressure the child, not the supervisor. The monotonic deadlines
            # remain active even if the external runner never reads another byte.
            time.sleep(wait)
            return
        for key, _ in self.selector.select(wait):
            try:
                chunk = os.read(key.fd, 65536)
            except BlockingIOError:
                continue
            if not chunk:
                self.selector.unregister(key.fileobj)
                continue
            text = self.decoder.decode(chunk)
            self.recent_output = (self.recent_output + text)[-4096:]
            combined = self.tail + text
            self.failed = self.failed or TEST_FAILURE_MARKER in combined
            self.tail = combined[-len(TEST_FAILURE_MARKER):]
            self.write(text)
        self.flush_output()

    def close(self):
        """Finish local resources within a finite grace without waiting for EOF."""
        try:
            self.write(self.decoder.decode(b"", final=True))
            until = time.monotonic() + 0.25
            while self.pending and not self.output_error and time.monotonic() < until:
                self.flush_output()
                if self.pending:
                    time.sleep(0.01)
            if self.pending or self.output_error:
                message = "\n::error::BUILD_OUTPUT_UNAVAILABLE: runner output could not be fully delivered.\n"
                self.record(message)
                self.emergency(message)
                self.output_error = True
        finally:
            if self.output_blocking is not None:
                os.set_blocking(self.output_fd, self.output_blocking)
            self.selector.close()
            self.pipe.close()
            if self.diagnostic_log is not None:
                try:
                    self.diagnostic_log.close()
                except OSError:
                    self.output_error = True
                    self.emergency("\n::error::BUILD_DIAGNOSTIC_LOG_UNAVAILABLE: log closure failed.\n")


class _BuildCancelled(BaseException):
    def __init__(self, signum):
        self.signum = signum


class _CancellationRequest:
    """Latch the first cancellation before unwinding into bounded cleanup."""

    def __init__(self):
        self.signum = None

    def __call__(self, signum, _frame):
        if self.signum is None:
            self.signum = signum
            raise _BuildCancelled(signum)


def _signal_group(group, signum):
    try:
        os.killpg(group, signum)
        return True
    except ProcessLookupError:
        return False


@contextmanager
def _cancellation_shield():
    # Change both dispositions atomically with respect to their delivery so a
    # rapid SIGINT/SIGTERM pair cannot escape between handler updates.
    protected = {signal.SIGTERM, signal.SIGINT}
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, protected)
    try:
        handlers = {signum: signal.signal(signum, signal.SIG_IGN) for signum in protected}
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
    try:
        yield
    finally:
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, protected)
        try:
            for signum, handler in handlers.items():
                signal.signal(signum, handler)
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)


def _stop_group(process, grace, relay):
    with _cancellation_shield():
        return _stop_group_uninterrupted(process, grace, relay)


def _stop_group_uninterrupted(process, grace, relay):
    if not _signal_group(process.pid, signal.SIGTERM):
        return False
    until = time.monotonic() + grace
    while time.monotonic() < until:
        process.poll()
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            return False
        relay.read_available(min(0.05, max(0, until - time.monotonic())))
    forced = _signal_group(process.pid, 0)
    if forced:
        relay.diagnostic(
            "\n::error::PROCESS_GROUP_SHUTDOWN_TIMEOUT: owned build processes did not stop "
            f"within {grace:g}s after SIGTERM; sending SIGKILL.\n")
        _signal_group(process.pid, signal.SIGKILL)
    # Reap a normally killable launcher, but do not wait on an uninterruptible
    # kernel operation or on a pipe still held by a surviving descendant.
    try:
        process.wait(timeout=0.25)
    except subprocess.TimeoutExpired:
        pass
    relay.read_available(0)
    return forced


def run_bounded(command: Sequence[str], limits: BuildLimits = BuildLimits(),
                output: TextIO | None = None, diagnostic_log: Path | None = None) -> int:
    """Run one POSIX command with bounded failure shutdown and process cleanup.

    The command is executed without a shell in a new session/process group. Its
    environment and working directory are inherited unchanged. Output is relayed
    to ``output`` (standard output by default). File-descriptor destinations are
    written nonblockingly; pending output is bounded by backpressuring the child
    without stopping deadline checks. If output cannot be delivered, the build
    fails and diagnostics are attempted independently on stderr. In-memory output
    streams must provide nonblocking write/flush operations.

    A test-failure marker is latched:
    even a subsequent zero child exit is reported as failure. Ordinary child exit
    codes are preserved; signal deaths become conventional ``128 + signal`` codes.

    Healthy tests may exceed the failure-shutdown grace. That grace starts only
    when the first marker is observed. Either deadline returns 124 and emits a
    distinct ``::error::`` diagnostic before terminating the owned process group.
    Remaining descendants are also terminated if the launcher exits without them;
    failure to finish that cleanup within its grace also returns 124. SIGTERM and
    keyboard interruption trigger bounded cleanup and return 143 or 130 respectively.
    Repeated SIGTERM/SIGINT signals cannot interrupt an ongoing bounded cleanup;
    previous signal handlers are restored before returning.

    Args:
        command: Nonempty executable/argument sequence; no shell expansion occurs.
        limits: Positive finite second budgets for build, failure shutdown and kill.
        output: Writable text stream; it is not closed by this call. Descriptor
            blocking flags are temporarily changed and restored.
        diagnostic_log: Optional local file outside the build's clean-output tree.
            It is truncated for this invocation and records failures independently
            of output-pipe availability; parent directories are created as needed.

    Returns:
        Zero only when the command succeeds without a reported test failure and
        without exceeding a deadline; otherwise a nonzero process or watchdog code.

    Raises:
        ValueError: If command is empty, the platform is not POSIX, or the call is
            made outside the main Python thread.
        OSError: If the child cannot be launched or its output cannot be read.
    """
    if not command or os.name != "posix" or threading.current_thread() is not threading.main_thread():
        raise ValueError("A nonempty POSIX command and the main Python thread are required")
    destination = output if output is not None else sys.stdout
    log = None
    if diagnostic_log is not None:
        path = Path(diagnostic_log)
        path.parent.mkdir(parents=True, exist_ok=True)
        log = path.open("w", encoding="utf-8")
    try:
        process = subprocess.Popen(list(command), stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, start_new_session=True)
    except BaseException:
        if log is not None:
            log.close()
        raise
    relay = _OutputRelay(process, destination, log)
    relay.record(
        f"Release build limit: {limits.build_seconds:g}s; failure shutdown grace: "
        f"{limits.failure_shutdown_grace_seconds:g}s after first reported test failure; "
        f"SIGTERM grace: {limits.kill_grace_seconds:g}s.\n")
    cancellation = _CancellationRequest()
    protected = {signal.SIGTERM, signal.SIGINT}
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, protected)
    try:
        previous_handlers = {signum: signal.signal(signum, cancellation) for signum in protected}
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
    try:
        result = _monitor(process, relay, limits)
    except (_BuildCancelled, KeyboardInterrupt) as interruption:
        with _cancellation_shield():
            signum = interruption.signum if isinstance(interruption, _BuildCancelled) else signal.SIGINT
            relay.diagnostic(f"\n::error::BUILD_INTERRUPTED: received signal {signum}; terminating owned processes.\n")
            _stop_group(process, limits.kill_grace_seconds, relay)
            result = 128 + signum
    except BaseException:
        _stop_group(process, limits.kill_grace_seconds, relay)
        raise
    finally:
        with _cancellation_shield():
            relay.close()
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, protected)
        try:
            for signum, handler in previous_handlers.items():
                signal.signal(signum, handler)
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
    return result if result != 0 else 2 if relay.output_error else 0


def _monitor(process, relay, limits):
    started = time.monotonic()
    failed_at = None
    while True:
        relay.read_available(0.1)
        now = time.monotonic()
        if relay.failed and failed_at is None:
            failed_at = now
            relay.diagnostic(
                "\n::error::TEST_FAILURE_REPORTED: allowing at most "
                f"{limits.failure_shutdown_grace_seconds:g}s for build shutdown; "
                "this is not a healthy-test execution deadline.\n")
        if relay.output_error:
            relay.diagnostic("\n::error::BUILD_OUTPUT_UNAVAILABLE: terminating build after output failure.\n")
            _stop_group(process, limits.kill_grace_seconds, relay)
            return 2
        code = process.poll()
        if code is not None:
            # Drain queued bytes without waiting for a pipe still held by a descendant.
            relay.read_available(0)
            forced = _stop_group(process, limits.kill_grace_seconds, relay)
            for _ in range(16):
                if not relay.selector.get_map() or not relay.selector.select(0):
                    break
                relay.read_available(0)
            code = code if code >= 0 else 128 - code
            if forced:
                return 124
            return code if code != 0 else int(relay.failed)
        reason = None
        if now - started >= limits.build_seconds:
            reason = f"BUILD_TIMEOUT: build exceeded {limits.build_seconds:g}s"
        elif failed_at is not None and now - failed_at >= limits.failure_shutdown_grace_seconds:
            reason = ("TEST_FAILURE_SHUTDOWN_TIMEOUT: build did not exit within "
                      f"{limits.failure_shutdown_grace_seconds:g}s after a reported test failure")
        if reason is not None:
            relay.diagnostic(f"\n::error::{reason}; terminating build process group.\n")
            _stop_group(process, limits.kill_grace_seconds, relay)
            return 124


def main(argv=None) -> int:
    """Validate the release version and run only the bounded build/check stage.

    Args:
        argv: Optional command-line arguments; ``None`` reads ``sys.argv``.

    Returns:
        The bounded build's exit code, or 2 for invalid input/launch failure.
        Publishing is intentionally left to later successful workflow steps.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True, help="validated release version, for example 1.2.3")
    parser.add_argument("--diagnostic-log", type=Path,
                        default=Path(os.environ.get("RUNNER_TEMP", ".gradle/release-watchdog"))
                        / "zeroecho-release-watchdog.log",
                        help="local failure log retained even if the runner output pipe blocks")
    args = parser.parse_args(argv)
    from prepare_central_bundle import release_version
    try:
        version = release_version("release@" + args.version)
        return run_bounded(["./gradlew", "clean", "check", "javadoc", ":app:distTar", ":app:distZip",
                            "--no-daemon", "--console=plain", "--no-configuration-cache",
                            "-PreleaseWatchdog=true", "-PreleaseVersion=" + version],
                           diagnostic_log=args.diagnostic_log)
    except (OSError, ValueError) as failure:
        print(f"::error::Release build could not start: {failure}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("::error::Release build interrupted; owned processes terminated.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
