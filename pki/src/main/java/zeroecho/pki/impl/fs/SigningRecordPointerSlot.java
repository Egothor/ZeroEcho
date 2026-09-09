/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. All advertising materials mentioning features or use of this software must
 *    display the following acknowledgement:
 *    This product includes software developed by the Egothor project.
 *
 * 4. Neither the name of the copyright holder nor the names of its contributors
 *    may be used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
package zeroecho.pki.impl.fs;

/** One-way physical record location resolved before its pointer is published. */
@SuppressWarnings({ "PMD.AvoidLiteralsInIfCondition", "PMD.AvoidSynchronizedAtMethodLevel" })
final class SigningRecordPointerSlot {
    private static final long MINIMUM_RECORD_OFFSET = Math.min(
            SigningCheckpointCodec.HEADER_BYTES, SigningWalContainerCodec.HEADER_BYTES);

    private long offset = -1L;
    private int length;

    /* default */ static SigningRecordPointerSlot resolved(long frameOffset, int frameLength) {
        SigningRecordPointerSlot result = new SigningRecordPointerSlot();
        result.resolve(frameOffset, frameLength);
        return result;
    }

    /* default */ synchronized void resolve(long frameOffset, int frameLength) {
        if (offset >= 0L || frameOffset < MINIMUM_RECORD_OFFSET
                || frameLength <= 0 || frameLength > SigningWalFrameCodec.MAX_FRAME_BYTES) {
            throw new IllegalStateException("signing frame pointer slot cannot be resolved");
        }
        try {
            Math.addExact(frameOffset, frameLength);
        } catch (ArithmeticException failure) {
            throw new IllegalStateException("signing frame pointer boundary overflows", failure);
        }
        offset = frameOffset;
        length = frameLength;
    }

    /* default */ synchronized long offset() {
        requireResolved();
        return offset;
    }

    /* default */ synchronized int length() {
        requireResolved();
        return length;
    }

    /* default */ synchronized boolean resolved() { return offset >= 0L; }

    private void requireResolved() {
        if (offset < 0L) {
            throw new IllegalStateException("signing frame pointer slot is unresolved");
        }
    }
}
