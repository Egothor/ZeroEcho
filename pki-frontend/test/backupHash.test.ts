/*
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
 */

import { describe, expect, it } from 'vitest';
import { Blob as NodeBlob } from 'node:buffer';
import { createHash } from 'node:crypto';
import { sha256File } from '@/api/backupHash';

describe('bounded file SHA-256', () => {
  it.each([0, 3, 55, 56, 63, 64, 65, 65535, 65536, 65537, 5 * 1024 * 1024])(
    'matches the independent platform digest for %i bytes', async (size) => {
      const bytes = Uint8Array.from({ length: size }, (_, index) => index % 251);
      const blob = new NodeBlob([bytes]) as unknown as Blob;
      expect(await sha256File(blob, new AbortController().signal))
        .toBe(createHash('sha256').update(bytes).digest('hex'));
    },
  );
  it('matches the published abc vector', async () => {
    expect(await sha256File(new NodeBlob(['abc']) as unknown as Blob, new AbortController().signal))
      .toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });
  it('honors cancellation before reading a file', async () => {
    const controller = new AbortController();
    controller.abort();
    await expect(sha256File(new NodeBlob(['abc']) as unknown as Blob, controller.signal)).rejects.toThrow();
  });
});

