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

/** Incremental SHA-256 for file integrity, with O(n) time and fixed 64 KiB I/O. */
export async function sha256File(file: Blob, signal: AbortSignal): Promise<string> {
  const hash = new Sha256();
  for (let offset = 0; offset < file.size; offset += 65536) {
    signal.throwIfAborted();
    hash.update(new Uint8Array(await file.slice(offset, offset + 65536).arrayBuffer()));
  }
  signal.throwIfAborted();
  return hash.finish();
}

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);
const rotate = (value: number, bits: number) => (value >>> bits) | (value << (32 - bits));

/** SHA-256 compression and padding as specified in FIPS 180-4; not an authentication mechanism. */
class Sha256 {
  private readonly state = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
  private readonly block = new Uint8Array(64);
  private readonly words = new Uint32Array(64);
  private used = 0;
  private length = 0;

  update(bytes: Uint8Array) {
    this.length += bytes.length;
    if (!Number.isSafeInteger(this.length * 8)) throw new Error('File length exceeds hash limits.');
    let offset = 0;
    while (offset < bytes.length) {
      const count = Math.min(64 - this.used, bytes.length - offset);
      this.block.set(bytes.subarray(offset, offset + count), this.used);
      this.used += count;
      offset += count;
      if (this.used === 64) { this.compress(); this.used = 0; }
    }
  }

  finish(): string {
    const bits = this.length * 8;
    this.block[this.used++] = 0x80;
    if (this.used > 56) {
      this.block.fill(0, this.used);
      this.compress();
      this.used = 0;
    }
    this.block.fill(0, this.used, 56);
    const view = new DataView(this.block.buffer);
    view.setUint32(56, Math.floor(bits / 0x100000000));
    view.setUint32(60, bits >>> 0);
    this.compress();
    return Array.from(this.state, (word) => word.toString(16).padStart(8, '0')).join('');
  }

  private compress() {
    const w = this.words;
    const view = new DataView(this.block.buffer);
    for (let i = 0; i < 16; i++) w[i] = view.getUint32(i * 4);
    for (let i = 16; i < 64; i++) {
      const x = w[i - 15]!, y = w[i - 2]!;
      w[i] = (w[i - 16]! + (rotate(x, 7) ^ rotate(x, 18) ^ (x >>> 3))
        + w[i - 7]! + (rotate(y, 17) ^ rotate(y, 19) ^ (y >>> 10))) >>> 0;
    }
    let a = this.state[0]!, b = this.state[1]!, c = this.state[2]!, d = this.state[3]!;
    let e = this.state[4]!, f = this.state[5]!, g = this.state[6]!, h = this.state[7]!;
    for (let i = 0; i < 64; i++) {
      const t1 = (h + (rotate(e, 6) ^ rotate(e, 11) ^ rotate(e, 25))
        + ((e & f) ^ (~e & g)) + K[i]! + w[i]!) >>> 0;
      const t2 = ((rotate(a, 2) ^ rotate(a, 13) ^ rotate(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    this.state[0] = (this.state[0]! + a) >>> 0;
    this.state[1] = (this.state[1]! + b) >>> 0;
    this.state[2] = (this.state[2]! + c) >>> 0;
    this.state[3] = (this.state[3]! + d) >>> 0;
    this.state[4] = (this.state[4]! + e) >>> 0;
    this.state[5] = (this.state[5]! + f) >>> 0;
    this.state[6] = (this.state[6]! + g) >>> 0;
    this.state[7] = (this.state[7]! + h) >>> 0;
  }
}
