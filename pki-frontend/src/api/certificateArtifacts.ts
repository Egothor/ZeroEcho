/*******************************************************************************
 * Copyright (C) 2025, Leo Galambos
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

import { z } from 'zod';
import { api } from '@/api/client';

const artifact = z.object({ credentialId: z.string().min(1), authorityId: z.string().min(1), formatId: z.string().min(1),
  representations: z.array(z.object({ id: z.string().min(1), label: z.string().min(1), mediaType: z.string().min(1), fileName: z.string().min(1), href: z.string().min(1) })) });
/** Server-authorized format representations; an empty list grants no content access. */
export type CertificateArtifact = z.infer<typeof artifact>;

/**
 * Reads authorized certificate metadata; never converts binary content through JSON or text.
 * @param target Exact credential identity or authority whose current CA certificate is resolved by the server.
 * @param signal Cancellation of this metadata read.
 * @returns Provider-owned representations with validated same-origin artifact links.
 */
export async function certificateArtifact(target: { credentialId: string } | { authorityId: string }, signal?: AbortSignal): Promise<CertificateArtifact> {
  const path = 'credentialId' in target ? `/admin/v1/certificate-artifacts/${encodeURIComponent(target.credentialId)}`
    : `/admin/v1/authorities/${encodeURIComponent(target.authorityId)}/certificate`;
  const response = z.object({ version: z.literal(1), requestId: z.string(), operation: z.literal('certificate.artifact.inspect'),
    status: z.literal('SUCCEEDED'), failure: z.null(), result: z.object({ value: artifact }) }).parse(await api.get<unknown>(path, { signal }));
  const metadata = response.result.value;
  if ('credentialId' in target && metadata.credentialId !== target.credentialId) throw new Error('The server returned a different certificate identity.');
  for (const representation of metadata.representations) {
    const expected = `/admin/v1/certificate-artifacts/${encodeURIComponent(metadata.credentialId)}/content?representation=${encodeURIComponent(representation.id)}`;
    if (representation.href !== expected) throw new Error('The server returned an invalid certificate download link.');
  }
  return metadata;
}

const statusArtifactSchema = artifact.omit({ credentialId: true }).extend({ statusObjectId: z.string().min(1), type: z.string().min(1) });
/**
 * Reads authorized status-object representations without loading binary content into JSON.
 * @param statusObjectId Exact immutable status identity; the returned identity must match.
 * @param signal Cancellation for the authenticated metadata request.
 * @returns Provider-owned representations with exact same-origin attachment links.
 * @throws Error when the response identity, schema or attachment link violates the contract.
 */
export async function statusArtifact(statusObjectId: string, signal?: AbortSignal): Promise<z.infer<typeof statusArtifactSchema>> {
  const response = z.object({ version: z.literal(1), requestId: z.string(), operation: z.literal('status.artifact.inspect'),
    status: z.literal('SUCCEEDED'), failure: z.null(), result: z.object({ value: statusArtifactSchema }) }).parse(
      await api.get<unknown>(`/admin/v1/status-artifacts/${encodeURIComponent(statusObjectId)}`, { signal }));
  const metadata = response.result.value;
  if (metadata.statusObjectId !== statusObjectId) throw new Error('The server returned a different status identity.');
  for (const representation of metadata.representations) {
    const expected = `/admin/v1/status-artifacts/${encodeURIComponent(statusObjectId)}/content?representation=${encodeURIComponent(representation.id)}`;
    if (representation.href !== expected) throw new Error('The server returned an invalid status download link.');
  }
  return metadata;
}
