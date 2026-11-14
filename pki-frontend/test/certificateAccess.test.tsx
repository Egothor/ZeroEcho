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

import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, expect, it } from 'vitest';
import userEvent from '@testing-library/user-event';
import { certificateArtifact, statusArtifact } from '@/api/certificateArtifacts';
import { ResultView } from '@/components/ResultView';
import { CertificateDownloads } from '@/components/CertificateDownloads';
import { PublicRepositoryPage } from '@/pages/PublicRepositoryPage';
import { DemoModeContext } from '@/demo/demoModeContext';
import { resetTransport, setTransport, type TransportRequest } from '@/api/transport';
afterEach(resetTransport);
const envelope = (operation: string, result: unknown) => ({ version: 1, requestId: 'wire', operation, status: 'SUCCEEDED', failure: null, result });
const rep = (id: string, label: string) => ({ id, label, mediaType: 'application/octet-stream', fileName: `certificate.${id}`, href: `/admin/v1/certificate-artifacts/cert%3Aone/content?representation=${id}` });
function fixture(options: { available?: boolean; authorityListAvailable?: boolean; basePath?: string; representations?: ReturnType<typeof rep>[] } = {}) {
  const calls: TransportRequest[] = [];
  setTransport(async request => {
    calls.push(request);
    const result = request.path === '/admin/v1/realm'
      ? envelope('realm.inspect', { realmId: 'one', displayName: 'One', authorityExposure: 'PRIVATE', authorityCreationPermitted: true,
        publicRepository: { available: options.available ?? false, authorityListAvailable: options.authorityListAvailable ?? false, ...(options.basePath ? { basePath: options.basePath } : {}) } })
      : request.path.startsWith('/admin/v1/certificate-artifacts/') || request.path.startsWith('/admin/v1/authorities/')
        ? envelope('certificate.artifact.inspect', { value: { credentialId: 'cert:one', authorityId: 'ca:one', formatId: 'custom-provider', representations: options.representations ?? [rep('original', 'Provider binary')] } })
        : { authorities: [] };
    return { status: 200, headers: {}, body: JSON.stringify(result) };
  });
  return calls;
}
function mount(node: React.ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const view = render(<QueryClientProvider client={client}><MemoryRouter>{node}</MemoryRouter></QueryClientProvider>);
  return { ...view, client };
}
it('resolves current CA certificate and exposes provider-owned native attachments without text-fetching binary', async () => {
  const calls = fixture({ representations: [rep('original', 'DER'), rep('pem', 'PEM')] });
  const view = mount(<CertificateDownloads authorityId="ca:one" />);
  const der = await screen.findByRole('link', { name: 'Download CA certificate — DER' });
  expect(der).toHaveAttribute('href', '/admin/v1/certificate-artifacts/cert%3Aone/content?representation=original');
  expect(der).toHaveAttribute('download', 'certificate.original');
  expect(await screen.findByRole('link', { name: 'Download CA certificate — PEM' })).toHaveAttribute('href', expect.stringContaining('representation=pem'));
  expect(calls.map(call => call.path)).toEqual(['/admin/v1/authorities/ca%3Aone/certificate']);
  expect(calls.every(call => !call.path.endsWith('/content'))).toBe(true);
  view.client.clear();
});
it('does not invent PEM for a provider that offers only its own binary representation', async () => {
  fixture(); const view = mount(<CertificateDownloads credentialId="cert:one" />);
  await screen.findByRole('link', { name: 'Download certificate — Provider binary' });
  expect(screen.queryByRole('link', { name: /PEM/ })).not.toBeInTheDocument(); view.client.clear();
});
it('explains metadata-only access and never offers unauthorized content links', async () => {
  fixture({ representations: [] }); const view = mount(<CertificateDownloads credentialId="cert:one" />);
  expect(await screen.findByText(/no authorized download representation/)).toBeVisible();
  expect(screen.queryByRole('link')).not.toBeInTheDocument(); view.client.clear();
});
it('rejects an injected or noncanonical download URL from metadata', async () => {
  fixture({ representations: [{ ...rep('original', 'Original'), href: 'https://elsewhere.invalid/content' }] });
  await expect(certificateArtifact({ credentialId: 'cert:one' })).rejects.toThrow('invalid certificate download link');
});
it('never falls through to real certificate endpoints in demo mode', async () => {
  const calls = fixture(); const view = mount(<DemoModeContext.Provider value={{ enabled: true, role: 'ADMINISTRATOR', setRole: () => undefined }}><CertificateDownloads authorityId="ca:one" /></DemoModeContext.Provider>);
  expect(screen.getByText(/require a live authenticated deployment/)).toBeVisible();
  expect(screen.queryByRole('link')).not.toBeInTheDocument(); expect(calls).toHaveLength(0); view.client.clear();
});
it.each([{ available: false }, { available: true }])('does not send public requests without an explicitly usable public binding: %j', async options => {
  const calls = fixture(options); const view = mount(<PublicRepositoryPage />);
  await screen.findByText(/unavailable on this console endpoint/);
  const list = screen.getByRole('button', { name: 'List authorities' }); expect(list).toBeDisabled(); fireEvent.click(list);
  expect(screen.getByRole('link', { name: 'Certificates and downloads' })).toHaveAttribute('href', '/issuance');
  expect(calls.every(call => !call.path.startsWith('/public/'))).toBe(true); view.client.clear();
});
it('uses the explicitly advertised public binding with its query and canonical encoded identity intact', async () => {
  const calls = fixture({ available: true, authorityListAvailable: true, basePath: '/public/v1' }); const view = mount(<PublicRepositoryPage />);
  await waitFor(() => expect(screen.getByRole('button', { name: 'List authorities' })).toBeEnabled());
  fireEvent.click(screen.getByRole('button', { name: 'List authorities' }));
  await waitFor(() => expect(calls.some(call => call.path === '/public/v1/authorities')).toBe(true));
  expect(calls.find(call => call.path === '/public/v1/authorities')?.query).toEqual({ limit: 100 });
  fireEvent.change(screen.getByLabelText('Authority id'), { target: { value: 'ca:one' } });
  expect(screen.getByRole('link', { name: 'Current chain' })).toHaveAttribute('href', '/public/v1/authorities/ca%3Aone/chain'); view.client.clear();
});

it('loads compact row access only on demand, avoiding a metadata request for every table row', async () => {
  const calls = fixture(); const view = mount(<CertificateDownloads authorityId="ca:one" compact />);
  expect(calls).toHaveLength(0);
  fireEvent.click(screen.getByRole('button', { name: 'Download CA certificate' }));
  await screen.findByRole('link', { name: 'Download CA certificate — Provider binary' });
  expect(calls.map(call => call.path)).toEqual(['/admin/v1/authorities/ca%3Aone/certificate']); view.client.clear();
});
it('offers immediate download from a completed operation result without copying its credential ID', async () => {
  const calls = fixture(); const view = mount(<ResultView value={{ value: { credentialId: 'cert:one', authorityId: 'ca:one' } }} />);
  expect(await screen.findByRole('link', { name: 'Download certificate — Provider binary' })).toHaveAttribute('download', 'certificate.original');
  expect(calls[0]?.path).toBe('/admin/v1/certificate-artifacts/cert%3Aone'); view.client.clear();
});

it('rejects metadata for another credential instead of offering its attachment', async () => {
  fixture();
  await expect(certificateArtifact({ credentialId: 'cert:different' })).rejects.toThrow('different certificate identity');
});

it('does not list authorities when listing is unpublished while keeping public artifact links usable', async () => {
  const calls = fixture({ available: true, authorityListAvailable: false, basePath: '/public/v1' });
  const view = mount(<PublicRepositoryPage />);
  expect(await screen.findByText(/authority list is not published/)).toBeVisible();
  const list = screen.getByRole('button', { name: 'List authorities' });
  expect(list).toBeDisabled(); fireEvent.click(list);
  const identity = screen.getByLabelText('Authority id'); expect(identity).toBeEnabled();
  fireEvent.change(identity, { target: { value: 'ca:one' } });
  expect(screen.getByRole('link', { name: 'Current chain' })).toHaveAttribute('href', '/public/v1/authorities/ca%3Aone/chain');
  expect(calls.every(call => !call.path.startsWith('/public/'))).toBe(true);
  view.client.clear();
});

it('offers completed status-object native attachments and validates the exact status identity and link', async () => {
  const calls: string[] = [];
  setTransport(async request => {
    calls.push(request.path);
    return { status: 200, headers: {}, body: JSON.stringify(envelope('status.artifact.inspect', { value: {
      statusObjectId: 'crl:one', authorityId: 'ca:one', formatId: 'custom', type: 'CRL', representations: [
        { id: 'original', label: 'DER', mediaType: 'application/pkix-crl', fileName: 'status.crl', href: '/admin/v1/status-artifacts/crl%3Aone/content?representation=original' },
        { id: 'pem', label: 'PEM', mediaType: 'application/x-pem-file', fileName: 'status.pem', href: '/admin/v1/status-artifacts/crl%3Aone/content?representation=pem' }
      ] } })) };
  });
  const view = mount(<ResultView value={{ statusObjectId: 'crl:one' }} />);
  expect(await screen.findByRole('link', { name: 'Download status object — DER' })).toHaveAttribute('download', 'status.crl');
  expect(screen.getByRole('link', { name: 'Download status object — PEM' })).toHaveAttribute('href', '/admin/v1/status-artifacts/crl%3Aone/content?representation=pem');
  await userEvent.tab();
  expect(screen.getByRole('link', { name: 'Download status object — DER' })).toHaveFocus();
  expect(calls).toEqual(['/admin/v1/status-artifacts/crl%3Aone']);
  view.unmount(); view.client.clear();
});
it('keeps status metadata-only access explicit and never invents links', async () => {
  setTransport(async () => ({ status: 200, headers: {}, body: JSON.stringify(envelope('status.artifact.inspect', { value: {
    statusObjectId: 'status:one', authorityId: 'ca:one', formatId: 'opaque', type: 'CRL', representations: [] } })) }));
  const view = mount(<CertificateDownloads statusObjectId="status:one" />);
  await screen.findByText(/Status object metadata is visible/);
  expect(screen.queryByRole('link')).toBeNull(); view.client.clear();
});

it('rejects substituted status identities and unsafe attachment links', async () => {
  for(const [identity, href] of [['other:status','/admin/v1/status-artifacts/crl%3Aone/content?representation=original'],['crl:one','https://elsewhere.invalid/file']]) {
    setTransport(async () => ({status:200,headers:{},body:JSON.stringify(envelope('status.artifact.inspect',{value:{
      statusObjectId:identity,authorityId:'ca:one',formatId:'x509',type:'CRL',representations:[{id:'original',label:'DER',mediaType:'application/pkix-crl',fileName:'status.crl',href}]
    }}))}));
    await expect(statusArtifact('crl:one')).rejects.toThrow(/different status identity|invalid status download link/);
  }
});
