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

import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, expect, it, vi } from 'vitest';
import { OperationForm } from '@/components/operation/OperationForm';
import { operationSpec } from '@/api/operationCatalog';
import { displayLabel } from '@/api/labels';
import { setTransport, resetTransport } from '@/api/transport';
vi.mock('@/hooks/useDerivedValues', () => ({ useDerivedValues: () => ({ values: {}, loading: false }) }));
// Subject itself uses the real MUI OperationField; only remote selector widgets are isolated.
vi.mock('@/components/operation/EntityAutocomplete', () => ({ EntityAutocomplete: ({ field, value, onChange }: {
  field: { name: string; label?: string }; value: unknown; onChange: (value: string) => void;
}) => <label>{field.label || displayLabel(field.name)}<input aria-label={field.label || displayLabel(field.name)} value={String(value ?? '')}
  onChange={event => onChange(event.target.value)} /></label> }));
afterEach(resetTransport);
const metadata = [
  { formatId: 'x509', displayName: 'X509', subjectInput: { label: 'Distinguished name', help: 'Use attribute=value, for example CN=Example Root CA. Full rules are checked by the server.', placeholder: 'CN=Example Root CA', pattern: String.raw`^\s*(?:[A-Za-z][A-Za-z0-9-]*|[0-9]+(?:\.[0-9]+)+)\s*=.*$` } },
  { formatId: 'provider-urn', displayName: 'Provider URN', subjectInput: { label: 'Provider subject URN', help: 'Use urn:example:root.', placeholder: 'urn:example:root', pattern: '^urn:example:[a-z]+$' } },
  { formatId: 'opaque', displayName: 'Opaque', subjectInput: { label: 'Opaque reference', help: 'Provider-owned opaque value.', placeholder: '' } },
];
const envelope = (operation: string, result: unknown) => ({ version: 1, requestId: 'metadata', operation, status: 'SUCCEEDED', result, failure: null });
function transport(firstChoices?: Promise<void>) {
  let choices = 0;
  setTransport(async request => {
    const operation = decodeURIComponent(request.path.split('/').at(-1)!);
    if (operation === 'profile.list-all') return { status: 200, headers: {}, body: JSON.stringify(envelope(operation, { profiles: [
      { profileId: 'root-x509', formatId: 'x509' }, { profileId: 'root-urn', formatId: 'provider-urn' }, { profileId: 'root-opaque', formatId: 'opaque' },
    ], truncated: false })) };
    if (operation === 'configuration.choices') {
      if (choices++ === 0 && firstChoices) await firstChoices;
      return { status: 200, headers: {}, body: JSON.stringify(envelope(operation, { value: { formats: metadata } })) };
    }
    return { status: 404, headers: {}, body: '{}' };
  });
}
function mount(formatId = 'x509', subjectRef = 'Bare display name', profileId = 'root-x509') {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const submit = vi.fn();
  render(<QueryClientProvider client={client}><OperationForm spec={operationSpec('ca.create')!} managedRequest initialValues={{ formatId, subjectRef, profileId, keyRef: 'key:root' }} onSubmit={submit} /></QueryClientProvider>);
  return { client, submit };
}
it('uses selected provider guidance, flags a bare DN title at input and blocks submission', async () => {
  transport(); const view = mount();
  const input = await screen.findByLabelText('Distinguished name');
  expect(input).toHaveAttribute('aria-invalid', 'true');
  expect(screen.getByText(/for example CN=Example Root CA/)).toBeVisible();
  expect(input).toHaveAttribute('placeholder', 'CN=Example Root CA');
  expect(screen.getByRole('button', { name: 'Submit request' })).toBeDisabled();
  fireEvent.submit(input.closest('form')!);
  expect(view.submit).not.toHaveBeenCalled();
  view.client.clear();
});
it.each(['CN=Example Root CA', String.raw`CN=Root\, Inc+OU=Signing,O=Example`, '2.5.4.3=Root', 'CN="Quoted, Root",O=Example'])('keeps valid coarse DN syntax %s unchanged', async subject => {
  transport(); const view = mount('x509', subject);
  const input = await screen.findByLabelText('Distinguished name');
  expect(input).toHaveAttribute('aria-invalid', 'false');
  fireEvent.click(screen.getByRole('button', { name: 'Submit request' }));
  expect(view.submit.mock.calls[0]?.[0].subjectRef).toBe(subject);
  view.client.clear();
});
it('applies a different provider pattern and never imposes DN syntax on an opaque format', async () => {
  transport(); const first = mount('provider-urn', 'CN=Wrong', 'root-urn');
  const input = await screen.findByLabelText('Provider subject URN');
  expect(input).toHaveAttribute('aria-invalid', 'true');
  fireEvent.change(input, { target: { value: 'urn:example:root' } });
  expect(screen.getByRole('button', { name: 'Submit request' })).toBeEnabled();
  first.client.clear();
});
it('accepts provider-owned opaque references without an attribute=value rule', async () => {
  transport(); const view = mount('opaque', 'opaque title with no equals', 'root-opaque');
  const input = await screen.findByLabelText('Opaque reference');
  expect(input).toHaveAttribute('aria-invalid', 'false');
  expect(screen.getByRole('button', { name: 'Submit request' })).toBeEnabled();
  expect(screen.queryByText(/CN=Example Root CA/)).not.toBeInTheDocument();
  view.client.clear();
});
it('rejects a profile/format mismatch without silently changing either selection', async () => {
  transport(); const view = mount('opaque', 'opaque-value', 'root-x509');
  expect(await screen.findByText(/profile requires format x509/)).toBeVisible();
  expect(screen.getByLabelText('Certificate format')).toHaveValue('opaque');
  expect(screen.getByRole('button', { name: 'Submit request' })).toBeDisabled();
  view.client.clear();
});
it('ignores a late previous-format response after both format and profile change', async () => {
  let release!: () => void;
  const pending = new Promise<void>(resolve => { release = resolve; });
  transport(pending); const view = mount();
  await screen.findByText('Reading selected format input rules…');
  fireEvent.change(screen.getByLabelText('Certificate format'), { target: { value: 'provider-urn' } });
  fireEvent.change(screen.getByLabelText('Certificate profile'), { target: { value: 'root-urn' } });
  await screen.findByLabelText('Provider subject URN');
  await act(async () => { release(); await pending; });
  await waitFor(() => expect(screen.getByLabelText('Provider subject URN')).toBeVisible());
  expect(screen.queryByLabelText('Distinguished name')).not.toBeInTheDocument();
  view.client.clear();
});
