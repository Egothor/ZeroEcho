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

import { useRef, useState } from 'react';
import { Alert, Button, Paper, Stack, TextField, Typography } from '@mui/material';
import { PageHeader } from '@/components/PageHeader';
import { OPERATIONS } from '@/api/operationCatalog';
import { executeOperation, useOperationDescriptors, type FieldValue } from '@/api/operations';
import { sha256File } from '@/api/backupHash';

interface Artifact {
  artifactHandle: string;
  backupId: string;
  length: number;
  sha256: string;
  manifestSha256: string;
  state: string;
  restoreId: string;
  purpose: 'IMPORT' | 'EXPORT';
}

function artifact(value: unknown): Artifact {
  if (typeof value !== 'object' || value === null) throw new Error('Invalid backup response.');
  const record = value as Record<string, unknown>;
  for (const name of ['artifactHandle', 'backupId', 'sha256', 'manifestSha256', 'state', 'restoreId']) {
    if (typeof record[name] !== 'string') throw new Error('Invalid backup response.');
  }
  if (typeof record.length !== 'number' || !Number.isSafeInteger(record.length)) throw new Error('Invalid backup length.');
  if (record.purpose !== 'IMPORT' && record.purpose !== 'EXPORT') throw new Error('Invalid backup purpose.');
  return record as unknown as Artifact;
}

/** Explicit upload, approval and cold-activation workflow over server-owned operations. */
export function BackupPage() {
  const descriptors = useOperationDescriptors();
  const available = new Set(descriptors.data?.operations.map((operation) => operation.operation) ?? []);
  const [current, setCurrent] = useState<Artifact>();
  const [label, setLabel] = useState('PKI backup');
  const [backupId, setBackupId] = useState('');
  const [file, setFile] = useState<File>();
  const [workflow, setWorkflow] = useState('');
  const [approvalId, setApprovalId] = useState('');
  const [pending, setPending] = useState<{ id: string; values: Record<string, FieldValue> }>();
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);
  const cancellation = useRef<AbortController | undefined>(undefined);
  const frame = useRef<HTMLIFrameElement>(null);

  async function run(work: (signal: AbortSignal) => Promise<void>) {
    const controller = new AbortController();
    cancellation.current = controller;
    setBusy(true);
    setMessage('');
    try { await work(controller.signal); }
    catch (error) {
      setMessage(controller.signal.aborted
        ? 'Request cancelled. If restoration was submitted, inspect its workflow before taking further action.'
        : error instanceof Error ? error.message : 'Request failed. Inspect the workflow if its outcome is uncertain.');
    } finally { setBusy(false); cancellation.current = undefined; }
  }

  async function operation(id: string, values: Record<string, FieldValue>, signal: AbortSignal, useApproval = true) {
    const spec = OPERATIONS.find((entry) => entry.id === id);
    if (!spec || !available.has(id)) throw new Error('This operation is unavailable or not authorized.');
    const outcome = await executeOperation(spec, values, {
      signal, ...(useApproval && approvalId ? { approvalId } : {}),
    });
    if (outcome.kind === 'approval-required') {
      setPending({ id, values });
      setMessage('Approval is required. Request it, wait for an independent decision, then retry this action.');
      return undefined;
    }
    if (outcome.kind !== 'succeeded') throw new Error('The server did not complete this action. Inspect the workflow before retrying restoration.');
    if (useApproval) setApprovalId('');
    setPending(undefined);
    return outcome.envelope.result;
  }

  function accept(result: unknown) {
    const value = artifact((result as { value?: unknown } | undefined)?.value);
    setCurrent(value);
    setBackupId(value.backupId);
    setWorkflow(value.artifactHandle);
    setMessage(value.state === 'STAGED'
      ? 'Restore staged. An administrator must restart the server; then inspect the outcome here.'
      : value.state === 'ACTIVATED' ? 'Restore activated successfully after restart.'
        : value.state === 'UNCERTAIN' ? 'Restore outcome is uncertain. Reconcile after restart; do not submit another restore.'
          : value.state === 'REJECTED' ? 'Restore was rejected. The requested replacement was not activated.'
            : value.state);
  }

  async function upload(signal: AbortSignal) {
    if (!file || !current) throw new Error('Select a file and reserve its upload first.');
    if (file.size !== current.length || await sha256File(file, signal) !== current.sha256) {
      throw new Error('The selected file differs from the reserved upload.');
    }
    const response = await fetch('/admin/v1/backup/upload', {
      method: 'POST', credentials: 'same-origin', signal, body: file,
      headers: { 'Content-Type': 'application/zip', 'X-ZeroEcho-Artifact': current.artifactHandle,
        'X-ZeroEcho-Transfer': '1', ...(approvalId ? { 'X-ZeroEcho-Approval': approvalId } : {}) },
    });
    const body: unknown = await response.json();
    if (response.status === 409 && JSON.stringify(body).includes('APPROVAL_REQUIRED')) {
      setPending({ id: 'backup.stream.upload', values: { artifactHandle: current.artifactHandle } });
      setMessage('Upload approval is required. Request approval, then retry the upload.');
      return;
    }
    if (!response.ok) throw new Error('Upload did not complete. Reserve a new upload after checking server status.');
    accept((body as { result?: unknown }).result);
    setApprovalId('');
  }

  const handleValues = { artifactHandle: current?.artifactHandle ?? '' };
  return (
    <>
      <PageHeader title="Backup and restore" description="Download a logical backup or verify and stage a local archive for activation after restart." />
      {descriptors.isLoading && <Alert severity="info">Loading available operations…</Alert>}
      {!descriptors.isLoading && !available.has('backup.stream.export') && !available.has('backup.stream.reserve') &&
        <Alert severity="warning">Backup transfer is disabled or your account has no transfer permission.</Alert>}
      <Stack spacing={3}>
        <Paper variant="outlined" sx={{ p: 2 }}>
          <Stack spacing={2}>
            <Typography variant="h2">Export</Typography>
            <TextField label="Backup label" value={label} onChange={(event) => setLabel(event.target.value)} />
            <Button disabled={busy || !available.has('backup.stream.export')} onClick={() => void run(async (signal) => {
              const result = await operation('backup.stream.export', { label }, signal);
              if (result) accept(result);
            })}>Create backup</Button>
            <form action="/admin/v1/backup/download" method="post" target="backup-download">
              <input type="hidden" name="artifactHandle" value={current?.artifactHandle ?? ''} />
              <input type="hidden" name="approvalId" value={approvalId} />
              <Button type="submit" disabled={busy || current?.purpose !== 'EXPORT' || current.state !== 'READY' || !available.has('backup.stream.download')}>
                Download archive once
              </Button>
            </form>
            <iframe ref={frame} name="backup-download" title="Backup download response" hidden onLoad={() => {
              const text = frame.current?.contentDocument?.body.textContent ?? '';
              if (text.includes('APPROVAL_REQUIRED') && current) {
                setPending({ id: 'backup.stream.download', values: { artifactHandle: current.artifactHandle } });
                setMessage('Download approval is required. Request approval, then retry the download.');
              } else if (text.includes('"FAILED"')) setMessage('Download was rejected. Create a new export if the previous handle was consumed.');
            }} />
          </Stack>
        </Paper>
        <Paper variant="outlined" sx={{ p: 2 }}>
          <Stack spacing={2}>
            <Typography variant="h2">Verify a local archive</Typography>
            <Typography>Keep the backup identifier shown when exporting. Integrity verification does not authenticate the archive’s origin.</Typography>
            <input aria-label="Backup archive" type="file" accept=".zip,application/zip" disabled={busy}
              onChange={(event) => { setFile(event.target.files?.[0]); setCurrent(undefined); }} />
            <TextField label="Source backup identifier" value={backupId} onChange={(event) => setBackupId(event.target.value)} />
            <Button disabled={busy || !file || !backupId || !available.has('backup.stream.reserve')}
              onClick={() => void run(async (signal) => {
                if (!file) return;
                const sha256 = await sha256File(file, signal);
                const result = await operation('backup.stream.reserve', { backupId, length: file.size, sha256 }, signal);
                if (result) accept(result);
              })}>Check file and reserve upload</Button>
            <Button disabled={busy || !file || current?.state !== 'RESERVED' || !available.has('backup.stream.upload')}
              onClick={() => void run(upload)}>Upload archive</Button>
            <Button disabled={busy || current?.purpose !== 'IMPORT' || current.state !== 'READY' || !available.has('backup.stream.verify')}
              onClick={() => void run(async (signal) => {
                const result = await operation('backup.stream.verify', handleValues, signal);
                if (result) accept(result);
              })}>Verify uploaded archive</Button>
            <Button color="warning" disabled={busy || current?.state !== 'VERIFIED' || !available.has('backup.stream.restore')}
              onClick={() => void run(async (signal) => {
                const result = await operation('backup.stream.restore', handleValues, signal);
                if (result) accept(result);
              })}>Stage restore</Button>
          </Stack>
        </Paper>
        <Paper variant="outlined" sx={{ p: 2 }}>
          <Stack spacing={2}>
            <Typography variant="h2">Approval and recovery</Typography>
            <TextField label="Approval identifier" value={approvalId} onChange={(event) => setApprovalId(event.target.value)} />
            <Button disabled={busy || !pending || !available.has('security.approval.request')}
              onClick={() => void run(async (signal) => {
                if (!pending) return;
                const id = crypto.randomUUID();
                const result = await operation('security.approval.request', {
                  approvalId: id, targetOperation: pending.id, targetArguments: JSON.stringify(pending.values),
                }, signal, false);
                if (result) { setApprovalId(id); setMessage('Approval requested. An independent approver can decide it on the Approvals page.'); }
              })}>Request approval</Button>
            <TextField label="Restore workflow identifier" value={workflow} onChange={(event) => setWorkflow(event.target.value)} />
            <Button disabled={busy || !workflow || !available.has('backup.stream.status')}
              onClick={() => void run(async (signal) => {
                const result = await operation('backup.stream.status', { artifactHandle: workflow }, signal);
                if (result) accept(result);
              })}>Inspect restore outcome</Button>
            <Button disabled={busy || !current || !['ACTIVATED', 'REJECTED'].includes(current.state)
                || !available.has('backup.stream.acknowledge')}
              onClick={() => void run(async (signal) => {
                const result = await operation('backup.stream.acknowledge', handleValues, signal);
                if (result) { setCurrent(undefined); setWorkflow(''); setMessage('Restore outcome acknowledged.'); }
              })}>Acknowledge outcome</Button>
            {current && <Typography component="pre" sx={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>
              {'Backup: ' + current.backupId + '\nArchive SHA-256: ' + current.sha256 + '\nState: ' + current.state}
            </Typography>}
          </Stack>
        </Paper>
        {busy && <Button onClick={() => cancellation.current?.abort()}>Cancel request</Button>}
        {message && <Alert severity="info" role="status">{message}</Alert>}
      </Stack>
    </>
  );
}
