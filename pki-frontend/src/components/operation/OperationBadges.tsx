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

import { Chip, Stack } from '@mui/material';
import type { OperationSpec } from '@/api/operationSchema';
import type { OperationDescriptor } from '@/api/types';

interface Props {
  readonly spec?: OperationSpec | undefined;
  readonly descriptor?: OperationDescriptor | undefined;
}

/** Security metadata badges for an operation (authoritative from the server descriptor when present). */
export function OperationBadges({ spec, descriptor }: Props) {
  const mutating = descriptor ? descriptor.mutating : spec ? !spec.read : false;
  const approval = descriptor?.approval ?? spec?.approval ?? 'NONE';
  const family = descriptor?.family ?? spec?.family;

  return (
    <Stack direction="row" spacing={0.75} sx={{ flexWrap: 'wrap', gap: 0.75 }}>
      <Chip
        size="small"
        variant="outlined"
        color={mutating ? 'primary' : 'default'}
        label={mutating ? 'mutating' : 'read-only'}
      />
      {approval === 'HIGH_RISK' && <Chip size="small" color="error" label="HIGH RISK" />}
      {(approval === 'ISSUANCE_SINGLE' || approval === 'ISSUANCE_THRESHOLD') && (
        <Chip size="small" color="warning" variant="outlined" label="issuance approval" />
      )}
      {family === 'SERVER_CONTROL_OPERATION' && (
        <Chip size="small" variant="outlined" label="control" />
      )}
      {spec?.scope === 'authority' && <Chip size="small" variant="outlined" label="authority-scoped" />}
    </Stack>
  );
}
