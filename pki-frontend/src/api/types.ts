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

/** Wire types for the pki-server admin API. */

/** One operation descriptor as returned by `GET /admin/v1/operations`. */
export interface OperationDescriptor {
  readonly operation: string;
  readonly family: 'PKI_OPERATION' | 'SERVER_CONTROL_OPERATION';
  readonly mutating: boolean;
  readonly resourceType: string;
  readonly approval: string;
  readonly dataView: string;
}

export interface OperationCatalogResponse {
  readonly count: number;
  readonly operations: readonly OperationDescriptor[];
}

export type OperationStatus = 'SUCCEEDED' | 'PENDING' | 'FAILED' | 'APPROVAL_REQUIRED';

export interface OperationFailure {
  readonly classification: string;
  readonly code: string;
  readonly messageKey: string;
  readonly recoveryRequired: boolean;
  readonly reconciliationRequired: boolean;
}

/** The response envelope for every admin operation execution. */
export interface OperationEnvelope {
  readonly version: number;
  readonly requestId: string;
  readonly operation: string;
  readonly status: OperationStatus;
  readonly result: Record<string, unknown> | null;
  readonly failure: OperationFailure | null;
}

/** The request envelope posted to `POST /admin/v1/operations/{id}`. */
export interface OperationRequest {
  readonly version: 1;
  readonly authorityId?: string;
  readonly approvalId?: string;
  /** ISO-8601 duration, e.g. "PT30S". */
  readonly deadline?: string;
  readonly arguments: Record<string, unknown>;
}
