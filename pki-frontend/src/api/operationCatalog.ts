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

import {
  ACME_CHALLENGE_TYPE,
  APPROVAL_STATE,
  CA_STATE,
  DISCLOSURE_POLICY,
  OCSP_CERT_ID_HASH,
  OCSP_NONCE_POLICY,
  OCSP_REQUEST_AUTHENTICATION_MODE,
  OCSP_RESPONDER_ID_FORM,
  OCSP_SIGNING_MODE,
  PERMISSION_ACTION,
  PERMISSION_CONDITION,
  PERMISSION_DATA_VIEW,
  PERMISSION_EFFECT,
  PERMISSION_RELATIONSHIP,
  PERMISSION_RESOURCE_TYPE,
  PRINCIPAL_TYPE,
  PUBLICATION_SOURCE_TYPE,
  PUBLICATION_TARGET_TYPE,
  REPOSITORY_ALIAS_TYPE,
  REVOCATION_REASON,
  STATUS_OBJECT_TYPE,
} from '@/api/enums';
import { F, type OperationSpec } from '@/api/operationSchema';

/**
 * The full ZeroEcho operation catalog (101 operations: 47 PKI + 54 control),
 * mirroring the server decoder `HttpOperationCodec`. `scope`/`authorityFrom`
 * encode the request-envelope rules (realm-wide operations must NOT carry an
 * authorityId; authority-scoped operations must; embedded ones derive it from an
 * argument). See operationSchema.ts for the parameter-schema rationale.
 */
export const OPERATIONS: readonly OperationSpec[] = [
  // ---- Certificate authorities (PKI) ----------------------------------------
  {
    id: 'ca.list', title: 'List authorities', summary: 'List certificate authorities in the realm.',
    family: 'PKI_OPERATION', nav: 'authorities', scope: 'realm', read: true, approval: 'NONE',
    fields: [F.int('limit', { help: 'Maximum number of authorities to return.' })],
  },
  {
    id: 'ca.inspect', title: 'Inspect authority', summary: 'Show one authority in detail.',
    family: 'PKI_OPERATION', nav: 'authorities', scope: 'authority', authorityFrom: 'caId', read: true,
    approval: 'NONE', fields: [F.id('caId', { ref: 'authority' })],
  },
  {
    id: 'ca.create', title: 'Create root authority', summary: 'Create a new root certificate authority.',
    family: 'PKI_OPERATION', nav: 'authorities', scope: 'realm', read: false, approval: 'HIGH_RISK',
    fields: [F.text('formatId'), F.text('subjectRef'), F.text('profileId'), F.text('keyRef')],
  },
  {
    id: 'ca.transition', title: 'Transition authority state', summary: 'Change the lifecycle state of an authority.',
    family: 'PKI_OPERATION', nav: 'authorities', scope: 'authority', authorityFrom: 'caId', read: false,
    approval: 'HIGH_RISK', fields: [F.id('caId', { ref: 'authority' }), F.enum('state', CA_STATE), F.text('reason')],
  },
  {
    id: 'ca.intermediate.create', title: 'Create intermediate CA', summary: 'Create a subordinate certificate authority.',
    family: 'PKI_OPERATION', nav: 'authorities', scope: 'authority', authorityFrom: 'issuerCaId', read: false,
    approval: 'HIGH_RISK',
    fields: [F.text('formatId'), F.id('issuerCaId', { ref: 'authority' }), F.text('subjectRef'), F.text('profileId'), F.textOpt('keyRef')],
  },
  {
    id: 'ca.intermediate.issue', title: 'Issue intermediate certificate', summary: 'Issue a CA certificate for a subordinate authority.',
    family: 'PKI_OPERATION', nav: 'authorities', scope: 'authority', authorityFrom: 'issuerCaId', read: false,
    approval: 'HIGH_RISK',
    fields: [F.text('formatId'), F.id('issuerCaId', { ref: 'authority' }), F.id('subjectCaId', { ref: 'authority' }), F.text('profileId'),
      F.instantOpt('notBefore', { help: 'Optional; supply with notAfter.' }),
      F.instantOpt('notAfter', { help: 'Optional; supply with notBefore.' })],
  },
  {
    id: 'ca.rollover', title: 'Roll over CA certificate', summary: 'Roll the CA certificate to a new generation.',
    family: 'PKI_OPERATION', nav: 'authorities', scope: 'authority', authorityFrom: 'caId', read: false,
    approval: 'HIGH_RISK', fields: [F.id('caId', { ref: 'authority' }), F.idOpt('issuerCaId', { ref: 'authority' })],
  },
  {
    id: 'ca.rotate', title: 'Rotate CA key', summary: 'Rotate the signing key of an authority.',
    family: 'PKI_OPERATION', nav: 'authorities', scope: 'authority', authorityFrom: 'caId', read: false,
    approval: 'HIGH_RISK', fields: [F.id('caId', { ref: 'authority' }), F.textOpt('newKeyRef'), F.idOpt('issuerCaId', { ref: 'authority' })],
  },

  // ---- Issuer generations & chain paths (PKI) -------------------------------
  {
    id: 'issuer.generation.inspect', title: 'Inspect issuer generation', summary: 'Show one issuer generation.',
    family: 'PKI_OPERATION', nav: 'issuers', scope: 'realm', read: true, approval: 'NONE', fields: [F.id('issuerId')],
  },
  {
    id: 'issuer.path.inspect', title: 'Inspect chain path', summary: 'Show one issuer chain path.',
    family: 'PKI_OPERATION', nav: 'issuers', scope: 'realm', read: true, approval: 'NONE', fields: [F.id('pathId')],
  },
  {
    id: 'issuer.path.list', title: 'List chain paths', summary: 'List chain paths for an issuer generation.',
    family: 'PKI_OPERATION', nav: 'issuers', scope: 'realm', read: true, approval: 'NONE', fields: [F.id('issuerId')],
  },
  {
    id: 'issuer.path.select', title: 'Select issuance path', summary: 'Select the active issuance path for an authority.',
    family: 'PKI_OPERATION', nav: 'issuers', scope: 'authority', authorityFrom: 'caId', read: false,
    approval: 'HIGH_RISK', fields: [F.id('caId', { ref: 'authority' }), F.id('issuerId'), F.id('pathId'), F.text('reason')],
  },
  {
    id: 'issuer.path.register', title: 'Register chain path', summary: 'Register a new issuer chain path.',
    family: 'PKI_OPERATION', nav: 'issuers', scope: 'authority', authorityFrom: 'caId', read: false,
    approval: 'NONE', fields: [F.id('caId', { ref: 'authority' }), F.id('issuerId'), F.id('parentPathId')],
  },

  // ---- Certificate profiles (PKI) -------------------------------------------
  {
    id: 'profile.list', title: 'List profile versions', summary: 'List versions of a certificate profile.',
    family: 'PKI_OPERATION', nav: 'profiles', scope: 'authority', read: true, approval: 'NONE',
    fields: [F.text('profileId')],
  },
  {
    id: 'profile.inspect', title: 'Inspect profile', summary: 'Show one certificate profile version.',
    family: 'PKI_OPERATION', nav: 'profiles', scope: 'authority', read: true, approval: 'NONE',
    fields: [F.text('profileId'), F.long('profileVersion')],
  },
  {
    id: 'profile.activate', title: 'Activate profile', summary: 'Activate a certificate profile version.',
    family: 'PKI_OPERATION', nav: 'profiles', scope: 'authority', read: false, approval: 'HIGH_RISK',
    fields: [F.text('profileId'), F.long('profileVersion')],
  },
  {
    id: 'profile.register', title: 'Register profile', summary: 'Register a certificate profile document (DER/JSON, base64).',
    family: 'PKI_OPERATION', nav: 'profiles', scope: 'realm', read: false, approval: 'NONE',
    fields: [F.base64('document', { help: 'Base64-encoded profile document.' })],
  },
  {
    id: 'profile.validate', title: 'Validate profile', summary: 'Validate a certificate profile document without registering it.',
    family: 'PKI_OPERATION', nav: 'profiles', scope: 'realm', read: true, approval: 'NONE',
    fields: [F.base64('document', { help: 'Base64-encoded profile document.' })],
  },

  // ---- Requests / CSRs (PKI) ------------------------------------------------
  {
    id: 'request.inspect', title: 'Inspect request', summary: 'Show one certification request.',
    family: 'PKI_OPERATION', nav: 'requests', scope: 'realm', read: true, approval: 'NONE', fields: [F.id('requestId')],
  },
  {
    id: 'request.import', title: 'Import request (CSR)', summary: 'Import a DER certification request (base64).',
    family: 'PKI_OPERATION', nav: 'requests', scope: 'realm', read: false, approval: 'NONE',
    fields: [F.text('formatId'), F.base64('encoded', { help: 'Base64-encoded DER CSR.' })],
  },
  {
    id: 'request.verify', title: 'Verify request', summary: 'Verify a certification request (proof of possession).',
    family: 'PKI_OPERATION', nav: 'requests', scope: 'realm', read: true, approval: 'NONE', fields: [F.id('requestId')],
  },

  // ---- Issuance (PKI) -------------------------------------------------------
  {
    id: 'credential.inspect', title: 'Inspect credential', summary: 'Show one issued credential.',
    family: 'PKI_OPERATION', nav: 'issuance', scope: 'authority', read: true, approval: 'NONE',
    fields: [F.id('credentialId')],
  },
  {
    id: 'credential.issue', title: 'Issue credential', summary: 'Issue a credential from a request and profile.',
    family: 'PKI_OPERATION', nav: 'issuance', scope: 'authority', authorityFrom: 'issuerCaId', read: false,
    approval: 'ISSUANCE_SINGLE', fields: [F.id('issuerCaId', { ref: 'authority' }), F.id('requestId'), F.text('profileId')],
  },

  // ---- Lifecycle (PKI) ------------------------------------------------------
  {
    id: 'credential.renew', title: 'Renew credential', summary: 'Renew an existing credential.',
    family: 'PKI_OPERATION', nav: 'lifecycle', scope: 'authority', read: false, approval: 'NONE',
    fields: [F.id('credentialId')],
  },
  {
    id: 'credential.replace', title: 'Replace credential', summary: 'Replace a credential with a new request and profile.',
    family: 'PKI_OPERATION', nav: 'lifecycle', scope: 'authority', read: false, approval: 'NONE',
    fields: [F.id('existingCredentialId'), F.id('requestId'), F.text('profileId')],
  },
  {
    id: 'credential.reissue', title: 'Reissue credential', summary: 'Reissue a credential (same key).',
    family: 'PKI_OPERATION', nav: 'lifecycle', scope: 'authority', read: false, approval: 'HIGH_RISK',
    fields: [F.id('credentialId')],
  },

  // ---- Credential confirmation (PKI) ----------------------------------------
  {
    id: 'credential.confirmation.pending.list', title: 'List pending confirmations',
    summary: 'List pending credential confirmations for an authority.',
    family: 'PKI_OPERATION', nav: 'confirmations', scope: 'authority', read: true, approval: 'NONE',
    fields: [F.textOpt('profileId'), F.instant('cutoffInclusive'), F.textOpt('afterExclusive'), F.int('limit')],
  },
  {
    id: 'credential.confirmation.challenge.issue', title: 'Issue confirmation challenge',
    summary: 'Issue a proof-of-possession challenge for a credential.',
    family: 'PKI_OPERATION', nav: 'confirmations', scope: 'authority', read: false, approval: 'NONE',
    fields: [F.id('credentialId')],
  },
  {
    id: 'credential.confirmation.proof.complete', title: 'Complete confirmation proof',
    summary: 'Complete a proof-of-possession challenge.',
    family: 'PKI_OPERATION', nav: 'confirmations', scope: 'authority', read: false, approval: 'NONE',
    fields: [F.id('credentialId'), F.long('expectedLifecycleRevision'),
      F.text('expectedLifecycleRecordCommitment'), F.text('expectedChallengeRecordCommitment'),
      F.text('response', { help: 'Canonical unpadded Base64url proof response.' })],
  },
  {
    id: 'credential.confirmation.pending.revoke', title: 'Revoke pending confirmation',
    summary: 'Revoke a pending credential confirmation.',
    family: 'PKI_OPERATION', nav: 'confirmations', scope: 'authority', read: false, approval: 'NONE',
    fields: [F.id('credentialId'), F.textOpt('justification')],
  },

  // ---- Revocation (PKI) -----------------------------------------------------
  {
    id: 'credential.revoke', title: 'Revoke credential', summary: 'Revoke an issued credential.',
    family: 'PKI_OPERATION', nav: 'revocation', scope: 'authority', read: false, approval: 'NONE',
    fields: [F.id('credentialId'), F.enum('reason', REVOCATION_REASON), F.textOpt('justification')],
  },
  {
    id: 'revocation.inspect', title: 'Inspect revocation', summary: 'Show the revocation state of a credential.',
    family: 'PKI_OPERATION', nav: 'revocation', scope: 'authority', read: true, approval: 'NONE',
    fields: [F.id('credentialId')],
  },
  {
    id: 'revocation.history', title: 'Revocation history', summary: 'Read the revocation history of a credential.',
    family: 'PKI_OPERATION', nav: 'revocation', scope: 'authority', read: true, approval: 'NONE',
    fields: [F.id('credentialId'), F.int('limit')],
  },
  {
    id: 'revocation.snapshot', title: 'Snapshot revocations', summary: 'Take a realm-wide revocation snapshot.',
    family: 'PKI_OPERATION', nav: 'revocation', scope: 'realm', read: true, approval: 'NONE', fields: [F.int('limit')],
  },

  // ---- Status objects & CRLs (PKI) ------------------------------------------
  {
    id: 'status.inspect', title: 'Inspect status object', summary: 'Show one status object (CRL/delta).',
    family: 'PKI_OPERATION', nav: 'status', scope: 'realm', read: true, approval: 'NONE',
    fields: [F.id('statusObjectId')],
  },
  {
    id: 'inventory.status', title: 'List status objects', summary: 'List status objects for an issuer.',
    family: 'PKI_OPERATION', nav: 'status', scope: 'authority', authorityFrom: 'issuerCaId', read: true,
    approval: 'NONE', fields: [F.id('issuerCaId', { ref: 'authority' }), F.int('limit')],
  },
  {
    id: 'status.generate', title: 'Generate status object', summary: 'Generate a CRL or delta CRL.',
    family: 'PKI_OPERATION', nav: 'status', scope: 'authority', authorityFrom: 'issuerCaId', read: false,
    approval: 'NONE', fields: [F.id('issuerCaId', { ref: 'authority' }), F.enum('type', STATUS_OBJECT_TYPE), F.text('formatId')],
  },

  // ---- Publication (PKI) ----------------------------------------------------
  {
    id: 'publication.list', title: 'List publications', summary: 'List publication records in the realm.',
    family: 'PKI_OPERATION', nav: 'publication', scope: 'realm', read: true, approval: 'NONE', fields: [F.int('limit')],
  },
  {
    id: 'publication.inspect', title: 'Inspect publication', summary: 'Show one publication record.',
    family: 'PKI_OPERATION', nav: 'publication', scope: 'authority', read: true, approval: 'NONE',
    fields: [F.id('publicationId', { ref: 'publication' })],
  },
  {
    id: 'publication.register', title: 'Register publication', summary: 'Register a publication of a credential or status object.',
    family: 'PKI_OPERATION', nav: 'publication', scope: 'authority', read: false, approval: 'NONE',
    fields: [F.id('publicationId'), F.enum('sourceType', PUBLICATION_SOURCE_TYPE), F.id('sourceId'),
      F.enum('targetType', PUBLICATION_TARGET_TYPE), F.text('targetId')],
  },
  {
    id: 'publication.process', title: 'Process publication', summary: 'Process a pending publication.',
    family: 'PKI_OPERATION', nav: 'publication', scope: 'authority', read: false, approval: 'NONE',
    fields: [F.id('publicationId', { ref: 'publication' })],
  },
  {
    id: 'publication.retry', title: 'Retry publication', summary: 'Retry a failed publication.',
    family: 'PKI_OPERATION', nav: 'publication', scope: 'authority', read: false, approval: 'NONE',
    fields: [F.id('publicationId', { ref: 'publication' })],
  },
  {
    id: 'publication.reconcile', title: 'Reconcile publication', summary: 'Reconcile a publication record.',
    family: 'PKI_OPERATION', nav: 'publication', scope: 'authority', read: false, approval: 'NONE',
    fields: [F.id('publicationId', { ref: 'publication' })],
  },

  // ---- Configuration & algorithm bindings (PKI) -----------------------------
  {
    id: 'configuration.validate', title: 'Validate configuration', summary: 'Validate the active PKI configuration.',
    family: 'PKI_OPERATION', nav: 'configuration', scope: 'realm', read: true, approval: 'NONE', fields: [],
  },
  {
    id: 'algorithm.binding.list', title: 'List algorithm bindings', summary: 'List algorithm bindings.',
    family: 'PKI_OPERATION', nav: 'configuration', scope: 'realm', read: true, approval: 'NONE',
    fields: [F.textOpt('origin'), F.textOpt('role'), F.int('limit')],
  },
  {
    id: 'algorithm.binding.inspect', title: 'Inspect algorithm binding', summary: 'Show one algorithm binding.',
    family: 'PKI_OPERATION', nav: 'configuration', scope: 'realm', read: true, approval: 'NONE',
    fields: [F.text('bindingId', { ref: 'algorithmBinding' })],
  },
  {
    id: 'algorithm.binding.validate', title: 'Validate algorithm bindings', summary: 'Validate algorithm bindings.',
    family: 'PKI_OPERATION', nav: 'configuration', scope: 'realm', read: true, approval: 'NONE',
    fields: [F.textOpt('bindingId', { ref: 'algorithmBinding' }), F.textOpt('expectedCommitment')],
  },

  // ---- Principals (control) -------------------------------------------------
  {
    id: 'security.principal.register', title: 'Register principal', summary: 'Register a security principal.',
    family: 'SERVER_CONTROL_OPERATION', nav: 'principals', scope: 'realm', read: false, approval: 'HIGH_RISK',
    fields: [F.text('principalId'), F.enum('type', PRINCIPAL_TYPE), F.text('displayName'), F.bool('enabled')],
  },
  {
    id: 'security.principal.inspect', title: 'Inspect principal', summary: 'Show one security principal.',
    family: 'SERVER_CONTROL_OPERATION', nav: 'principals', scope: 'realm', read: true, approval: 'NONE',
    fields: [F.text('principalId', { ref: 'principal' })],
  },
  {
    id: 'security.principal.list', title: 'List principals', summary: 'List security principals.',
    family: 'SERVER_CONTROL_OPERATION', nav: 'principals', scope: 'realm', read: true, approval: 'NONE',
    fields: [F.int('offset'), F.int('limit')],
  },
  {
    id: 'security.principal.enable', title: 'Enable principal', summary: 'Enable a security principal.',
    family: 'SERVER_CONTROL_OPERATION', nav: 'principals', scope: 'realm', read: false, approval: 'NONE',
    fields: [F.text('principalId', { ref: 'principal' })],
  },
  {
    id: 'security.principal.disable', title: 'Disable principal', summary: 'Disable a security principal.',
    family: 'SERVER_CONTROL_OPERATION', nav: 'principals', scope: 'realm', read: false, approval: 'HIGH_RISK',
    fields: [F.text('principalId', { ref: 'principal' })],
  },

  // ---- Roles & grants (control) ---------------------------------------------
  {
    id: 'security.role-template.list', title: 'List role templates', summary: 'List available role templates.',
    family: 'SERVER_CONTROL_OPERATION', nav: 'access', scope: 'realm', read: true, approval: 'NONE', fields: [],
  },
  {
    id: 'security.role-template.inspect', title: 'Inspect role template', summary: 'Show one role template version.',
    family: 'SERVER_CONTROL_OPERATION', nav: 'access', scope: 'realm', read: true, approval: 'NONE',
    fields: [F.text('templateId', { ref: 'roleTemplate' }), F.int('version')],
  },
  {
    id: 'security.role-assignment.create', title: 'Create role assignment', summary: 'Assign a role template to a principal.',
    family: 'SERVER_CONTROL_OPERATION', nav: 'access', scope: 'realm', read: false, approval: 'HIGH_RISK',
    fields: [F.text('assignmentId'), F.text('principalId', { ref: 'principal' }), F.text('templateId', { ref: 'roleTemplate' }), F.int('templateVersion'),
      F.textOpt('profileId'), F.instantOpt('expiresAt')],
  },
  {
    id: 'security.role-assignment.inspect', title: 'Inspect role assignment', summary: 'Show one role assignment.',
    family: 'SERVER_CONTROL_OPERATION', nav: 'access', scope: 'realm', read: true, approval: 'NONE',
    fields: [F.text('assignmentId', { ref: 'roleAssignment' })],
  },
  {
    id: 'security.role-assignment.list', title: 'List role assignments', summary: 'List role assignments.',
    family: 'SERVER_CONTROL_OPERATION', nav: 'access', scope: 'realm', read: true, approval: 'NONE',
    fields: [F.int('offset'), F.int('limit')],
  },
  {
    id: 'security.role-assignment.revoke', title: 'Revoke role assignment', summary: 'Revoke a role assignment.',
    family: 'SERVER_CONTROL_OPERATION', nav: 'access', scope: 'realm', read: false, approval: 'NONE',
    fields: [F.text('assignmentId', { ref: 'roleAssignment' })],
  },
  {
    id: 'security.grant.create', title: 'Create grant', summary: 'Create an explicit authorization grant.',
    family: 'SERVER_CONTROL_OPERATION', nav: 'access', scope: 'realm', read: false, approval: 'HIGH_RISK',
    fields: [F.text('grantId'), F.text('principalId', { ref: 'principal' }), F.enum('effect', PERMISSION_EFFECT),
      F.enum('action', PERMISSION_ACTION), F.enum('resourceType', PERMISSION_RESOURCE_TYPE),
      F.idOpt('issuerId'), F.textOpt('profileId'), F.textOpt('responderId'),
      F.enum('relationship', PERMISSION_RELATIONSHIP), F.enum('dataView', PERMISSION_DATA_VIEW),
      F.enumSet('conditions', PERMISSION_CONDITION), F.instantOpt('expiresAt')],
  },
  {
    id: 'security.grant.inspect', title: 'Inspect grant', summary: 'Show one authorization grant.',
    family: 'SERVER_CONTROL_OPERATION', nav: 'access', scope: 'realm', read: true, approval: 'NONE',
    fields: [F.text('grantId', { ref: 'grant' })],
  },
  {
    id: 'security.grant.list', title: 'List grants', summary: 'List authorization grants.',
    family: 'SERVER_CONTROL_OPERATION', nav: 'access', scope: 'realm', read: true, approval: 'NONE',
    fields: [F.int('offset'), F.int('limit')],
  },
  {
    id: 'security.grant.revoke', title: 'Revoke grant', summary: 'Revoke an authorization grant.',
    family: 'SERVER_CONTROL_OPERATION', nav: 'access', scope: 'realm', read: false, approval: 'NONE',
    fields: [F.text('grantId', { ref: 'grant' })],
  },
  {
    id: 'security.authorization.evaluate', title: 'Evaluate authorization', summary: 'Evaluate whether a principal is authorized for an action.',
    family: 'SERVER_CONTROL_OPERATION', nav: 'access', scope: 'realm', read: true, approval: 'NONE',
    fields: [F.text('principalId', { ref: 'principal' }), F.enum('action', PERMISSION_ACTION),
      F.enum('resourceType', PERMISSION_RESOURCE_TYPE), F.enum('relationship', PERMISSION_RELATIONSHIP),
      F.enum('dataView', PERMISSION_DATA_VIEW)],
  },

  // ---- Approvals (control) --------------------------------------------------
  {
    id: 'security.approval.request', title: 'Request approval', summary: 'Create a durable approval for a HIGH_RISK target operation.',
    family: 'SERVER_CONTROL_OPERATION', nav: 'approvals', scope: 'realm', read: false, approval: 'NONE',
    fields: [F.text('approvalId'), F.text('targetOperation', { help: 'Operation id being approved.' }),
      { name: 'targetArguments', type: 'json', required: true, help: 'JSON object of the target operation arguments.' },
      F.textOpt('targetAuthorityId')],
  },
  {
    id: 'security.approval.inspect', title: 'Inspect approval', summary: 'Show one approval.',
    family: 'SERVER_CONTROL_OPERATION', nav: 'approvals', scope: 'realm', read: true, approval: 'NONE',
    fields: [F.text('approvalId', { ref: 'approval' })],
  },
  {
    id: 'security.approval.list', title: 'List approvals', summary: 'List approvals, optionally filtered.',
    family: 'SERVER_CONTROL_OPERATION', nav: 'approvals', scope: 'realm', read: true, approval: 'NONE',
    fields: [F.int('offset'), F.int('limit'), F.enumOpt('state', APPROVAL_STATE),
      F.textOpt('requesterPrincipalId'), F.textOpt('targetOperationId')],
  },
  {
    id: 'security.approval.approve', title: 'Approve', summary: 'Approve a pending approval.',
    family: 'SERVER_CONTROL_OPERATION', nav: 'approvals', scope: 'realm', read: false, approval: 'NONE',
    fields: [F.text('approvalId', { ref: 'approval' }), F.text('justification')],
  },
  {
    id: 'security.approval.reject', title: 'Reject', summary: 'Reject a pending approval.',
    family: 'SERVER_CONTROL_OPERATION', nav: 'approvals', scope: 'realm', read: false, approval: 'NONE',
    fields: [F.text('approvalId', { ref: 'approval' }), F.text('justification')],
  },
  {
    id: 'security.approval.cancel', title: 'Cancel approval', summary: 'Cancel a pending approval.',
    family: 'SERVER_CONTROL_OPERATION', nav: 'approvals', scope: 'realm', read: false, approval: 'NONE',
    fields: [F.text('approvalId', { ref: 'approval' })],
  },

  // ---- Break-glass (control) ------------------------------------------------
  {
    id: 'security.break-glass.create', title: 'Create break-glass', summary: 'Create a break-glass emergency grant.',
    family: 'SERVER_CONTROL_OPERATION', nav: 'break-glass', scope: 'realm', read: false, approval: 'HIGH_RISK',
    fields: [F.text('breakGlassId'), F.text('principalId', { ref: 'principal' }), F.text('grantId'),
      F.enum('action', PERMISSION_ACTION), F.enum('resourceType', PERMISSION_RESOURCE_TYPE),
      F.text('reason'), F.instant('expiresAt')],
  },
  {
    id: 'security.break-glass.activate', title: 'Activate break-glass', summary: 'Activate a break-glass grant.',
    family: 'SERVER_CONTROL_OPERATION', nav: 'break-glass', scope: 'realm', read: false, approval: 'HIGH_RISK',
    fields: [F.text('breakGlassId', { ref: 'breakGlass' })],
  },
  {
    id: 'security.break-glass.inspect', title: 'Inspect break-glass', summary: 'Show one break-glass grant.',
    family: 'SERVER_CONTROL_OPERATION', nav: 'break-glass', scope: 'realm', read: true, approval: 'NONE',
    fields: [F.text('breakGlassId', { ref: 'breakGlass' })],
  },
  {
    id: 'security.break-glass.list', title: 'List break-glass', summary: 'List break-glass grants.',
    family: 'SERVER_CONTROL_OPERATION', nav: 'break-glass', scope: 'realm', read: true, approval: 'NONE',
    fields: [F.int('offset'), F.int('limit')],
  },
  {
    id: 'security.break-glass.revoke', title: 'Revoke break-glass', summary: 'Revoke a break-glass grant.',
    family: 'SERVER_CONTROL_OPERATION', nav: 'break-glass', scope: 'realm', read: false, approval: 'NONE',
    fields: [F.text('breakGlassId', { ref: 'breakGlass' })],
  },

  // ---- Disclosure & capabilities (control) ----------------------------------
  {
    id: 'security.disclosure.inspect', title: 'Inspect disclosure', summary: 'Show the disclosure policy of an object.',
    family: 'SERVER_CONTROL_OPERATION', nav: 'disclosure', scope: 'realm', read: true, approval: 'NONE',
    fields: [F.id('objectId')],
  },
  {
    id: 'security.disclosure.set', title: 'Set disclosure', summary: 'Set the disclosure policy of an object.',
    family: 'SERVER_CONTROL_OPERATION', nav: 'disclosure', scope: 'realm', read: false, approval: 'HIGH_RISK',
    fields: [F.id('objectId'), F.enum('policy', DISCLOSURE_POLICY)],
  },
  {
    id: 'certificate.publication.enroll', title: 'Enroll credential publication', summary: 'Enroll a credential for publication.',
    family: 'SERVER_CONTROL_OPERATION', nav: 'disclosure', scope: 'realm', read: false, approval: 'NONE',
    fields: [F.id('credentialId'), F.textOpt('ownerPrincipalId')],
  },
  {
    id: 'security.disclosure.capability.issue', title: 'Issue disclosure capability', summary: 'Issue a time-bounded disclosure capability.',
    family: 'SERVER_CONTROL_OPERATION', nav: 'disclosure', scope: 'realm', read: false, approval: 'NONE',
    fields: [F.id('objectId'), F.instant('expiresAt')],
  },
  {
    id: 'security.disclosure.capability.revoke', title: 'Revoke disclosure capability', summary: 'Revoke a disclosure capability.',
    family: 'SERVER_CONTROL_OPERATION', nav: 'disclosure', scope: 'realm', read: false, approval: 'NONE',
    fields: [F.text('capabilityId')],
  },

  // ---- Audit (control) ------------------------------------------------------
  {
    id: 'security.audit-view.inspect-redacted', title: 'Inspect audit (redacted)', summary: 'Inspect an audit record (redacted view).',
    family: 'SERVER_CONTROL_OPERATION', nav: 'audit', scope: 'realm', read: true, approval: 'NONE',
    fields: [F.id('objectId'), F.textOpt('reasonReference')],
  },
  {
    id: 'security.audit-view.inspect-full', title: 'Inspect audit (full)', summary: 'Inspect an audit record (full metadata view).',
    family: 'SERVER_CONTROL_OPERATION', nav: 'audit', scope: 'realm', read: true, approval: 'NONE',
    fields: [F.id('objectId'), F.textOpt('reasonReference')],
  },
  {
    id: 'security.audit-view.inspect-pii', title: 'Inspect audit (PII)', summary: 'Inspect an audit record (PII view).',
    family: 'SERVER_CONTROL_OPERATION', nav: 'audit', scope: 'realm', read: true, approval: 'NONE',
    fields: [F.id('objectId'), F.textOpt('reasonReference')],
  },
  {
    id: 'security.audit.search', title: 'Search audit', summary: 'Search the audit trail.',
    family: 'SERVER_CONTROL_OPERATION', nav: 'audit', scope: 'realm', read: true, approval: 'NONE',
    fields: [F.textOpt('category'), F.textOpt('action'), F.instantOpt('after'), F.instantOpt('before'),
      F.idOpt('objectId'), F.textOpt('principalName'), F.int('limit')],
  },
  {
    id: 'security.audit.verify-integrity', title: 'Verify audit integrity', summary: 'Verify the audit chain integrity.',
    family: 'SERVER_CONTROL_OPERATION', nav: 'audit', scope: 'realm', read: true, approval: 'NONE',
    fields: [{ name: 'sequence', type: 'long', required: false, help: 'Optional chain head sequence.' },
      F.textOpt('recordHash', { help: 'Optional chain head record hash (supply with sequence).' })],
  },

  // ---- Repository aliases (control; authority-scoped) -----------------------
  {
    id: 'repository.alias.inspect', title: 'Inspect repository alias', summary: 'Show a repository alias for an authority.',
    family: 'SERVER_CONTROL_OPERATION', nav: 'repository', scope: 'authority', authorityFrom: 'authorityId',
    read: true, approval: 'NONE', fields: [F.id('authorityId', { ref: 'authority' }), F.enum('type', REPOSITORY_ALIAS_TYPE)],
  },
  {
    id: 'repository.alias.list', title: 'List repository aliases', summary: 'List repository aliases.',
    family: 'SERVER_CONTROL_OPERATION', nav: 'repository', scope: 'realm', read: true, approval: 'NONE',
    fields: [F.int('offset'), F.int('limit')],
  },
  {
    id: 'repository.alias.set', title: 'Set repository alias', summary: 'Set a repository alias target.',
    family: 'SERVER_CONTROL_OPERATION', nav: 'repository', scope: 'authority', authorityFrom: 'authorityId',
    read: false, approval: 'HIGH_RISK',
    fields: [F.id('authorityId', { ref: 'authority' }), F.enum('type', REPOSITORY_ALIAS_TYPE), F.id('targetObjectId'),
      F.idOpt('issuerId'), F.textOpt('expectedCurrentCommitment')],
  },
  {
    id: 'repository.alias.remove', title: 'Remove repository alias', summary: 'Remove a repository alias.',
    family: 'SERVER_CONTROL_OPERATION', nav: 'repository', scope: 'authority', authorityFrom: 'authorityId',
    read: false, approval: 'HIGH_RISK',
    fields: [F.id('authorityId', { ref: 'authority' }), F.enum('type', REPOSITORY_ALIAS_TYPE), F.text('expectedCurrentCommitment')],
  },

  // ---- ACME administration (control) ----------------------------------------
  {
    id: 'acme.directory.register', title: 'Register ACME directory', summary: 'Register an ACME directory.',
    family: 'SERVER_CONTROL_OPERATION', nav: 'acme', scope: 'authority', authorityFrom: 'authorityId',
    read: false, approval: 'HIGH_RISK',
    fields: [F.text('alias'), F.id('authorityId', { ref: 'authority' }), F.text('profileId'), F.stringSet('dnsNamespaces'),
      F.long('maximumValidityMillis'), F.stringSet('publicKeyAlgorithms'), F.stringSet('x509BindingPolicies'),
      F.enumSet('challengeTypes', ACME_CHALLENGE_TYPE), F.stringSet('challengeProviderIds'),
      F.textOpt('eabProviderId'), F.bool('eabRequired')],
  },
  {
    id: 'acme.directory.inspect', title: 'Inspect ACME directory', summary: 'Show one ACME directory.',
    family: 'SERVER_CONTROL_OPERATION', nav: 'acme', scope: 'realm', read: true, approval: 'NONE',
    fields: [F.text('directoryId', { ref: 'acmeDirectory' })],
  },
  {
    id: 'acme.directory.list', title: 'List ACME directories', summary: 'List ACME directories.',
    family: 'SERVER_CONTROL_OPERATION', nav: 'acme', scope: 'realm', read: true, approval: 'NONE',
    fields: [F.int('offset'), F.int('limit')],
  },
  {
    id: 'acme.directory.activate', title: 'Activate ACME directory', summary: 'Activate an ACME directory.',
    family: 'SERVER_CONTROL_OPERATION', nav: 'acme', scope: 'realm', read: false, approval: 'HIGH_RISK',
    fields: [F.text('directoryId', { ref: 'acmeDirectory' })],
  },
  {
    id: 'acme.directory.deactivate', title: 'Deactivate ACME directory', summary: 'Deactivate an ACME directory.',
    family: 'SERVER_CONTROL_OPERATION', nav: 'acme', scope: 'realm', read: false, approval: 'NONE',
    fields: [F.text('directoryId', { ref: 'acmeDirectory' })],
  },
  {
    id: 'acme.account.inspect', title: 'Inspect ACME account', summary: 'Show one ACME account.',
    family: 'SERVER_CONTROL_OPERATION', nav: 'acme', scope: 'realm', read: true, approval: 'NONE',
    fields: [F.text('accountId', { ref: 'acmeAccount' })],
  },
  {
    id: 'acme.account.list', title: 'List ACME accounts', summary: 'List ACME accounts.',
    family: 'SERVER_CONTROL_OPERATION', nav: 'acme', scope: 'realm', read: true, approval: 'NONE',
    fields: [F.int('offset'), F.int('limit')],
  },
  {
    id: 'acme.account.deactivate', title: 'Deactivate ACME account', summary: 'Deactivate an ACME account.',
    family: 'SERVER_CONTROL_OPERATION', nav: 'acme', scope: 'realm', read: false, approval: 'NONE',
    fields: [F.text('accountId', { ref: 'acmeAccount' })],
  },

  // ---- OCSP administration (control) ----------------------------------------
  {
    id: 'ocsp.responder.register', title: 'Register OCSP responder', summary: 'Register an OCSP responder.',
    family: 'SERVER_CONTROL_OPERATION', nav: 'ocsp', scope: 'realm', read: false, approval: 'HIGH_RISK',
    fields: [F.text('responderId'), F.text('alias'), F.id('authorityId', { ref: 'authority' }), F.id('issuerId'),
      F.enum('signingMode', OCSP_SIGNING_MODE), F.id('responderCredentialId'), F.text('signingKeyRef'),
      F.id('chainPathId'), F.text('signatureAlgorithm'), F.textOpt('signatureBindingId'),
      F.text('signatureBindingCommitment'), F.enum('responderIdForm', OCSP_RESPONDER_ID_FORM),
      F.long('responseValidityMillis'), F.enum('noncePolicy', OCSP_NONCE_POLICY), F.int('maximumNonceBytes'),
      F.enumSet('acceptedHashes', OCSP_CERT_ID_HASH), F.int('maximumRequestBytes'), F.int('maximumEntries'),
      F.long('cacheLifetimeMillis'), F.enum('requestAuthenticationMode', OCSP_REQUEST_AUTHENTICATION_MODE),
      { name: 'requesterTrustPolicy', type: 'json', required: false, help: 'Optional JSON requester trust policy.' }],
  },
  {
    id: 'ocsp.responder.inspect', title: 'Inspect OCSP responder', summary: 'Show one OCSP responder.',
    family: 'SERVER_CONTROL_OPERATION', nav: 'ocsp', scope: 'realm', read: true, approval: 'NONE',
    fields: [F.text('responderId', { ref: 'ocspResponder' })],
  },
  {
    id: 'ocsp.responder.list', title: 'List OCSP responders', summary: 'List OCSP responders.',
    family: 'SERVER_CONTROL_OPERATION', nav: 'ocsp', scope: 'realm', read: true, approval: 'NONE',
    fields: [F.int('offset'), F.int('limit')],
  },
  {
    id: 'ocsp.responder.activate', title: 'Activate OCSP responder', summary: 'Activate an OCSP responder.',
    family: 'SERVER_CONTROL_OPERATION', nav: 'ocsp', scope: 'realm', read: false, approval: 'HIGH_RISK',
    fields: [F.text('responderId', { ref: 'ocspResponder' })],
  },
  {
    id: 'ocsp.responder.deactivate', title: 'Deactivate OCSP responder', summary: 'Deactivate an OCSP responder.',
    family: 'SERVER_CONTROL_OPERATION', nav: 'ocsp', scope: 'realm', read: false, approval: 'NONE',
    fields: [F.text('responderId', { ref: 'ocspResponder' })],
  },
];

const BY_ID = new Map<string, OperationSpec>(OPERATIONS.map((o) => [o.id, o]));

export function operationSpec(id: string): OperationSpec | undefined {
  return BY_ID.get(id);
}

export function operationsForNav(navId: string): readonly OperationSpec[] {
  return OPERATIONS.filter((o) => o.nav === navId);
}
