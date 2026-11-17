/* *****************************************************************************
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
package zeroecho.pki.server;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.application.PkiSigningOperation;
import zeroecho.pki.server.http.HttpOperationCodec;
import zeroecho.pki.server.http.StrictJson;

/**
 * Checks authenticated actors, retained targets and the current administrative policy.
 */
final class AdministrativeRequestPolicy {
    private final ServerRealmContext realm;
    private final java.util.function.Supplier<PkiServerConfiguration.Authentication> authentication;

    /* default */ AdministrativeRequestPolicy(ServerRealmContext realm,
            java.util.function.Supplier<PkiServerConfiguration.Authentication> authentication) {
        this.realm=realm; this.authentication=authentication;
    }

    /* default */ static PkiOperationValue.ObjectValue freezeCreationEnvelope(PkiOperationValue.ObjectValue envelope, AdministrativeOperation operation) {
        Optional<String> algorithm=operation instanceof AdministrativeOperation.Signing signing?switch(signing.operation()) {
            case PkiSigningOperation.CreateAuthority value -> value.signatureAlgorithmId();
            case PkiSigningOperation.CreateIntermediate value -> value.signatureAlgorithmId();
            default -> Optional.empty();
        }:Optional.empty();

        Map<String,PkiOperationValue> fields=new LinkedHashMap<>(envelope.fields());
        Map<String,PkiOperationValue> arguments=new LinkedHashMap<>(((PkiOperationValue.ObjectValue)fields.get("arguments")).fields());
        if(algorithm.isPresent()){ arguments.put("signatureAlgorithmId",AdministrativeRequestState.text(algorithm.orElseThrow())); }
        arguments=new LinkedHashMap<>(LifecycleProjection.arguments(new PkiOperationValue.ObjectValue(arguments),operation).fields());
        if (operation instanceof AdministrativeOperation.Signing signing
                && signing.operation() instanceof PkiSigningOperation.IssueOcspResponderCertificate selected) {
            arguments = new LinkedHashMap<>(OcspProvisioningProjection.encode(selected.request()).fields());
        }
        fields.put("arguments",new PkiOperationValue.ObjectValue(arguments));
        return new PkiOperationValue.ObjectValue(fields);
    }

    /* default */ static Optional<String> sdkProfileCommitment(zeroecho.pki.api.hybrid.sdk.HybridSdkFrame target) {
        String policy=new String(target.field(12),java.nio.charset.StandardCharsets.UTF_8);
        if(!policy.matches("sha256:[0-9a-f]{64}")){ throw new AdministrativeRequestCoordinator.ValidationFailure("SDK_PROFILE_COMMITMENT_UNSUPPORTED"); }
        String id=new String(target.field(10),java.nio.charset.StandardCharsets.UTF_8);
        long version=java.nio.ByteBuffer.wrap(target.field(11)).getLong();
        return Optional.of(ApprovalService.digest(id+"|"+version+"|"+policy.substring(7)));
    }

    /* default */ Optional<String> profileCommitment(ServerOperationGateway.Request request) {
        if (!(request.operation() instanceof AdministrativeOperation.Signing signing)) { return Optional.empty(); }
        Optional<String> profile = switch(signing.operation()) {
            case PkiSigningOperation.CreateAuthority value -> Optional.of(value.profileId());
            case PkiSigningOperation.RenewCredential value -> credentialProfile(value.credentialId());
            case PkiSigningOperation.ReissueCredential value -> credentialProfile(value.credentialId());
            case PkiSigningOperation.RolloverCaCertificate value -> authorityProfile(value.caId());
            case PkiSigningOperation.RotateCaKey value -> authorityProfile(value.caId());
            default -> request.resource().scope().profileId();
        };
        if (profile.isEmpty()) { return Optional.empty(); }
        zeroecho.pki.api.profile.CertificateProfileRef reference=realm.session().profiles().requireActiveProfile(profile.orElseThrow()).reference();
        return Optional.of(ApprovalService.digest(reference.profileId()+"|"+reference.profileVersion()+"|"+java.util.HexFormat.of().formatHex(reference.canonicalSha256())));
    }

    private Optional<String> authorityProfile(PkiId authorityId) {
        zeroecho.pki.api.ca.CaRecord authority=realm.session().repository().authority(authorityId).orElseThrow();
        zeroecho.pki.api.ca.IssuerGeneration generation=realm.session().repository().issuer(authority.currentIssuanceIssuerId()).orElseThrow();
        return credentialProfile(generation.credentialId());
    }

    private Optional<String> credentialProfile(PkiId credentialId) {
        zeroecho.pki.api.credential.Credential credential=realm.session().repository().credential(credentialId).orElseThrow();
        return switch(credential.profileBinding()) {
            case zeroecho.pki.api.credential.CaProfileBinding binding -> Optional.of(binding.reference().profileId());
            case zeroecho.pki.api.credential.EndEntityProfileBinding binding -> Optional.of(binding.reference().profileId());
        };
    }

    /* default */ void requireSameAdmission(AdministrativeRequest value,ServerOperationGateway.Admission admission) {
        if(!value.profileCommitment().equals(profileCommitment(admission.request()))) { throw new SecurityException("PROFILE_CHANGED"); }
        if(!value.operationCommitment().equals(admission.commitment()) || !value.scope().equals(admission.request().resource().scope())
                || !value.policyCommitment().equals(admission.policy().map(ApprovalService.Policy::commitment))) { throw new SecurityException("Target or policy changed"); }
    }

    /* default */ void validateBeforeApproval(ServerOperationGateway.Admission admission) {
        if(admission.request().operation() instanceof AdministrativeOperation.Signing signing) {
            validateSigningBeforeApproval(admission,signing.operation());
        } else if(admission.request().operation() instanceof AdministrativeOperation.Control
                && admission.policy().isPresent()) {
            realm.gateway().validateAdministrativeControl(admission);
        } else if(admission.request().operation() instanceof AdministrativeOperation.Pki pki && admission.policy().isPresent()) {
            realm.session().operations().validate(pki.operation(),CancellationSignal.NONE);
        } else if(admission.policy().isPresent()) { throw new AdministrativeRequestCoordinator.ValidationFailure("PURE_VALIDATION_UNAVAILABLE"); }
    }

    /* default */ ServerOperationGateway.Request request(AdministrativeRequest value) {
        HttpOperationCodec.Decoded decoded=HttpOperationCodec.decode(value.operation(),StrictJson.encode(value.envelope()),262_144,realm.configuration().realmId(),realm.gateway()::descriptor);
        return new ServerOperationGateway.Request(realm.configuration().realmId(),value.actor().principalId(),value.actor().mode(),value.actor().transportPrincipalId(),value.actor().evidence(),
                decoded.operation(),decoded.resource(),Permission.Relationship.ANY,decoded.context(),value.approvalId(),value.requestId());
    }

    /* default */ void validateActor(AdministrativeRequest value) { validateActor(value.actor()); }

    /* default */ void validateActor(AdministrativeRequest.Actor actor) {
        if(!realm.principal(actor.principalId()).enabled()) { throw new SecurityException("Requester disabled"); }
        PkiServerConfiguration.Authentication active=authentication.get(); if(active==null) { return; }
        if(active.mode()!=actor.mode()) { throw new SecurityException("Authentication policy changed"); }
        if(active.mode()==AdministrativeAuthenticationMode.TRUSTED_REVERSE_PROXY) {
            String proxy=actor.transportPrincipalId().orElseThrow(()->new SecurityException("Proxy unavailable"));
            if(!active.trustedProxyPrincipalIds().contains(proxy)) { throw new SecurityException("Proxy unavailable"); }realm.gateway().validateForwardingPrincipal(proxy);
        }
        CertificateIdentityEvidence evidence=actor.evidence().orElseThrow(()->new SecurityException("Credential evidence unavailable"));
        List<PkiServerConfiguration.ClientCertificateMapping> mappings=active.mode()==AdministrativeAuthenticationMode.TRUSTED_REVERSE_PROXY?active.forwardedClientMappings():active.directClientMappings();
        if(mappings.stream().noneMatch(m->m.principalId().equals(actor.principalId()) && (m.certificateSha256().filter(evidence.certificateSha256()::equals).isPresent()
                || m.subjectPublicKeyInfoSha256().filter(evidence.legacySpkiSha256()::contains).isPresent() || m.issuerSerialSha256().filter(evidence.issuerSerialSha256()::equals).isPresent()))) { throw new SecurityException("Credential mapping removed"); }
    }

    // Keep the original fail-closed or uncertain-outcome boundary for every runtime provider failure.
    /* default */
    @SuppressWarnings({"PMD.AvoidCatchingGenericException"})
    boolean canRead(AdministrativeRequest value,String viewer) {
        try {
            if(!realm.principal(viewer).enabled()) { return false; }
            return viewer.equals(value.actor().principalId()) || realm.gateway().authorizeControl(viewer,Permission.Action.REQUEST_READ_ANY,new Permission.Resource(Permission.ResourceType.APPROVAL,value.scope(),Optional.empty(),Optional.of(value.actor().principalId())),Permission.Context.empty(),value.requestId()).allowed();
        } catch(RuntimeException unavailable) { return false; }
    }

    // Keep the original fail-closed or uncertain-outcome boundary for every runtime provider failure.
    /* default */
    @SuppressWarnings({"PMD.AvoidCatchingGenericException"})
    boolean canReviewTarget(AdministrativeRequest value,String viewer) {
        try {
            ServerOperationGateway.Request original=request(value);
            ServerOperationGateway.Request inspect=new ServerOperationGateway.Request(original.realmId(),viewer,original.authenticationMode(),original.transportPrincipalId(),Optional.empty(),original.operation(),original.resource(),original.relationship(),original.context(),original.approvalId(),original.correlationId());
            realm.gateway().assessRetainedAdministrativeRequest(inspect);return true;
        } catch(RuntimeException denied) { return false; }
    }


    private void validateSigningBeforeApproval(ServerOperationGateway.Admission admission, PkiSigningOperation op) {
        if (op instanceof PkiSigningOperation.GenerateStatus) {
            if (admission.policy().isPresent()) {
                throw new AdministrativeRequestCoordinator.ValidationFailure("PURE_VALIDATION_UNAVAILABLE");
            }
        } else {
            AccessContext access=new AccessContext(new Principal("ADMIN_PRINCIPAL",admission.request().principalId()),
                    new Purpose(op.name()),Optional.empty(),Optional.empty());
            realm.session().signingCommands().orElseThrow().validate(op,access,
                    realm.gateway().administrativeSigningEvidence(admission),CancellationSignal.NONE);
        }
    }
}
