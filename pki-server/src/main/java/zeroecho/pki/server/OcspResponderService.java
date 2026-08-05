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
package zeroecho.pki.server;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;

import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.algorithm.X509AlgorithmBindingRegistry;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.application.OcspResponseService;
import zeroecho.pki.application.PkiRepository;

/** Durable exact responder-binding authority over the server control store. */
@SuppressWarnings({ "PMD.CyclomaticComplexity", "PMD.ControlStatementBraces",
        "PMD.FieldDeclarationsShouldBeAtStartOfClass", "PMD.AvoidLiteralsInIfCondition",
        "PMD.LinguisticNaming", "PMD.UseObjectForClearerAPI", "PMD.ExcessiveParameterList",
        "PMD.PreserveStackTrace", "PMD.AvoidCatchingGenericException", "PMD.UseEnumCollections",
        "PMD.ExceptionAsFlowControl" })
public final class OcspResponderService {
    /** Exact signing authority. */
    public enum SigningMode {
        ISSUER_SIGNED(1), DELEGATED_RESPONDER(2);
        private final int code;
        SigningMode(int code) { this.code = code; }
        /** Stable persistence code. */ public int code() { return code; }
        /** Resolves an exact stable code. */
        public static SigningMode fromCode(int code) {
            return switch (code) { case 1 -> ISSUER_SIGNED; case 2 -> DELEGATED_RESPONDER;
                default -> throw new IllegalArgumentException("Unknown OCSP signing mode code"); };
        }
    }
    /** Closed nonce behavior. */
    public enum NoncePolicy {
        REJECT(1), OPTIONAL_ECHO(2), REQUIRED(3);
        private final int code;
        NoncePolicy(int code) { this.code = code; }
        /** Stable persistence code. */ public int code() { return code; }
        /** Resolves an exact stable code. */
        public static NoncePolicy fromCode(int code) {
            return switch (code) { case 1 -> REJECT; case 2 -> OPTIONAL_ECHO; case 3 -> REQUIRED;
                default -> throw new IllegalArgumentException("Unknown OCSP nonce policy code"); };
        }
    }
    /** Durable activation state. */
    public enum State {
        INACTIVE(1), ACTIVE(2);
        private final int code;
        State(int code) { this.code = code; }
        /** Stable persistence code. */ public int code() { return code; }
        /** Resolves an exact stable code. */
        public static State fromCode(int code) {
            return switch (code) { case 1 -> INACTIVE; case 2 -> ACTIVE;
                default -> throw new IllegalArgumentException("Unknown OCSP responder state code"); };
        }
    }

    /** Closed administrator input without server-authoritative timestamps, state, or record commitments. */
    public record Registration(String responderId, String alias, PkiId authorityId, PkiId issuerId,
            SigningMode signingMode, PkiId responderCredentialId, KeyRef signingKeyRef, PkiId chainPathId,
            String signatureAlgorithm, Optional<String> signatureBindingId, String signatureBindingCommitment,
            OcspResponseService.ResponderId responderIdForm, Duration responseValidity, NoncePolicy noncePolicy,
            int maximumNonceBytes, Set<OcspResponseService.CertIdHash> acceptedHashes, int maximumRequestBytes,
            int maximumEntries, Duration cacheLifetime) {
        /** Snapshots the typed finite registration input. */
        public Registration {
            Permission.requireId(responderId, "OCSP responder"); Permission.requireId(alias, "OCSP alias");
            Objects.requireNonNull(authorityId); Objects.requireNonNull(issuerId); Objects.requireNonNull(signingMode);
            Objects.requireNonNull(responderCredentialId); Objects.requireNonNull(signingKeyRef);
            Objects.requireNonNull(chainPathId); Permission.requireBounded(signatureAlgorithm, 128,
                    "OCSP signature algorithm");
            signatureBindingId = Objects.requireNonNull(signatureBindingId);
            requireDigest(signatureBindingCommitment); Objects.requireNonNull(responderIdForm);
            Objects.requireNonNull(responseValidity); Objects.requireNonNull(noncePolicy);
            acceptedHashes = Set.copyOf(Objects.requireNonNull(acceptedHashes));
            Objects.requireNonNull(cacheLifetime);
        }
    }

    /** Strict versioned responder binding. */
    public record Responder(String responderId, String alias, RealmId realmId, PkiId authorityId,
            PkiId issuerId, SigningMode signingMode, PkiId responderCredentialId, KeyRef signingKeyRef,
            PkiId chainPathId, String signatureAlgorithm, Optional<String> signatureBindingId,
            String signatureBindingCommitment, OcspResponseService.ResponderId responderIdForm,
            Duration responseValidity, NoncePolicy noncePolicy, int maximumNonceBytes,
            Set<OcspResponseService.CertIdHash> acceptedHashes, int maximumRequestBytes,
            int maximumEntries, Duration cacheLifetime, State state, Instant createdAt,
            String configurationCommitment) {
        /** Validates all finite immutable dependencies and the record commitment. */
        public Responder {
            Permission.requireId(responderId, "OCSP responder"); Permission.requireId(alias, "OCSP alias");
            Objects.requireNonNull(realmId); Objects.requireNonNull(authorityId); Objects.requireNonNull(issuerId);
            Objects.requireNonNull(signingMode); Objects.requireNonNull(responderCredentialId);
            Objects.requireNonNull(signingKeyRef); Objects.requireNonNull(chainPathId);
            Permission.requireBounded(signatureAlgorithm, 128, "OCSP signature algorithm");
            signatureBindingId = Objects.requireNonNull(signatureBindingId);
            requireDigest(signatureBindingCommitment); Objects.requireNonNull(responderIdForm);
            positive(responseValidity, Duration.ofDays(7), "response validity"); Objects.requireNonNull(noncePolicy);
            if (maximumNonceBytes < 8 || maximumNonceBytes > 4096 || maximumRequestBytes < 256
                    || maximumRequestBytes > 1_048_576 || maximumEntries < 1 || maximumEntries > 4096) {
                throw new IllegalArgumentException("OCSP responder bounds are invalid");
            }
            acceptedHashes = Set.copyOf(Objects.requireNonNull(acceptedHashes));
            if (acceptedHashes.isEmpty()) throw new IllegalArgumentException("OCSP CertID hashes are empty");
            positive(cacheLifetime, responseValidity, "cache lifetime"); Objects.requireNonNull(state);
            Objects.requireNonNull(createdAt); requireDigest(configurationCommitment);
        }
    }

    private final RealmId realmId;
    private final ServerControlStore control;
    private final PkiRepository repository;
    private final X509AlgorithmBindingRegistry bindings;
    private final Optional<OcspResponseService> signing;
    private final Clock clock;

    /** Binds responder control to one realm and one authoritative PKI repository. */
    public OcspResponderService(RealmId realmId, ServerControlStore control, PkiRepository repository,
            X509AlgorithmBindingRegistry bindings, Optional<OcspResponseService> signing, Clock clock) {
        this.realmId = Objects.requireNonNull(realmId); this.control = Objects.requireNonNull(control);
        this.repository = Objects.requireNonNull(repository); this.bindings = Objects.requireNonNull(bindings);
        this.signing = Objects.requireNonNull(signing);
        this.clock = Objects.requireNonNull(clock);
    }

    /** Creates authoritative metadata and durably registers one inactive responder. */
    public Responder register(Registration supplied) {
        Objects.requireNonNull(supplied, "supplied");
        return register(create(supplied.responderId(), supplied.alias(), supplied.authorityId(), supplied.issuerId(),
                supplied.signingMode(), supplied.responderCredentialId(), supplied.signingKeyRef(),
                supplied.chainPathId(), supplied.signatureAlgorithm(), supplied.signatureBindingId(),
                supplied.signatureBindingCommitment(), supplied.responderIdForm(), supplied.responseValidity(),
                supplied.noncePolicy(), supplied.maximumNonceBytes(), supplied.acceptedHashes(),
                supplied.maximumRequestBytes(), supplied.maximumEntries(), supplied.cacheLifetime()));
    }

    /** Canonically seals an already constructed internal draft. */
    /* default */ Responder register(Responder supplied) {
        if (!supplied.realmId().equals(realmId) || supplied.state() != State.INACTIVE) {
            throw new IllegalArgumentException("OCSP responder realm or initial state is invalid");
        }
        if (!supplied.configurationCommitment().equals(commitment(supplied, true))) {
            throw new IllegalArgumentException("OCSP responder commitment differs");
        }
        if (!aliases(supplied.alias()).isEmpty()) {
            throw new IllegalStateException("OCSP responder alias already exists");
        }
        validateDependencies(supplied, true);
        Responder sealed = seal(supplied, State.INACTIVE);
        control.mutateProtocol(List.of(new ServerControlStore.ProtocolMutation(record(sealed), Optional.empty())));
        return sealed;
    }

    /** Returns one exact responder. */
    public Responder require(String responderId) {
        return control.protocolRecord(ServerControlStore.OCSP_RESPONDER, responderId)
                .map(this::decode).orElseThrow(() -> new IllegalArgumentException("OCSP responder is unavailable"));
    }

    /** Resolves one unique active public alias. */
    public Responder requireActiveAlias(String alias) {
        Responder result = requireAlias(alias);
        if (result.state() != State.ACTIVE) {
            throw new IllegalStateException("OCSP responder is inactive");
        }
        validateDependencies(result, false); return result;
    }

    /** Resolves one unique durable alias regardless of activation state. */
    public Responder requireAlias(String alias) {
        Permission.requireId(alias, "OCSP alias");
        List<Responder> matches = aliases(alias);
        if (matches.size() != 1) throw new IllegalArgumentException("OCSP responder alias is unavailable");
        return matches.getFirst();
    }

    /** Lists one bounded deterministic responder page. */
    public ServerControlStore.Page<Responder> list(int offset, int limit) {
        ServerControlStore.Page<ServerControlStore.ProtocolRecord> page =
                control.protocolRecords(ServerControlStore.OCSP_RESPONDER, offset, limit);
        return new ServerControlStore.Page<>(page.values().stream().map(this::decode).toList(),
                page.nextOffset(), page.hasMore());
    }

    private List<Responder> aliases(String alias) {
        List<Responder> matches = new ArrayList<>();
        int offset = 0;
        while (true) {
            ServerControlStore.Page<Responder> page = list(offset, 256);
            page.values().stream().filter(value -> value.alias().equals(alias)).forEach(matches::add);
            if (!page.hasMore()) return List.copyOf(matches);
            offset = page.nextOffset();
        }
    }

    /** Atomically changes only responder activation after dependency revalidation. */
    public Responder setActive(String responderId, boolean active) {
        Responder prior = require(responderId); validateDependencies(prior, true);
        Responder next = seal(prior, active ? State.ACTIVE : State.INACTIVE);
        control.mutateProtocol(List.of(new ServerControlStore.ProtocolMutation(record(next),
                Optional.of(record(prior).commitment()))));
        return next;
    }

    /** Revalidates every durable binding during realm recovery. */
    public void validateAll() {
        int offset = 0;
        while (true) {
            ServerControlStore.Page<Responder> page = list(offset, 256);
            page.values().forEach(value -> validateDependencies(value, true));
            if (!page.hasMore()) return;
            offset = page.nextOffset();
        }
    }

    /** Creates a canonical unsealed record for callers before registration. */
    public Responder create(String responderId, String alias, PkiId authorityId, PkiId issuerId,
            SigningMode signingMode, PkiId responderCredentialId, KeyRef signingKeyRef, PkiId chainPathId,
            String signatureAlgorithm, Optional<String> signatureBindingId, String bindingCommitment,
            OcspResponseService.ResponderId responderIdForm, Duration validity, NoncePolicy noncePolicy,
            int maximumNonceBytes, Set<OcspResponseService.CertIdHash> hashes, int maximumRequestBytes,
            int maximumEntries, Duration cacheLifetime) {
        Responder draft = new Responder(responderId, alias, realmId, authorityId, issuerId, signingMode,
                responderCredentialId, signingKeyRef, chainPathId, signatureAlgorithm, signatureBindingId,
                bindingCommitment, responderIdForm, validity, noncePolicy, maximumNonceBytes, hashes,
                maximumRequestBytes, maximumEntries, cacheLifetime, State.INACTIVE, clock.instant(),
                "0".repeat(64));
        return new Responder(draft.responderId(), draft.alias(), draft.realmId(), draft.authorityId(), draft.issuerId(),
                draft.signingMode(), draft.responderCredentialId(), draft.signingKeyRef(), draft.chainPathId(),
                draft.signatureAlgorithm(), draft.signatureBindingId(), draft.signatureBindingCommitment(),
                draft.responderIdForm(), draft.responseValidity(), draft.noncePolicy(), draft.maximumNonceBytes(),
                draft.acceptedHashes(), draft.maximumRequestBytes(), draft.maximumEntries(), draft.cacheLifetime(),
                draft.state(), draft.createdAt(), commitment(draft, true));
    }

    private Responder seal(Responder value, State state) {
        Responder draft = new Responder(value.responderId(), value.alias(), value.realmId(), value.authorityId(),
                value.issuerId(), value.signingMode(), value.responderCredentialId(), value.signingKeyRef(),
                value.chainPathId(), value.signatureAlgorithm(), value.signatureBindingId(),
                value.signatureBindingCommitment(), value.responderIdForm(), value.responseValidity(),
                value.noncePolicy(), value.maximumNonceBytes(), value.acceptedHashes(), value.maximumRequestBytes(),
                value.maximumEntries(), value.cacheLifetime(), state, value.createdAt(), value.configurationCommitment());
        return new Responder(draft.responderId(), draft.alias(), draft.realmId(), draft.authorityId(), draft.issuerId(),
                draft.signingMode(), draft.responderCredentialId(), draft.signingKeyRef(), draft.chainPathId(),
                draft.signatureAlgorithm(), draft.signatureBindingId(), draft.signatureBindingCommitment(),
                draft.responderIdForm(), draft.responseValidity(), draft.noncePolicy(), draft.maximumNonceBytes(),
                draft.acceptedHashes(), draft.maximumRequestBytes(), draft.maximumEntries(), draft.cacheLifetime(),
                draft.state(), draft.createdAt(), commitment(draft, true));
    }

    private void validateDependencies(Responder value, boolean proveSigning) {
        value.signatureBindingId().ifPresentOrElse(
                bindingId -> bindings.require(bindingId, value.signatureBindingCommitment()),
                () -> {
                    if (!bindings.commitment().equals(value.signatureBindingCommitment())) {
                        throw new IllegalStateException("OCSP algorithm registry commitment differs");
                    }
                });
        IssuerGeneration issuer = repository.issuer(value.issuerId()).orElseThrow();
        IssuerChainPath path = repository.chainPath(value.chainPathId()).orElseThrow();
        if (!issuer.authorityId().equals(value.authorityId()) || !path.authorityId().equals(value.authorityId())
                || !path.issuerId().equals(value.issuerId()) || !path.orderedCredentialIds().getFirst()
                        .equals(issuer.credentialId())) {
            throw new IllegalStateException("OCSP responder issuer/path binding differs");
        }
        try {
            X509CertificateHolder issuerCertificate = certificate(issuer.credentialId());
            X509CertificateHolder responderCertificate = certificate(value.responderCredentialId());
            if (!responderCertificate.isValidOn(Date.from(clock.instant()))) {
                throw new IllegalStateException("OCSP responder certificate is outside its validity interval");
            }
            if (value.signingMode() == SigningMode.ISSUER_SIGNED) {
                if (!value.responderCredentialId().equals(issuer.credentialId())
                        || !value.signingKeyRef().equals(issuer.signingKeyRef())) {
                    throw new IllegalStateException("Issuer-signed responder binding differs");
                }
            } else {
                if (!responderCertificate.isSignatureValid(new JcaContentVerifierProviderBuilder()
                        .build(issuerCertificate)) || responderCertificate.getExtension(Extension.extendedKeyUsage) == null
                        || !org.bouncycastle.asn1.x509.ExtendedKeyUsage.fromExtensions(
                                responderCertificate.getExtensions()).hasKeyPurposeId(
                                        org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_OCSPSigning)) {
                    throw new IllegalStateException("Delegated OCSP responder certificate is unauthorized");
                }
                Extension usage = responderCertificate.getExtension(Extension.keyUsage);
                if (usage != null && !KeyUsage.fromExtensions(responderCertificate.getExtensions())
                        .hasUsages(KeyUsage.digitalSignature)) {
                    throw new IllegalStateException("Delegated OCSP responder key usage is invalid");
                }
            }
        } catch (IllegalStateException failure) {
            throw failure;
        } catch (Exception failure) {
            throw new IllegalStateException("OCSP responder certificate validation failed");
        }
        if (proveSigning) {
            try {
                signing.orElseThrow(() -> new IllegalStateException("OCSP signing service is unavailable"))
                        .validateSigningBinding(value.responderCredentialId(), value.signingKeyRef(),
                                value.signatureAlgorithm(), value.signatureBindingId());
            } catch (IllegalStateException failure) {
                throw failure;
            } catch (RuntimeException failure) {
                throw new IllegalStateException("OCSP signing capability proof failed");
            }
        }
    }

    private X509CertificateHolder certificate(PkiId credentialId) throws IOException {
        try (zeroecho.pki.application.PkiRepositoryContent content = repository.openCredential(credentialId);
                java.io.InputStream input = content.openStream()) {
            byte[] encoded = input.readNBytes(1_048_577);
            if (encoded.length == 1_048_577 || input.read() != -1) {
                throw new IOException("OCSP responder certificate exceeds its finite bound");
            }
            X509CertificateHolder certificate = new X509CertificateHolder(encoded);
            if (!java.util.Arrays.equals(encoded, certificate.getEncoded())) {
                throw new IOException("OCSP responder certificate is not canonical DER");
            }
            return certificate;
        }
    }

    private ServerControlStore.ProtocolRecord record(Responder value) {
        byte[] payload = encode(value);
        return new ServerControlStore.ProtocolRecord(ServerControlStore.OCSP_RESPONDER,
                value.responderId(), sha256(payload), payload);
    }

    private Responder decode(ServerControlStore.ProtocolRecord stored) {
        Responder value = decode(stored.payload());
        if (!stored.recordId().equals(value.responderId()) || !stored.commitment().equals(sha256(stored.payload()))) {
            throw new IllegalStateException("OCSP responder record commitment differs");
        }
        if (value.configurationCommitment().equals("0".repeat(64))) {
            throw new IllegalStateException("OCSP responder commitment is unsealed");
        }
        if (!value.configurationCommitment().equals(commitment(value, true))) {
            throw new IllegalStateException("OCSP responder commitment differs");
        }
        return value;
    }

    private static String commitment(Responder value, boolean ignoreStored) {
        return sha256(encode(value, ignoreStored));
    }

    private static byte[] encode(Responder value) { return encode(value, false); }
    private static byte[] encode(Responder value, boolean ignoreCommitment) {
        try (ByteArrayOutputStream bytes = new ByteArrayOutputStream(1024);
                DataOutputStream output = new DataOutputStream(bytes)) {
            output.writeInt(1); write(output, value.responderId()); write(output, value.alias());
            write(output, value.realmId().value()); write(output, value.authorityId().value());
            write(output, value.issuerId().value()); output.writeInt(value.signingMode().code());
            write(output, value.responderCredentialId().value()); write(output, value.signingKeyRef().value());
            write(output, value.chainPathId().value()); write(output, value.signatureAlgorithm());
            output.writeBoolean(value.signatureBindingId().isPresent());
            if (value.signatureBindingId().isPresent()) write(output, value.signatureBindingId().orElseThrow());
            write(output, value.signatureBindingCommitment()); output.writeInt(value.responderIdForm().code());
            output.writeLong(value.responseValidity().toSeconds()); output.writeInt(value.noncePolicy().code());
            output.writeInt(value.maximumNonceBytes()); output.writeInt(value.acceptedHashes().size());
            for (OcspResponseService.CertIdHash hash : value.acceptedHashes().stream().sorted().toList()) {
                output.writeInt(hash.code());
            }
            output.writeInt(value.maximumRequestBytes()); output.writeInt(value.maximumEntries());
            output.writeLong(value.cacheLifetime().toSeconds()); output.writeInt(value.state().code());
            output.writeLong(value.createdAt().toEpochMilli());
            write(output, ignoreCommitment ? "0".repeat(64) : value.configurationCommitment()); output.flush();
            return bytes.toByteArray();
        } catch (IOException impossible) { throw new IllegalStateException("OCSP encoding failed", impossible); }
    }

    private static Responder decode(byte[] payload) {
        if (payload.length == 0 || payload.length > 65_536) throw new IllegalStateException("OCSP record bound differs");
        try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(payload))) {
            if (input.readInt() != 1) throw new IOException("OCSP record schema is obsolete");
            String id = read(input); String alias = read(input); RealmId realm = new RealmId(read(input));
            PkiId authority = new PkiId(read(input)); PkiId issuer = new PkiId(read(input));
            SigningMode mode = SigningMode.fromCode(input.readInt()); PkiId credential = new PkiId(read(input));
            KeyRef key = new KeyRef(read(input)); PkiId path = new PkiId(read(input)); String algorithm = read(input);
            Optional<String> binding = input.readBoolean() ? Optional.of(read(input)) : Optional.empty();
            String bindingCommitment = read(input);
            OcspResponseService.ResponderId form = OcspResponseService.ResponderId.fromCode(input.readInt());
            Duration validity = Duration.ofSeconds(input.readLong()); NoncePolicy nonce = NoncePolicy.fromCode(input.readInt());
            int nonceBytes = input.readInt(); int count = input.readInt();
            if (count < 1 || count > 2) throw new IOException("OCSP hash count differs");
            Set<OcspResponseService.CertIdHash> hashes = new java.util.HashSet<>();
            for (int index = 0; index < count; index++) {
                hashes.add(OcspResponseService.CertIdHash.fromCode(input.readInt()));
            }
            int requestBytes = input.readInt(); int entries = input.readInt(); Duration cache = Duration.ofSeconds(input.readLong());
            State state = State.fromCode(input.readInt()); Instant created = Instant.ofEpochMilli(input.readLong());
            String commitment = read(input); if (input.read() != -1) throw new IOException("Trailing OCSP record data");
            return new Responder(id, alias, realm, authority, issuer, mode, credential, key, path, algorithm,
                    binding, bindingCommitment, form, validity, nonce, nonceBytes, hashes, requestBytes,
                    entries, cache, state, created, commitment);
        } catch (IOException | RuntimeException failure) {
            throw new IllegalStateException("OCSP responder record is invalid");
        }
    }

    private static void write(DataOutputStream output, String value) throws IOException {
        byte[] encoded = value.getBytes(StandardCharsets.UTF_8);
        if (encoded.length > 16_384) throw new IOException("OCSP string bound differs");
        output.writeInt(encoded.length); output.write(encoded);
    }
    private static String read(DataInputStream input) throws IOException {
        int length = input.readInt(); if (length < 0 || length > 16_384) throw new IOException("OCSP string bound differs");
        byte[] encoded = input.readNBytes(length); if (encoded.length != length) throw new IOException("OCSP record is truncated");
        String value = new String(encoded, StandardCharsets.UTF_8);
        if (!java.util.Arrays.equals(encoded, value.getBytes(StandardCharsets.UTF_8))) throw new IOException("OCSP UTF-8 differs");
        return value;
    }
    private static String sha256(byte[] value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value)); }
        catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException("SHA-256 unavailable", impossible); }
    }
    private static void requireDigest(String value) {
        if (value == null || !value.matches("[0-9a-f]{64}")) throw new IllegalArgumentException("OCSP commitment is invalid");
    }
    private static void positive(Duration value, Duration maximum, String name) {
        if (value == null || value.isZero() || value.isNegative() || value.compareTo(maximum) > 0) {
            throw new IllegalArgumentException("OCSP " + name + " is invalid");
        }
    }
}
