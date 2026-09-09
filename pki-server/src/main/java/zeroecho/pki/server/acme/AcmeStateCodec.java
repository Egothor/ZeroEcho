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
package zeroecho.pki.server.acme;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.confirmation.ConfirmationDisclosurePolicy;
import zeroecho.pki.api.confirmation.ConfirmationProofSuiteRef;
import zeroecho.pki.api.confirmation.CredentialConfirmationPolicy;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.server.RealmId;

/** Strict versioned canonical binary codec for durable ACME records. */
@SuppressWarnings("PMD")
final class AcmeStateCodec {
    private static final int MAGIC = 0x5a454143;
    private static final int VERSION = 5;
    private static final int MAX_TEXT = 16_384;
    private static final int MAX_COLLECTION = 256;
    private static final String ZERO = "0".repeat(64);
    private static final int DIRECTORY = 1;
    private static final int ACCOUNT = 2;
    private static final int ORDER = 3;
    private static final int AUTHORIZATION = 4;
    private static final int CHALLENGE = 5;
    private static final int EVIDENCE = 6;

    byte[] encode(Object record) { return encode(record, true); }
    String commitment(Object record) { return sha256(encode(record, false)); }

    Object seal(Object record) {
        String value = commitment(record);
        return switch (record) {
            case AcmeState.Directory item -> new AcmeState.Directory(item.directoryId(), item.alias(), item.revision(),
                    item.realmId(), item.authorityId(), item.profile(), item.issuerId(), item.issuancePathId(),
                    item.issuancePathCommitment(), item.identifierTypes(), item.dnsNamespaces(), item.maximumValidity(),
                    item.publicKeyAlgorithms(), item.x509BindingPolicies(), item.challengeTypes(),
                    item.challengeProviderIds(), item.eabProviderId(), item.eabRequired(), item.confirmationPolicy(),
                    item.confirmationPolicyCommitment(), item.status(), item.policyCommitment(), item.createdAt(),
                    value);
            case AcmeState.Account item -> new AcmeState.Account(item.accountId(), item.directoryId(),
                    item.directoryRevision(), item.directoryPolicyCommitment(), item.keyThumbprint(), item.publicKeySpki(),
                    item.status(), item.contacts(), item.termsAgreed(), item.eabPolicyCommitment(), item.createdAt(),
                    item.updatedAt(), value);
            case AcmeState.Order item -> new AcmeState.Order(item.orderId(), item.accountId(), item.directoryId(),
                    item.directoryRevision(), item.directoryPolicyCommitment(), item.authorityId(), item.profile(),
                    item.issuerId(), item.issuancePathId(), item.issuancePathCommitment(), item.identifiers(),
                    item.notBefore(), item.notAfter(), item.status(), item.authorizationIds(), item.credentialId(),
                    item.issuanceCommitment(), item.signingOperationId(), item.createdAt(), item.expiresAt(), value);
            case AcmeState.Authorization item -> new AcmeState.Authorization(item.authorizationId(), item.orderId(),
                    item.accountId(), item.identifier(), item.status(), item.challengeIds(), item.expiresAt(),
                    item.evidenceId(), value);
            case AcmeState.Challenge item -> new AcmeState.Challenge(item.challengeId(), item.authorizationId(),
                    item.type(), item.token(), item.status(), item.providerId(), item.attempt(), item.failureCode(),
                    item.evidenceId(), item.createdAt(), item.updatedAt(), value);
            case AcmeState.AuthorizationEvidence item -> new AcmeState.AuthorizationEvidence(item.evidenceId(),
                    item.authorizationId(), item.providerId(), item.challengeType(), item.identifier(),
                    item.accountKeyCommitment(), item.keyAuthorizationCommitment(),
                    item.directoryPolicyCommitment(), item.attempt(), item.validatedAt(), item.expiresAt(),
                    item.result(), item.failureCode(), value);
            default -> throw new IllegalArgumentException("Unsupported ACME record");
        };
    }

    Object decode(byte[] encoded) {
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(encoded))) {
            if (in.readInt() != MAGIC || in.readInt() != VERSION) throw invalid();
            Object result = switch (in.readInt()) {
                case DIRECTORY -> readDirectory(in);
                case ACCOUNT -> readAccount(in);
                case ORDER -> readOrder(in);
                case AUTHORIZATION -> readAuthorization(in);
                case CHALLENGE -> readChallenge(in);
                case EVIDENCE -> readEvidence(in);
                default -> throw invalid();
            };
            if (in.read() != -1 || !storedCommitment(result).equals(commitment(result))) throw invalid();
            return result;
        } catch (IOException | RuntimeException failure) {
            throw new IllegalArgumentException("ACME control record is invalid");
        }
    }

    private byte[] encode(Object record, boolean includeCommitment) {
        try (ByteArrayOutputStream bytes = new ByteArrayOutputStream(); DataOutputStream out = new DataOutputStream(bytes)) {
            out.writeInt(MAGIC); out.writeInt(VERSION);
            switch (record) {
                case AcmeState.Directory item -> writeDirectory(out, item, includeCommitment);
                case AcmeState.Account item -> writeAccount(out, item, includeCommitment);
                case AcmeState.Order item -> writeOrder(out, item, includeCommitment);
                case AcmeState.Authorization item -> writeAuthorization(out, item, includeCommitment);
                case AcmeState.Challenge item -> writeChallenge(out, item, includeCommitment);
                case AcmeState.AuthorizationEvidence item -> writeEvidence(out, item, includeCommitment);
                default -> throw new IllegalArgumentException("Unsupported ACME record");
            }
            out.flush(); return bytes.toByteArray();
        } catch (IOException impossible) {
            throw new IllegalStateException("ACME in-memory encoding failed", impossible);
        }
    }

    private static void writeDirectory(DataOutputStream out, AcmeState.Directory v, boolean committed) throws IOException {
        out.writeInt(DIRECTORY); string(out, v.directoryId()); string(out, v.alias()); out.writeInt(v.revision());
        string(out, v.realmId().value()); string(out, v.authorityId().value()); profile(out, v.profile());
        string(out, v.issuerId().value()); string(out, v.issuancePathId().value()); string(out, v.issuancePathCommitment());
        enums(out, v.identifierTypes()); strings(out, v.dnsNamespaces()); out.writeLong(v.maximumValidity().toSeconds());
        strings(out, v.publicKeyAlgorithms()); strings(out, v.x509BindingPolicies()); enums(out, v.challengeTypes());
        strings(out, v.challengeProviderIds()); optional(out, v.eabProviderId()); out.writeBoolean(v.eabRequired());
        confirmationPolicy(out, v.confirmationPolicy()); string(out, v.confirmationPolicyCommitment());
        string(out, v.status().name()); string(out, v.policyCommitment());
        instant(out, v.createdAt()); string(out, committed ? v.commitment() : ZERO);
    }
    private static AcmeState.Directory readDirectory(DataInputStream in) throws IOException {
        String id = string(in), alias = string(in); int revision = in.readInt(); RealmId realm = new RealmId(string(in));
        PkiId authority = new PkiId(string(in)); CertificateProfileRef profile = profile(in);
        PkiId issuer = new PkiId(string(in)), path = new PkiId(string(in)); String pathCommitment = string(in);
        Set<AcmeState.IdentifierType> types = enumSet(in, AcmeState.IdentifierType.class);
        Set<String> namespaces = strings(in); Duration validity = Duration.ofSeconds(in.readLong());
        Set<String> algorithms = strings(in), bindings = strings(in);
        Set<AcmeState.ChallengeType> challenges = enumSet(in, AcmeState.ChallengeType.class);
        Set<String> providers = strings(in); Optional<String> eab = optional(in); boolean required = in.readBoolean();
        CredentialConfirmationPolicy confirmation = confirmationPolicy(in);
        String confirmationCommitment = string(in);
        AcmeState.DirectoryStatus status = AcmeState.DirectoryStatus.valueOf(string(in));
        return new AcmeState.Directory(id, alias, revision, realm, authority, profile, issuer, path, pathCommitment,
                types, namespaces, validity, algorithms, bindings, challenges, providers, eab, required,
                confirmation, confirmationCommitment, status, string(in), instant(in), string(in));
    }

    private static void confirmationPolicy(DataOutputStream out, CredentialConfirmationPolicy value)
            throws IOException {
        string(out, value.disclosurePolicy().name());
        out.writeLong(value.confirmationWindow().getSeconds());
        out.writeInt(value.confirmationWindow().getNano());
        string(out, value.proofSuite().suiteId());
        string(out, value.proofSuite().configurationCommitment());
    }

    private static CredentialConfirmationPolicy confirmationPolicy(DataInputStream in) throws IOException {
        ConfirmationDisclosurePolicy disclosure = ConfirmationDisclosurePolicy.valueOf(string(in));
        Duration window = Duration.ofSeconds(in.readLong(), in.readInt());
        ConfirmationProofSuiteRef proofSuite = new ConfirmationProofSuiteRef(string(in), string(in));
        return new CredentialConfirmationPolicy(disclosure, window, proofSuite);
    }

    private static void writeAccount(DataOutputStream out, AcmeState.Account v, boolean committed) throws IOException {
        out.writeInt(ACCOUNT); string(out, v.accountId()); string(out, v.directoryId()); out.writeInt(v.directoryRevision());
        string(out, v.directoryPolicyCommitment()); string(out, v.keyThumbprint()); bytes(out, v.publicKeySpki());
        string(out, v.status().name()); stringsList(out, v.contacts()); out.writeBoolean(v.termsAgreed());
        optional(out, v.eabPolicyCommitment()); instant(out, v.createdAt()); instant(out, v.updatedAt());
        string(out, committed ? v.commitment() : ZERO);
    }
    private static AcmeState.Account readAccount(DataInputStream in) throws IOException {
        return new AcmeState.Account(string(in), string(in), in.readInt(), string(in), string(in), bytes(in, 16_384),
                AcmeState.AccountStatus.valueOf(string(in)), stringsList(in), in.readBoolean(), optional(in),
                instant(in), instant(in), string(in));
    }

    private static void writeOrder(DataOutputStream out, AcmeState.Order v, boolean committed) throws IOException {
        out.writeInt(ORDER); string(out, v.orderId()); string(out, v.accountId()); string(out, v.directoryId());
        out.writeInt(v.directoryRevision()); string(out, v.directoryPolicyCommitment()); string(out, v.authorityId().value());
        profile(out, v.profile()); string(out, v.issuerId().value()); string(out, v.issuancePathId().value());
        string(out, v.issuancePathCommitment()); identifiers(out, v.identifiers()); optionalInstant(out, v.notBefore());
        optionalInstant(out, v.notAfter()); string(out, v.status().name()); stringsList(out, v.authorizationIds());
        optional(out, v.credentialId().map(PkiId::value)); optional(out, v.issuanceCommitment());
        instant(out, v.createdAt()); instant(out, v.expiresAt());
        optional(out, v.signingOperationId().map(PkiId::value));
        string(out, committed ? v.commitment() : ZERO);
    }
    private static AcmeState.Order readOrder(DataInputStream in) throws IOException {
        String id = string(in), account = string(in), directory = string(in); int revision = in.readInt();
        String directoryPolicyCommitment = string(in); PkiId authority = new PkiId(string(in)); CertificateProfileRef profile = profile(in);
        PkiId issuer = new PkiId(string(in)), path = new PkiId(string(in)); String pathCommitment = string(in);
        List<AcmeState.Identifier> identifiers = identifiers(in); Optional<Instant> from = optionalInstant(in), to = optionalInstant(in);
        AcmeState.OrderStatus status = AcmeState.OrderStatus.valueOf(string(in)); List<String> authorizations = stringsList(in);
        Optional<PkiId> credential = optional(in).map(PkiId::new); Optional<String> issuanceCommitment = optional(in);
        Instant created = instant(in), expires = instant(in);
        Optional<PkiId> signingOperation = optional(in).map(PkiId::new);
        return new AcmeState.Order(id, account, directory, revision, directoryPolicyCommitment, authority, profile, issuer,
                path, pathCommitment, identifiers, from, to, status, authorizations, credential,
                issuanceCommitment, signingOperation, created, expires, string(in));
    }

    private static void writeAuthorization(DataOutputStream out, AcmeState.Authorization v, boolean committed) throws IOException {
        out.writeInt(AUTHORIZATION); string(out, v.authorizationId()); string(out, v.orderId()); string(out, v.accountId());
        identifier(out, v.identifier()); string(out, v.status().name()); stringsList(out, v.challengeIds());
        instant(out, v.expiresAt()); optional(out, v.evidenceId()); string(out, committed ? v.commitment() : ZERO);
    }
    private static AcmeState.Authorization readAuthorization(DataInputStream in) throws IOException {
        return new AcmeState.Authorization(string(in), string(in), string(in), identifier(in),
                AcmeState.AuthorizationStatus.valueOf(string(in)), stringsList(in), instant(in), optional(in), string(in));
    }

    private static void writeChallenge(DataOutputStream out, AcmeState.Challenge v, boolean committed) throws IOException {
        out.writeInt(CHALLENGE); string(out, v.challengeId()); string(out, v.authorizationId()); string(out, v.type().name());
        string(out, v.token()); string(out, v.status().name()); string(out, v.providerId()); out.writeInt(v.attempt());
        optional(out, v.failureCode()); optional(out, v.evidenceId()); instant(out, v.createdAt()); instant(out, v.updatedAt());
        string(out, committed ? v.commitment() : ZERO);
    }
    private static AcmeState.Challenge readChallenge(DataInputStream in) throws IOException {
        return new AcmeState.Challenge(string(in), string(in), AcmeState.ChallengeType.valueOf(string(in)), string(in),
                AcmeState.ChallengeStatus.valueOf(string(in)), string(in), in.readInt(), optional(in), optional(in),
                instant(in), instant(in), string(in));
    }

    private static void writeEvidence(DataOutputStream out, AcmeState.AuthorizationEvidence v, boolean committed) throws IOException {
        out.writeInt(EVIDENCE); string(out, v.evidenceId()); string(out, v.authorizationId()); string(out, v.providerId());
        string(out, v.challengeType().name()); identifier(out, v.identifier()); string(out, v.accountKeyCommitment());
        string(out, v.keyAuthorizationCommitment()); string(out, v.directoryPolicyCommitment()); out.writeInt(v.attempt());
        instant(out, v.validatedAt()); instant(out, v.expiresAt()); string(out, v.result().name()); optional(out, v.failureCode());
        string(out, committed ? v.commitment() : ZERO);
    }
    private static AcmeState.AuthorizationEvidence readEvidence(DataInputStream in) throws IOException {
        return new AcmeState.AuthorizationEvidence(string(in), string(in), string(in),
                AcmeState.ChallengeType.valueOf(string(in)), identifier(in), string(in), string(in), string(in),
                in.readInt(), instant(in), instant(in), AcmeState.EvidenceResult.valueOf(string(in)), optional(in), string(in));
    }

    private static String storedCommitment(Object value) {
        return switch (value) {
            case AcmeState.Directory item -> item.commitment(); case AcmeState.Account item -> item.commitment();
            case AcmeState.Order item -> item.commitment(); case AcmeState.Authorization item -> item.commitment();
            case AcmeState.Challenge item -> item.commitment(); case AcmeState.AuthorizationEvidence item -> item.commitment();
            default -> throw invalid();
        };
    }
    private static void profile(DataOutputStream out, CertificateProfileRef value) throws IOException {
        string(out, value.profileId()); out.writeLong(value.profileVersion()); bytes(out, value.canonicalSha256());
    }
    private static CertificateProfileRef profile(DataInputStream in) throws IOException {
        return new CertificateProfileRef(string(in), in.readLong(), bytes(in, 32));
    }
    private static void identifier(DataOutputStream out, AcmeState.Identifier value) throws IOException {
        string(out, value.type().name()); string(out, value.value()); out.writeBoolean(value.wildcard());
    }
    private static AcmeState.Identifier identifier(DataInputStream in) throws IOException {
        return new AcmeState.Identifier(AcmeState.IdentifierType.valueOf(string(in)), string(in), in.readBoolean());
    }
    private static void identifiers(DataOutputStream out, List<AcmeState.Identifier> values) throws IOException {
        out.writeInt(values.size()); for (AcmeState.Identifier value : values) identifier(out, value);
    }
    private static List<AcmeState.Identifier> identifiers(DataInputStream in) throws IOException {
        int count = count(in); List<AcmeState.Identifier> result = new ArrayList<>(count);
        for (int index = 0; index < count; index++) result.add(identifier(in)); return List.copyOf(result);
    }
    private static <E extends Enum<E>> void enums(DataOutputStream out, Set<E> values) throws IOException {
        strings(out, values.stream().map(Enum::name).collect(java.util.stream.Collectors.toSet()));
    }
    private static <E extends Enum<E>> Set<E> enumSet(DataInputStream in, Class<E> type) throws IOException {
        Set<E> result = new HashSet<>(); for (String name : strings(in)) if (!result.add(Enum.valueOf(type, name))) throw invalid();
        return Set.copyOf(result);
    }
    private static void strings(DataOutputStream out, Set<String> values) throws IOException {
        List<String> sorted = values.stream().sorted().toList(); stringsList(out, sorted);
    }
    private static Set<String> strings(DataInputStream in) throws IOException {
        List<String> values = stringsList(in); Set<String> result = new HashSet<>(values);
        if (result.size() != values.size()) throw invalid(); return Set.copyOf(result);
    }
    private static void stringsList(DataOutputStream out, List<String> values) throws IOException {
        if (values.size() > MAX_COLLECTION) throw invalid(); out.writeInt(values.size()); for (String value : values) string(out, value);
    }
    private static List<String> stringsList(DataInputStream in) throws IOException {
        int count = count(in); List<String> result = new ArrayList<>(count);
        for (int index = 0; index < count; index++) result.add(string(in)); return List.copyOf(result);
    }
    private static void string(DataOutputStream out, String value) throws IOException {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8); if (bytes.length > MAX_TEXT) throw invalid();
        out.writeInt(bytes.length); out.write(bytes);
    }
    private static String string(DataInputStream in) throws IOException {
        int length = in.readInt(); if (length < 0 || length > MAX_TEXT) throw invalid();
        byte[] bytes = in.readNBytes(length); if (bytes.length != length) throw invalid();
        String value = new String(bytes, StandardCharsets.UTF_8);
        if (!java.util.Arrays.equals(bytes, value.getBytes(StandardCharsets.UTF_8))) throw invalid(); return value;
    }
    private static void bytes(DataOutputStream out, byte[] value) throws IOException { out.writeInt(value.length); out.write(value); }
    private static byte[] bytes(DataInputStream in, int maximum) throws IOException {
        int length = in.readInt(); if (length <= 0 || length > maximum) throw invalid();
        byte[] result = in.readNBytes(length); if (result.length != length) throw invalid(); return result;
    }
    private static void optional(DataOutputStream out, Optional<String> value) throws IOException { out.writeBoolean(value.isPresent()); if (value.isPresent()) string(out, value.orElseThrow()); }
    private static Optional<String> optional(DataInputStream in) throws IOException { return in.readBoolean() ? Optional.of(string(in)) : Optional.empty(); }
    private static void instant(DataOutputStream out, Instant value) throws IOException { out.writeLong(value.toEpochMilli()); }
    private static Instant instant(DataInputStream in) throws IOException { return Instant.ofEpochMilli(in.readLong()); }
    private static void optionalInstant(DataOutputStream out, Optional<Instant> value) throws IOException { out.writeBoolean(value.isPresent()); if (value.isPresent()) instant(out, value.orElseThrow()); }
    private static Optional<Instant> optionalInstant(DataInputStream in) throws IOException { return in.readBoolean() ? Optional.of(instant(in)) : Optional.empty(); }
    private static int count(DataInputStream in) throws IOException { int value = in.readInt(); if (value < 0 || value > MAX_COLLECTION) throw invalid(); return value; }
    private static String sha256(byte[] value) { try { return java.util.HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value)); } catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException("SHA-256 unavailable", impossible); } }
    private static IllegalArgumentException invalid() { return new IllegalArgumentException("ACME control record is invalid"); }
}
