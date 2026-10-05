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

package zeroecho.pki.impl.fs;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import javax.security.auth.x500.X500Principal;
import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.impl.core.CrlScope;
import zeroecho.pki.impl.core.continuation.DomainCommandEncoding;
import zeroecho.pki.impl.framework.x509.StreamingDerReader;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pkix.Pkix;

/** Bounded reservation coordinates, derived from the exact accepted TBS and frozen command. */
record SignAcceptanceCrlScope(List<CrlScopeOwner> owners, ScopeSerialReservation reservation) {
    private static final int EXTENSIONS_POSITION = 3;
    private static final int HIGH_TAG_NUMBER = 0x1f;
    private static final String CREATE_ROOT = "CREATE_ROOT";

    private static final int MAXIMUM_TBS_BYTES = 1_048_576;

    SignAcceptanceCrlScope {
        owners = List.copyOf(owners);
    }

    /* default */ static Optional<SignAcceptanceCrlScope> derive(FilesystemPkiStore store,
            SignWorkflowStore.AcceptanceCommand accepted, RepeatableContent content) throws IOException {
        if (accepted.outer().isEmpty()) { return Optional.empty(); }
        SignWorkflowStore.OuterCommand outer = accepted.outer().orElseThrow();
        if (outer.kind() == DomainContinuationStore.Kind.STATUS
                || outer.kind() == DomainContinuationStore.Kind.KEY_PROOF) { return Optional.empty(); }
        DomainCommandEncoding.Decoded command = DomainCommandEncoding.decode(outer.command());
        boolean issuance = outer.kind() == DomainContinuationStore.Kind.ISSUANCE;
        if (!issuance && !"x509".equals(command.field(0))) { return Optional.empty(); }
        X509Certificate candidate = candidate(accepted, content);
        boolean root = !issuance && (CREATE_ROOT.equals(command.operation())
                || "ROLLOVER_ROOT".equals(command.operation()));
        requireCandidateFields(candidate, command, accepted, issuance, root);
        PkiId authority = new PkiId(command.field(root ? 13 : issuance ? 0 : 1));
        require(accepted.fairnessAuthorityId().equals(authority));
        ScopeSerialReservation.SigningOwner owner = new ScopeSerialReservation.SigningOwner(
                accepted.operationId(), outer.commandCommitment().substring("domain:v1:".length()));
        if (root) { return rootScope(store, accepted, command, candidate, authority, owner); }
        return issuerScope(store, accepted, command, candidate, authority, owner, issuance);
    }

    private static X509Certificate candidate(SignWorkflowStore.AcceptanceCommand accepted,
            RepeatableContent content) throws IOException {
        long length = accepted.candidate().length();
        require(accepted.candidate().encoding() == Encoding.DER && length > 0 && length <= MAXIMUM_TBS_BYTES);
        try (InputStream input = content.openStream()) {
            byte[] tbs = input.readNBytes(Math.toIntExact(length));
            require(tbs.length == length && input.read() == -1
                    && sha256(tbs).equals(accepted.candidate().sha256()));
            new StreamingDerReader().validate(tbs, MAXIMUM_TBS_BYTES);
            requireV3CertificateFields(tbs);
            // The placeholder is only a structural adapter. It is never verified,
            // published, or evidence of algorithm/key authorization. Preparation
            // owns that decision, including configured private algorithm bindings.
            X509Certificate certificate = Pkix.parseCertificate(
                    Pkix.assembleCertificateOrCrl(tbs, new byte[] { 0 }, false));
            require(MessageDigest.isEqual(tbs, certificate.getTBSCertificate()));
            return certificate;
        } catch (CertificateEncodingException failure) {
            throw new IllegalArgumentException("Signing candidate is not a complete canonical TBSCertificate", failure);
        }
    }

    // The bounded DER reader establishes canonical TLV encodings first. This
    // local schema walk additionally consumes every TBSCertificate field; the
    // certificate adapter can otherwise preserve unrecognized trailing fields.
    private static void requireV3CertificateFields(byte[] encoded) {
        ByteBuffer input = ByteBuffer.wrap(encoded);
        ByteBuffer tbs = field(input, 0x30);
        require(!input.hasRemaining());
        ByteBuffer version = field(tbs, 0xa0);
        ByteBuffer integer = field(version, 0x02);
        require(integer.remaining() == 1 && integer.get() == 2 && !version.hasRemaining());
        field(tbs, 0x02); // Serial positivity and RFC size are checked by the reservation model.
        requireAlgorithmFields(field(tbs, 0x30));
        requireNameFields(field(tbs, 0x30));
        ByteBuffer validity = field(tbs, 0x30);
        requireTimeField(validity);
        requireTimeField(validity);
        require(!validity.hasRemaining());
        requireNameFields(field(tbs, 0x30));
        ByteBuffer spki = field(tbs, 0x30);
        requireAlgorithmFields(field(spki, 0x30));
        ByteBuffer publicKey = field(spki, 0x03);
        require(publicKey.hasRemaining() && publicKey.get() == 0 && !spki.hasRemaining());
        requireOptionalCertificateFields(tbs);
    }

    private static void requireAlgorithmFields(ByteBuffer algorithm) {
        field(algorithm, 0x06);
        if (algorithm.hasRemaining()) { field(algorithm, -1); }
        require(!algorithm.hasRemaining());
    }

    private static void requireNameFields(ByteBuffer name) {
        while (name.hasRemaining()) {
            ByteBuffer rdn = field(name, 0x31);
            require(rdn.hasRemaining());
            while (rdn.hasRemaining()) {
                ByteBuffer attribute = field(rdn, 0x30);
                field(attribute, 0x06);
                field(attribute, -1);
                require(!attribute.hasRemaining());
            }
        }
    }

    private static void requireTimeField(ByteBuffer validity) {
        require(validity.hasRemaining());
        int tag = Byte.toUnsignedInt(validity.get(validity.position()));
        require(tag == 0x17 || tag == 0x18);
        field(validity, tag);
    }

    /** Returns a zero-copy value slice from the already validated bounded DER. */
    private static ByteBuffer field(ByteBuffer input, int expectedTag) {
        require(input.hasRemaining());
        int tag = Byte.toUnsignedInt(input.get());
        require(expectedTag < 0 || tag == expectedTag);
        if ((tag & HIGH_TAG_NUMBER) == HIGH_TAG_NUMBER) {
            int part;
            do {
                require(input.hasRemaining());
                part = Byte.toUnsignedInt(input.get());
            } while ((part & 0x80) != 0);
        }
        require(input.hasRemaining());
        int length = Byte.toUnsignedInt(input.get());
        if ((length & 0x80) != 0) {
            int octets = length & 0x7f;
            require(octets > 0 && octets <= 4 && input.remaining() >= octets);
            length = 0;
            for (int index = 0; index < octets; index++) {
                length = Math.addExact(Math.multiplyExact(length, 256), Byte.toUnsignedInt(input.get()));
            }
        }
        require(length <= input.remaining());
        ByteBuffer value = input.slice(input.position(), length);
        input.position(Math.addExact(input.position(), length));
        return value;
    }

    private static CrlScope scope(X509Certificate certificate) {
        return CrlScope.of(certificate.getSubjectX500Principal().getEncoded(), certificate.getPublicKey().getEncoded());
    }

    private static String sha256(byte[] value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
        } catch (java.security.NoSuchAlgorithmException unavailable) {
            throw new IllegalStateException("SHA-256 unavailable", unavailable);
        }
    }

    private static void require(boolean valid) {
        if (!valid) { throw invalid(); }
    }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("Signing candidate reservation coordinates differ from the frozen command");
    }

    private static void requireCandidateFields(X509Certificate candidate, DomainCommandEncoding.Decoded command,
            SignWorkflowStore.AcceptanceCommand accepted, boolean issuance, boolean root) {
        int serialField = issuance ? 10 : root ? 9 : 13;
        int validityField = issuance ? 8 : root ? 7 : 11;
        int keyField = issuance ? 11 : root ? 3 : 14;
        require(candidate.getSerialNumber().equals(new BigInteger(command.field(serialField)))
                && candidate.getNotBefore().toInstant().equals(Instant.parse(command.field(validityField)))
                && candidate.getNotAfter().toInstant().equals(Instant.parse(command.field(validityField + 1)))
                && accepted.keyRef().value().equals(command.field(keyField)));
    }
    private static Optional<SignAcceptanceCrlScope> rootScope(FilesystemPkiStore store,
            SignWorkflowStore.AcceptanceCommand accepted, DomainCommandEncoding.Decoded command,
            X509Certificate candidate, PkiId authority, ScopeSerialReservation.SigningOwner owner) {
        require(candidate.getIssuerX500Principal().equals(candidate.getSubjectX500Principal())
                && candidate.getSubjectX500Principal().equals(new X500Principal(command.field(10))));
        if (CREATE_ROOT.equals(command.operation())) {
            require(authority.equals(DomainCommandEncoding.rootAuthorityId(accepted.operationId())));
        } else {
            require(store.getCa(authority).isPresent());
        }
        CrlScope scope = scope(candidate);
        return Optional.of(new SignAcceptanceCrlScope(List.of(new CrlScopeOwner(scope, authority)),
                new ScopeSerialReservation(scope, candidate.getSerialNumber(), owner)));
    }


    private static void requireOptionalCertificateFields(ByteBuffer tbs) {
        int previous = 0;
        while (tbs.hasRemaining()) {
            int tag = Byte.toUnsignedInt(tbs.get(tbs.position()));
            int position = switch (tag) {
                case 0x81 -> 1;
                case 0x82 -> 2;
                case 0xa3 -> 3;
                default -> throw invalid();
            };
            require(position > previous);
            previous = position;
            ByteBuffer optional = field(tbs, tag);
            if (position == EXTENSIONS_POSITION) {
                ByteBuffer extensions = field(optional, 0x30);
                require(!optional.hasRemaining() && extensions.hasRemaining());
                while (extensions.hasRemaining()) {
                    ByteBuffer extension = field(extensions, 0x30);
                    field(extension, 0x06);
                    if (extension.hasRemaining() && extension.get(extension.position()) == 0x01) {
                        ByteBuffer critical = field(extension, 0x01);
                        require(critical.remaining() == 1 && critical.get() == (byte) 0xff);
                    }
                    field(extension, 0x04);
                    require(!extension.hasRemaining());
                }
            } else {
                require(optional.hasRemaining());
                int unused = Byte.toUnsignedInt(optional.get());
                require(unused <= 7 && (optional.hasRemaining() || unused == 0));
                if (optional.hasRemaining()) {
                    require((optional.get(optional.limit() - 1) & ((1 << unused) - 1)) == 0);
                }
            }
        }
    }

    private static Optional<SignAcceptanceCrlScope> issuerScope(FilesystemPkiStore store,
            SignWorkflowStore.AcceptanceCommand accepted, DomainCommandEncoding.Decoded command,
            X509Certificate candidate, PkiId authority, ScopeSerialReservation.SigningOwner owner,
            boolean issuance) throws IOException {
        if (!issuance) {
            String frozen = command.field(10);
            require(frozen.equals(candidate.getSubjectX500Principal().getName(X500Principal.RFC2253))
                    || frozen.equals(Pkix.distinguishedNameString(
                            Pkix.parseDistinguishedName(candidate.getSubjectX500Principal().getEncoded()))));
        }
        IssuerGeneration generation = store.getIssuerGeneration(new PkiId(command.field(issuance ? 1 : 3)))
                .orElseThrow(SignAcceptanceCrlScope::invalid);
        IssuerChainPath path = store.getIssuerChainPath(new PkiId(command.field(issuance ? 2 : 4)))
                .orElseThrow(SignAcceptanceCrlScope::invalid);
        Credential issuer = store.getCredential(generation.credentialId()).orElseThrow(SignAcceptanceCrlScope::invalid);
        requireIssuerBinding(authority, generation, path, issuer, command, accepted, candidate, issuance);
        X509Certificate issuerCertificate = store.certificateHolder(issuer);
        require(candidate.getIssuerX500Principal().equals(issuerCertificate.getSubjectX500Principal()));
        CrlScope scope = scope(issuerCertificate);
        List<CrlScopeOwner> owners = issuance ? List.of(new CrlScopeOwner(scope, authority))
                : List.of(new CrlScopeOwner(scope, authority),
                        new CrlScopeOwner(scope(candidate), new PkiId(command.field(2))));
        return Optional.of(new SignAcceptanceCrlScope(owners,
                new ScopeSerialReservation(scope, candidate.getSerialNumber(), owner)));
    }

    private static void requireIssuerBinding(PkiId authority, IssuerGeneration generation, IssuerChainPath path,
            Credential issuer, DomainCommandEncoding.Decoded command, SignWorkflowStore.AcceptanceCommand accepted,
            X509Certificate candidate, boolean issuance) {
        require(authority.equals(generation.authorityId()) && authority.equals(path.authorityId())
                && generation.issuerId().equals(path.issuerId())
                && path.orderedCredentialIds().getFirst().equals(issuer.credentialId())
                && path.pathCommitment().equals(command.field(issuance ? 3 : 5))
                && generation.signingKeyRef().equals(accepted.keyRef())
                && issuer.content().contentId().equals(command.field(issuance ? 12 : 15))
                && issuer.content().sha256().equals(command.field(issuance ? 13 : 16))
                && sha256(candidate.getPublicKey().getEncoded()).equals(command.field(issuance ? 14 : 17)));
    }

}
