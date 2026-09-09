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
package zeroecho.pkix.bc;

import java.io.IOException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;

import zeroecho.pkix.CertificateExtension;

/**
 * Builds BouncyCastle {@link Extension}s and general names from the typed
 * ZeroEcho PKIX model, and reads requested extensions back. Confined to
 * {@code zeroecho.pkix.bc}.
 */
final class BcExtensions {

    private BcExtensions() {
    }

    /* default */ static X500Name toX500Name(X500Principal principal) {
        return X500Name.getInstance(principal.getEncoded());
    }

    /* default */ static X500Principal toPrincipal(X500Name name) {
        try {
            return new X500Principal(name.getEncoded());
        } catch (IOException failure) {
            throw new IllegalArgumentException("Cannot encode X.500 name", failure);
        }
    }

    /* default */ static SubjectPublicKeyInfo spki(PublicKey publicKey) {
        return SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
    }

    /* default */ static GeneralName toBc(zeroecho.pkix.GeneralName name) {
        return switch (name) {
            case zeroecho.pkix.GeneralName.DnsName dns -> new GeneralName(GeneralName.dNSName, dns.value());
            case zeroecho.pkix.GeneralName.IpAddress ip -> new GeneralName(GeneralName.iPAddress, ip.value());
            case zeroecho.pkix.GeneralName.Rfc822Name email -> new GeneralName(GeneralName.rfc822Name, email.value());
            case zeroecho.pkix.GeneralName.UniformResourceIdentifier uri ->
                    new GeneralName(GeneralName.uniformResourceIdentifier, uri.value());
            case zeroecho.pkix.GeneralName.DirectoryName dn ->
                    new GeneralName(GeneralName.directoryName, toX500Name(dn.value()));
            case zeroecho.pkix.GeneralName.RegisteredId rid ->
                    new GeneralName(GeneralName.registeredID, new ASN1ObjectIdentifier(rid.oid()));
            case zeroecho.pkix.GeneralName.OtherName other -> otherName(other);
        };
    }

    private static GeneralName otherName(zeroecho.pkix.GeneralName.OtherName other) {
        try {
            ASN1EncodableVector vector = new ASN1EncodableVector();
            vector.add(new ASN1ObjectIdentifier(other.typeOid()));
            vector.add(new DERTaggedObject(true, 0, ASN1Primitive.fromByteArray(other.derValue())));
            return new GeneralName(GeneralName.otherName, new DERSequence(vector));
        } catch (IOException failure) {
            throw new IllegalArgumentException("Invalid otherName value DER", failure);
        }
    }

    /* default */ static zeroecho.pkix.GeneralName fromBc(GeneralName name) {
        return switch (name.getTagNo()) {
            case GeneralName.dNSName ->
                    new zeroecho.pkix.GeneralName.DnsName(name.getName().toString());
            case GeneralName.iPAddress ->
                    new zeroecho.pkix.GeneralName.IpAddress(ipLiteral(name));
            case GeneralName.rfc822Name ->
                    new zeroecho.pkix.GeneralName.Rfc822Name(name.getName().toString());
            case GeneralName.uniformResourceIdentifier ->
                    new zeroecho.pkix.GeneralName.UniformResourceIdentifier(name.getName().toString());
            case GeneralName.directoryName ->
                    new zeroecho.pkix.GeneralName.DirectoryName(toPrincipal(X500Name.getInstance(name.getName())));
            case GeneralName.registeredID ->
                    new zeroecho.pkix.GeneralName.RegisteredId(name.getName().toString());
            default -> otherFromBc(name);
        };
    }

    private static String ipLiteral(GeneralName name) {
        byte[] octets = ASN1OctetString.getInstance(name.getName()).getOctets();
        try {
            return java.net.InetAddress.getByAddress(octets).getHostAddress();
        } catch (java.net.UnknownHostException failure) {
            throw new IllegalArgumentException("Malformed iPAddress general name", failure);
        }
    }

    private static zeroecho.pkix.GeneralName otherFromBc(GeneralName name) {
        try {
            return new zeroecho.pkix.GeneralName.OtherName(String.valueOf(name.getTagNo()),
                    name.getName().toASN1Primitive().getEncoded());
        } catch (IOException failure) {
            throw new IllegalArgumentException("Cannot encode general name", failure);
        }
    }

    /* default */ static GeneralNames generalNames(List<zeroecho.pkix.GeneralName> names) {
        GeneralName[] converted = names.stream().map(BcExtensions::toBc).toArray(GeneralName[]::new);
        return new GeneralNames(converted);
    }

    /* default */ static Extension keyUsage(Set<zeroecho.pkix.KeyUsage> usage, boolean critical) {
        int bits = 0;
        for (zeroecho.pkix.KeyUsage single : usage) {
            bits |= usageBit(single);
        }
        try {
            return new Extension(Extension.keyUsage, critical, new DEROctetString(new KeyUsage(bits)));
        } catch (IOException failure) {
            throw new IllegalArgumentException("Cannot encode key usage", failure);
        }
    }

    private static int usageBit(zeroecho.pkix.KeyUsage usage) {
        return switch (usage) {
            case DIGITAL_SIGNATURE -> KeyUsage.digitalSignature;
            case NON_REPUDIATION -> KeyUsage.nonRepudiation;
            case KEY_ENCIPHERMENT -> KeyUsage.keyEncipherment;
            case DATA_ENCIPHERMENT -> KeyUsage.dataEncipherment;
            case KEY_AGREEMENT -> KeyUsage.keyAgreement;
            case KEY_CERT_SIGN -> KeyUsage.keyCertSign;
            case CRL_SIGN -> KeyUsage.cRLSign;
            case ENCIPHER_ONLY -> KeyUsage.encipherOnly;
            case DECIPHER_ONLY -> KeyUsage.decipherOnly;
        };
    }

    /* default */ static Extension extendedKeyUsage(zeroecho.pkix.ExtendedKeyUsage eku, boolean critical) {
        KeyPurposeId[] purposes = eku.keyPurposeOids().stream()
                .map(oid -> KeyPurposeId.getInstance(new ASN1ObjectIdentifier(oid)))
                .toArray(KeyPurposeId[]::new);
        try {
            return new Extension(Extension.extendedKeyUsage, critical,
                    new DEROctetString(new ExtendedKeyUsage(purposes)));
        } catch (IOException failure) {
            throw new IllegalArgumentException("Cannot encode extended key usage", failure);
        }
    }

    /* default */ static Extension basicConstraints(zeroecho.pkix.BasicConstraints constraints, boolean critical) {
        BasicConstraints value;
        if (constraints.certificateAuthority()) {
            if (constraints.pathLenConstraint().isPresent()) {
                value = new BasicConstraints(constraints.pathLenConstraint().getAsInt());
            } else {
                value = new BasicConstraints(true);
            }
        } else {
            value = new BasicConstraints(false);
        }
        try {
            return new Extension(Extension.basicConstraints, critical, new DEROctetString(value));
        } catch (IOException failure) {
            throw new IllegalArgumentException("Cannot encode basic constraints", failure);
        }
    }

    /* default */ static Extension subjectAlternativeNames(List<zeroecho.pkix.GeneralName> names, boolean critical) {
        try {
            return new Extension(Extension.subjectAlternativeName, critical,
                    new DEROctetString(generalNames(names)));
        } catch (IOException failure) {
            throw new IllegalArgumentException("Cannot encode subject alternative names", failure);
        }
    }

    /* default */ static Extension subjectKeyIdentifier(PublicKey publicKey) {
        return subjectKeyIdentifier(spki(publicKey));
    }

    /* default */ static Extension subjectKeyIdentifier(SubjectPublicKeyInfo spki) {
        try {
            return new Extension(Extension.subjectKeyIdentifier, false, new DEROctetString(
                    extensionUtils().createSubjectKeyIdentifier(spki)));
        } catch (IOException failure) {
            throw new IllegalArgumentException("Cannot encode subject key identifier", failure);
        }
    }

    /* default */ static Extension authorityKeyIdentifier(byte[] keyIdentifier) {
        try {
            return new Extension(Extension.authorityKeyIdentifier, false, new DEROctetString(
                    new org.bouncycastle.asn1.x509.AuthorityKeyIdentifier(keyIdentifier.clone())));
        } catch (IOException failure) {
            throw new IllegalArgumentException("Cannot encode authority key identifier", failure);
        }
    }

    /* default */ static Extension generic(CertificateExtension extension) {
        return new Extension(new ASN1ObjectIdentifier(extension.oid()), extension.critical(),
                new DEROctetString(extension.derValue()));
    }

    /* default */ static List<CertificateExtension> fromBc(Extensions extensions) {
        List<CertificateExtension> result = new ArrayList<>();
        if (extensions == null) {
            return result;
        }
        for (ASN1ObjectIdentifier oid : extensions.getExtensionOIDs()) {
            Extension extension = extensions.getExtension(oid);
            ASN1OctetString value = extension.getExtnValue();
            result.add(new CertificateExtension(oid.getId(), extension.isCritical(), value.getOctets()));
        }
        return result;
    }

    /* default */ static List<zeroecho.pkix.GeneralName> sansFromBc(Extensions extensions) {
        List<zeroecho.pkix.GeneralName> result = new ArrayList<>();
        if (extensions == null) {
            return result;
        }
        Extension san = extensions.getExtension(Extension.subjectAlternativeName);
        if (san == null) {
            return result;
        }
        GeneralNames names = GeneralNames.getInstance(san.getParsedValue());
        for (GeneralName name : names.getNames()) {
            result.add(fromBc(name));
        }
        return result;
    }

    /* default */ static byte[] keyIdentifier(PublicKey publicKey) {
        return extensionUtils().createSubjectKeyIdentifier(spki(publicKey)).getKeyIdentifier();
    }

    private static JcaX509ExtensionUtils extensionUtils() {
        try {
            return new JcaX509ExtensionUtils();
        } catch (java.security.NoSuchAlgorithmException failure) {
            throw new IllegalStateException("SHA-1 unavailable for key identifier", failure);
        }
    }
}
