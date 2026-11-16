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
package zeroecho.pki.application;

import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.*;
import zeroecho.pki.api.status.*;
import zeroecho.pki.impl.fs.*;
import zeroecho.pki.impl.framework.x509.bc.BcX509CredentialFramework;
import zeroecho.pki.testkit.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Large immutable status exports remain streaming, integrity checked and provider owned.
 */
class StatusExportsTest {
    /**
     * Streaming PEM handles chunk edges repeated EOF cancellation and lease closure.
     *
     * @throws Exception if fixture setup, execution, or cleanup fails
     */
    @Test void streamingPemHandlesChunkEdgesRepeatedEofCancellationAndLeaseClosure() throws Exception {
        for(int size:new int[]{1,47,48,49,49152,49153,98304}) {
            byte[] bytes=new byte[size];new java.util.Random(17).nextBytes(bytes);
            try(var content=new zeroecho.pki.impl.framework.x509.StreamingPemContent(new zeroecho.core.io.ImmutableByteContent(bytes),"X509 CRL",CancellationSignal.NONE)) {
                try(var input=content.openStream()) {
                    byte[] rendered=input.readAllBytes();assertEquals(content.length().orElseThrow(),rendered.length);
                    String armor=new String(rendered,java.nio.charset.StandardCharsets.US_ASCII);
                    String body=armor.replace("-----BEGIN X509 CRL-----\n", "").replace("-----END X509 CRL-----\n", "");
                    assertArrayEquals(bytes,java.util.Base64.getMimeDecoder().decode(body));assertEquals(-1,input.read());assertEquals(-1,input.read());

                }
            }
        }
        var closed=new zeroecho.pki.impl.framework.x509.StreamingPemContent(new zeroecho.core.io.ImmutableByteContent(new byte[]{1}),"X509 CRL",CancellationSignal.NONE);
        closed.close();assertThrows(java.io.IOException.class,closed::openStream);
        try(var cancelled=new zeroecho.pki.impl.framework.x509.StreamingPemContent(new zeroecho.core.io.ImmutableByteContent(new byte[]{1}),"X509 CRL",()->true)) {
            assertThrows(java.io.IOException.class,cancelled::openStream);
        }
    }
    /**
     * Exports large CRL and generic native without certificate buffer limit.
     *
     * @param directory isolated temporary test directory supplied by JUnit
     * @throws Exception if fixture setup, execution, or cleanup fails
     */
    @Test void exportsLargeCrlAndGenericNativeWithoutCertificateBufferLimit(@TempDir Path directory) throws Exception {
        var keys = java.security.KeyPairGenerator.getInstance("RSA"); keys.initialize(2048); var pair = keys.generateKeyPair();
        var now = java.time.Instant.parse("2026-01-01T00:00:00Z");
        var builder = new org.bouncycastle.cert.X509v2CRLBuilder(new org.bouncycastle.asn1.x500.X500Name("CN=Large CRL"), java.util.Date.from(now));
        builder.setNextUpdate(java.util.Date.from(now.plusSeconds(3600)));
        for(int index=1;index<=60000;index++)builder.addCRLEntry(java.math.BigInteger.valueOf(index),java.util.Date.from(now),1);
        byte[] der=builder.build(new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withRSA").build(pair.getPrivate())).getEncoded();
        assertTrue(der.length>1024*1024,"fixture must exceed the certificate exporter limit");
        try(var store=new FilesystemPkiStore(directory,FsPkiStoreOptions.defaults())) {
            var fixture=new IntermediateIssuanceFixture();fixture.initialize(store);
            var framework=new BcX509CredentialFramework(fixture.base.signing,fixture.base.verifier);
            var repository=new DefaultPkiRepository(store,()->{},List.of(framework));
            var reference=PkiTestRuntime.fixtureReference(store.stagedContent(),Encoding.DER,der);
            var id=new PkiId("large:crl");
            store.putStatusObject(new StatusObject(id,new FormatId("x509"),IntermediateCreationFixture.CA,StatusObjectType.CRL,now,Optional.empty(),reference,new zeroecho.pki.impl.core.attr.SimpleAttributeSet(List.of())));
            assertEquals(List.of("original","pem"),repository.statusRepresentations(id).stream().map(value->value.id()).toList());
            for(String representation:List.of("original","pem")) {
                try(var lease=repository.openStatusObject(id,representation,CancellationSignal.NONE);var input=lease.openStream()) {
                    byte[] bytes=input.readAllBytes();assertEquals(lease.length(),bytes.length);
                    assertEquals(lease.sha256(),java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(bytes)));
                    var crl=(java.security.cert.X509CRL)java.security.cert.CertificateFactory.getInstance("X.509").generateCRL(new java.io.ByteArrayInputStream(bytes));
                    crl.verify(pair.getPublic());assertArrayEquals(der,crl.getEncoded());
                }
            }
            var generic=new PkiId("opaque:status");
            store.putStatusObject(new StatusObject(generic,new FormatId("opaque"),IntermediateCreationFixture.CA,StatusObjectType.CRL,now,Optional.empty(),reference,new zeroecho.pki.impl.core.attr.SimpleAttributeSet(List.of())));
            assertEquals(List.of("original"),repository.statusRepresentations(generic).stream().map(value->value.id()).toList());
            try(var lease=repository.openStatusObject(generic,"original",CancellationSignal.NONE);var input=lease.openStream()){assertArrayEquals(der,input.readAllBytes());}
            assertThrows(UnsupportedOperationException.class,()->repository.openStatusObject(id,"unknown",CancellationSignal.NONE));
            assertThrows(java.io.IOException.class,()->repository.openStatusObject(id,"pem",()->true));
        }
    }
}
