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
package zeroecho.pki.server.acme;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.server.spi.AcmeChallengeProvider;
import zeroecho.pki.spi.ProviderConfig;

/** Exercises the public DNS provider through actual loopback UDP and the JDK JNDI DNS adapter. */
class JndiDns01ChallengeProviderTest {
    private static final String AUTHORIZATION="A".repeat(43)+"."+"B".repeat(43);

    @Test void actualJndiUnquotedSingleTxtValidates() throws Exception {
        try(var dns=new Dns(List.of(List.of(expected())))) {
            var result=validate(dns,43,1);
            assertTrue(result.valid(),result.classification());
            assertTrue(dns.type.get()==16||dns.type.get()==255,"Actual JNDI must have queried DNS");
        }
    }

    @Test void existingQuotedMultipleChunksRetainTheirCanonicalMeaning() throws Exception {
        String expected=expected();
        var parser=JndiDns01ChallengeProvider.class.getDeclaredMethod("txt",String.class);
        parser.setAccessible(true);
        assertEquals(expected,parser.invoke(null,"\""+expected.substring(0,20)+"\" \""+expected.substring(20)+"\""));
    }

    static Stream<String> invalidPresentations() {
        return Stream.of("not-the-proof","", "abc def", "abc\tdef", "abc\ndef", "abc\\def", "abc\"def", "é");
    }

    @ParameterizedTest @MethodSource("invalidPresentations")
    void invalidOrMismatchedDnsTextNeverValidates(String text) throws Exception {
        try(var dns=new Dns(List.of(List.of(text)))) {
            assertFalse(validate(dns,256,1).valid());
        }
    }

    @Test void decodedRecordByteBoundStillApplies() throws Exception {
        try(var dns=new Dns(List.of(List.of(expected()+"x")))) {
            var result=validate(dns,43,1);
            assertFalse(result.valid());assertEquals("DNS_VALIDATION_FAILED",result.classification());
        }
    }

    @Test void recordCountBoundStillAppliesEvenWhenOneValueMatches() throws Exception {
        try(var dns=new Dns(List.of(List.of(expected()),List.of("x".repeat(43))))) {
            var result=validate(dns,43,1);
            assertFalse(result.valid());assertEquals("DNS_VALIDATION_FAILED",result.classification());
        }
    }

    private static String expected() throws Exception {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(AUTHORIZATION.getBytes(StandardCharsets.US_ASCII)));
    }

    private static AcmeChallengeProvider.Result validate(Dns dns,int maximumBytes,int maximumRecords) {
        Instant now=Instant.now();
        var context=new AcmeChallengeProvider.Context("directory:test","authorization:test",
            new AcmeState.Identifier(AcmeState.IdentifierType.DNS,"example.test",false),AcmeState.ChallengeType.DNS_01,
            "A".repeat(43),AUTHORIZATION,1,now,now.plusSeconds(5));
        var configuration=new ProviderConfig(JndiDns01ChallengeProvider.ID,Map.of("providerUrl","dns://127.0.0.1:"+dns.socket.getLocalPort(),
            "timeoutMillis","500","maximumRecords",Integer.toString(maximumRecords),"maximumRecordBytes",Integer.toString(maximumBytes),"maximumCnameDepth","0"));
        return new JndiDns01ChallengeProvider().validate(context,configuration,CancellationSignal.NONE);
    }

    private static final class Dns implements AutoCloseable {
        private final DatagramSocket socket;
        private final Thread worker;
        private final AtomicInteger type=new AtomicInteger();
        Dns(List<List<String>> records) throws Exception {
            socket=new DatagramSocket(0,InetAddress.getByName("127.0.0.1"));
            socket.setSoTimeout(250);
            worker=new Thread(()->{
                while(!socket.isClosed())try {
                    var packet=new DatagramPacket(new byte[512],512);socket.receive(packet);
                    byte[] query=java.util.Arrays.copyOf(packet.getData(),packet.getLength());
                    int end=12;
                    while((query[end]&255)!=0)end+=1+(query[end]&255);
                    end++;type.set((query[end]&255)*256+(query[end+1]&255));end+=4;
                    var bytes=new ByteArrayOutputStream();var output=new DataOutputStream(bytes);
                    output.write(query,0,2);output.writeShort(0x8180);output.writeShort(1);output.writeShort(records.size());output.writeShort(0);output.writeShort(0);
                    output.write(query,12,end-12);
                    for(var chunks:records) {
                        var content=new ByteArrayOutputStream();
                        for(String chunk:chunks){byte[] raw=chunk.getBytes(StandardCharsets.UTF_8);content.write(raw.length);content.write(raw);}
                        byte[] raw=content.toByteArray();
                        output.writeShort(0xc00c);output.writeShort(16);output.writeShort(1);output.writeInt(0);output.writeShort(raw.length);output.write(raw);
                    }
                    byte[] answer=bytes.toByteArray();socket.send(new DatagramPacket(answer,answer.length,packet.getSocketAddress()));
                } catch(java.net.SocketTimeoutException timeout) {
                    // Periodic wakeup permits deterministic close without another query.
                } catch(Exception failure) {if(!socket.isClosed())throw new AssertionError(failure);}
            },"test-jndi-dns");
            worker.setDaemon(true);worker.start();
        }
        @Override public void close() {socket.close();try {worker.join(1000);}catch(InterruptedException failure){Thread.currentThread().interrupt();throw new AssertionError(failure);}assertFalse(worker.isAlive());}
    }
}
