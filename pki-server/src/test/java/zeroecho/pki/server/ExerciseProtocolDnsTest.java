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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Hashtable;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import javax.naming.directory.InitialDirContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Actual JNDI multi-attribute lookup must receive the nonce-owned TXT proof. */
class ExerciseProtocolDnsTest {
    @Test
    void actualJndiTxtAndCnameLookupReceivesTxtForAnyQuery(@TempDir Path root) throws Exception {
        String nonce="a".repeat(32), token="b".repeat(43), name="_acme-challenge.probe.example.invalid";
        Files.createDirectory(root.resolve("config"));
        Files.writeString(root.resolve("config/protocol-dns.json"),"{\"nonce\":\""+nonce+"\",\"runId\":\""+nonce+"\",\"name\":\""+name+"\",\"value\":\""+token+"\"}");
        AtomicInteger queryType=new AtomicInteger();
        AtomicReference<Throwable> error=new AtomicReference<>();
        var socket=new DatagramSocket(0,InetAddress.getLoopbackAddress());
        try {
            Thread server=new Thread(()->{
                try {
                    byte[] buffer=new byte[512];var packet=new DatagramPacket(buffer,buffer.length);
                    socket.receive(packet);
                    byte[] query=java.util.Arrays.copyOf(buffer,packet.getLength());
                    queryType.set((query[query.length-4]&255)*256+(query[query.length-3]&255));
                    byte[] response=ExerciseProtocolDns.response(root,nonce,nonce,query);
                    socket.send(new DatagramPacket(response,response.length,packet.getSocketAddress()));
                } catch(Exception failure) {if(!socket.isClosed())error.set(failure);}
            },"qualification-dns-test");
            server.start();
            try {
                Hashtable<String,String> properties=new Hashtable<>();
                properties.put("java.naming.factory.initial","com.sun.jndi.dns.DnsContextFactory");
                properties.put("java.naming.provider.url","dns://127.0.0.1:"+socket.getLocalPort());
                properties.put("com.sun.jndi.dns.timeout.initial","1000");
                properties.put("com.sun.jndi.dns.timeout.retries","1");
                var context=new InitialDirContext(properties);
                try {
                    var attributes=context.getAttributes(name,new String[]{"TXT","CNAME"});
                    assertEquals(255,queryType.get());
                    assertNotNull(attributes.get("TXT"));
                    assertEquals(token,attributes.get("TXT").get());
                } finally {context.close();}
            } finally {
                socket.close();server.join(2000);
            }
            assertEquals(null,error.get());
        } finally {socket.close();}
    }
}
