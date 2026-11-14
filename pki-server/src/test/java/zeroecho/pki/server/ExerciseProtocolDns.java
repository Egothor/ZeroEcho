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

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.server.http.StrictJson;

/** Test-only loopback TXT responder; no recursion, forwarding, network publication or key access. */
public final class ExerciseProtocolDns {
    private ExerciseProtocolDns() { }
    /**
     * Serves bounded fixture-owned DNS-01 TXT proof for at most four hours on loopback53535.
     * @param arguments private fixture root, nonce and exact exercise run ID
     * @throws Exception if ownership or the local bounded UDP listener cannot be established
     */
    public static void main(String[] arguments)throws Exception {
        if(arguments.length!=3||!arguments[1].matches("[0-9a-f]{32}")||!arguments[2].matches("[0-9a-f]{32}"))throw new IllegalArgumentException("Owned DNS fixture arguments required");
        Path root=Path.of(arguments[0]);
        var owner=(PkiOperationValue.ObjectValue)StrictJson.parse(Files.readAllBytes(root.resolve(".exercise-owner.json")),4096);
        if(!owner.fields().get("nonce").equals(new PkiOperationValue.Text(arguments[1])))throw new IllegalArgumentException("DNS fixture owner differs");
        try(var socket=new DatagramSocket(53535,InetAddress.getLoopbackAddress())) {
            socket.setSoTimeout(500);System.out.println("PROTOCOL_DNS_READY");System.out.flush();
            long until=System.nanoTime()+Duration.ofHours(4).toNanos();
            while(System.nanoTime()<until) {
                byte[] buffer=new byte[512];var request=new DatagramPacket(buffer,buffer.length);
                try {socket.receive(request);}catch(java.net.SocketTimeoutException idle){continue;}
                byte[] reply=response(root,arguments[1],arguments[2],java.util.Arrays.copyOf(buffer,request.getLength()));
                if(reply!=null)socket.send(new DatagramPacket(reply,reply.length,request.getSocketAddress()));
            }
        }
    }
    static byte[] response(Path root,String nonce,String runId,byte[] query)throws Exception {
        if(query.length<17||query.length>256||query[4]!=0||query[5]!=1||(query[2]&0x80)!=0)return null;
        int position=12;var name=new StringBuilder();
        while(position<query.length) {
            int size=query[position++]&255;if(size==0)break;
            if(size>63||position+size>query.length)return null;
            if(!name.isEmpty())name.append('.');
            for(int index=0;index<size;index++){int value=query[position++]&255;if(value<33||value>126)return null;name.append((char)value);}
        }
        if(position+4>query.length)return null;int type=(query[position]&255)*256+(query[position+1]&255),kind=(query[position+2]&255)*256+(query[position+3]&255);position+=4;
        String value=null;Path record=root.resolve("config/protocol-dns.json");
        if(Files.isRegularFile(record,java.nio.file.LinkOption.NOFOLLOW_LINKS)&&Files.size(record)<4096) {
            var document=((PkiOperationValue.ObjectValue)StrictJson.parse(Files.readAllBytes(record),4096)).fields();
            if(document.get("nonce").equals(new PkiOperationValue.Text(nonce))&&document.get("runId").equals(new PkiOperationValue.Text(runId))
                    &&document.get("name") instanceof PkiOperationValue.Text expected&&name.toString().equalsIgnoreCase(expected.value())
                    &&expected.value().matches("_acme-challenge\\.[a-z0-9-]+\\.example\\.invalid")&&document.get("value") instanceof PkiOperationValue.Text txt&&txt.value().matches("[A-Za-z0-9_-]{43}")&&(type==16||type==255)&&kind==1)value=txt.value();
        }
        var bytes=new java.io.ByteArrayOutputStream();var output=new java.io.DataOutputStream(bytes);
        output.write(query,0,2);output.writeShort(0x8180);output.writeShort(1);output.writeShort(value==null?0:1);output.writeShort(0);output.writeShort(0);output.write(query,12,position-12);
        if(value!=null){byte[] text=value.getBytes(java.nio.charset.StandardCharsets.US_ASCII);output.writeShort(0xc00c);output.writeShort(16);output.writeShort(1);output.writeInt(1);output.writeShort(text.length+1);output.writeByte(text.length);output.write(text);}
        return bytes.toByteArray();
    }
}
