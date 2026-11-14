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
package zeroecho.pki.impl.framework.x509;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Objects;
import java.util.OptionalLong;
import java.util.concurrent.atomic.AtomicBoolean;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.RepeatableContent;

/** Repeatable bounded-memory PEM encoding which retains ownership of immutable DER content. */
public final class StreamingPemContent implements RepeatableContent {
    private final RepeatableContent source;
    private final byte[] header;
    private final byte[] footer;
    private final long length;
    private final CancellationSignal cancellation;
    private final AtomicBoolean closed=new AtomicBoolean();
    /**
     * Takes ownership of DER content and exposes a repeatable PEM stream with 64-column lines.
     * @param source immutable DER source; closed when this content closes
     * @param label fixed format-owned armor label
     * @param cancellation shared cooperative cancellation checked on each bounded chunk
     * @throws IllegalArgumentException if the source length or armor label is invalid
     */
    public StreamingPemContent(RepeatableContent source,String label,CancellationSignal cancellation) {
        this.source=Objects.requireNonNull(source,"source");this.cancellation=Objects.requireNonNull(cancellation,"cancellation");
        if(label==null||!label.matches("[A-Z0-9 ]{1,48}"))throw new IllegalArgumentException("Invalid PEM label");
        long bytes=source.length().orElseThrow(() -> new IllegalArgumentException("PEM source length is required"));
        if(bytes<1)throw new IllegalArgumentException("Empty PEM source");
        header=("-----BEGIN "+label+"-----\n").getBytes(StandardCharsets.US_ASCII);
        footer=("-----END "+label+"-----\n").getBytes(StandardCharsets.US_ASCII);
        long characters=Math.multiplyExact(Math.addExact(bytes,2)/3,4);
        length=Math.addExact(header.length+footer.length,Math.addExact(characters,Math.addExact(characters,63)/64));
    }
    /** @return new independently positioned reader; retains at most one 48-KiB input chunk and its encoding */
    @Override public InputStream openStream()throws IOException {
        if(closed.get())throw new IOException("PEM content lease closed");cancellation.throwIfCancelled();
        return new PemStream(source.openStream());
    }
    /** @return exact PEM byte length including armor and line endings */
    @Override public OptionalLong length(){return OptionalLong.of(length);}
    /** @return non-secret format/content identity */
    @Override public String contentId(){return "pem:"+source.contentId();}
    /** Releases the owned source exactly once. @throws IOException if source release fails */
    @Override public void close()throws IOException {if(closed.compareAndSet(false,true))source.close();}
    private final class PemStream extends InputStream {
        private final InputStream input;
        private final byte[] raw=new byte[48*1024];
        private byte[] segment=header;
        private int offset;
        private boolean newline;
        private boolean ended;
        private boolean footerWritten;
        private boolean readerClosed;
        PemStream(InputStream input){this.input=input;}
        private boolean advance()throws IOException {
            if(readerClosed)throw new IOException("PEM reader closed");
            cancellation.throwIfCancelled();if(closed.get())throw new IOException("PEM content lease closed");
            if(offset<segment.length)return true;
            if(footerWritten)return false;
            offset=0;
            if(newline){newline=false;segment=new byte[]{'\n'};return true;}
            if(!ended) {
                int count=0;
                while(count<raw.length) {cancellation.throwIfCancelled();int read=input.read(raw,count,raw.length-count);if(read==-1){ended=true;break;}count+=read;}
                if(count>0) {segment=Base64.getMimeEncoder(64,new byte[]{'\n'}).encode(count==raw.length?raw:java.util.Arrays.copyOf(raw,count));newline=true;return true;}
            }
            if(!footerWritten){footerWritten=true;segment=footer;return true;}
            return false;
        }
        @Override public int read()throws IOException {return advance()?segment[offset++]&255:-1;}
        @Override public int read(byte[] buffer,int start,int size)throws IOException {
            Objects.checkFromIndexSize(start,size,buffer.length);if(size==0)return 0;int copied=0;
            while(copied<size&&advance()){int count=Math.min(size-copied,segment.length-offset);System.arraycopy(segment,offset,buffer,start+copied,count);offset+=count;copied+=count;}
            return copied==0?-1:copied;
        }
        @Override public void close()throws IOException {if(!readerClosed){readerClosed=true;input.close();}}
    }
}
