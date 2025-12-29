/*******************************************************************************
 * Copyright (C) 2025, Leo Galambos
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
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
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
package zeroecho.pki.impl.audit;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AuditEvent;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;

/**
 * Internal codec for deterministic audit event identification and line-based
 * persistence encoding.
 *
 * <h2>Stable id</h2>
 * <p>
 * {@link #eventId(AuditEvent)} computes SHA-256 over canonical bytes from
 * {@link #canonicalBytes(AuditEvent)}. Canonicalization sorts
 * {@link AuditEvent#details()} keys to ensure deterministic output.
 * </p>
 *
 * <h2>Security</h2>
 * <ul>
 * <li>This codec does not log.</li>
 * <li>It assumes audit details have already been redacted by the caller (no
 * secrets).</li>
 * </ul>
 */
final class AuditEventCodec {

    private AuditEventCodec() {
    }

    /**
     * Computes a deterministic stable identifier for an audit event.
     *
     * @param event audit event (must not be null)
     * @return stable id
     * @throws IllegalArgumentException if {@code event} is null
     */
    /* default */ static PkiId eventId(AuditEvent event) {
        if (event == null) {
            throw new IllegalArgumentException("event must not be null");
        }
        byte[] bytes = canonicalBytes(event);
        byte[] digest = sha256(bytes);
        return new PkiId(toHex(digest));
    }

    /**
     * Produces canonical UTF-8 bytes used as input to stable hashing.
     *
     * @param event audit event (must not be null)
     * @return canonical bytes
     * @throws IllegalArgumentException if {@code event} is null
     */
    @SuppressWarnings("PMD")
    /* default */ static byte[] canonicalBytes(AuditEvent event) {
        if (event == null) {
            throw new IllegalArgumentException("event must not be null");
        }

        StringBuilder sb = new StringBuilder(256);
        sb.append("time=").append(event.time().toString()).append('\n');
        sb.append("category=").append(event.category()).append('\n');
        sb.append("action=").append(event.action()).append('\n');
        sb.append("principal.type=").append(event.principal().type()).append('\n');
        sb.append("principal.name=").append(event.principal().name()).append('\n');
        sb.append("purpose=").append(event.purpose().value()).append('\n');

        Optional<PkiId> objectId = event.objectId();
        sb.append("objectId=").append(objectId.isPresent() ? objectId.get().value() : "").append('\n');

        Optional<FormatId> formatId = event.formatId();
        sb.append("formatId=").append(formatId.isPresent() ? formatId.get().value() : "").append('\n');

        TreeMap<String, String> sorted = new TreeMap<String, String>();
        sorted.putAll(event.details());
        for (Map.Entry<String, String> e : sorted.entrySet()) {
            sb.append("d.").append(e.getKey()).append('=').append(e.getValue()).append('\n');
        }

        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Encodes an event into a deterministic single-line representation
     * (newline-terminated).
     *
     * @param event audit event (must not be null)
     * @return encoded line
     * @throws IllegalArgumentException if {@code event} is null
     */
    @SuppressWarnings("PMD")
    /* default */ static String encodeLine(AuditEvent event) {
        if (event == null) {
            throw new IllegalArgumentException("event must not be null");
        }

        StringBuilder sb = new StringBuilder(256);
        sb.append("t=").append(event.time().toString()).append('|');
        sb.append("c=").append(escape(event.category())).append('|');
        sb.append("a=").append(escape(event.action())).append('|');
        sb.append("pt=").append(escape(event.principal().type())).append('|');
        sb.append("pn=").append(escape(event.principal().name())).append('|');
        sb.append("pu=").append(escape(event.purpose().value())).append('|');
        sb.append("oid=").append(escape(event.objectId().isPresent() ? event.objectId().get().value() : ""))
                .append('|');
        sb.append("fid=").append(escape(event.formatId().isPresent() ? event.formatId().get().value() : ""))
                .append('|');

        TreeMap<String, String> sorted = new TreeMap<String, String>();
        sorted.putAll(event.details());

        boolean first = true;
        for (Map.Entry<String, String> e : sorted.entrySet()) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            sb.append(escape(e.getKey())).append('=').append(escape(e.getValue()));
        }

        sb.append('\n');
        return sb.toString();
    }

    /**
     * Decodes a single encoded line created by {@link #encodeLine(AuditEvent)}.
     *
     * @param line encoded line (must not be null or blank)
     * @return decoded event
     * @throws IllegalArgumentException if the input is malformed or missing
     *                                  required fields
     */
    /* default */ static AuditEvent decodeLine(String line) {
        if (line == null || line.isBlank()) {
            throw new IllegalArgumentException("line must not be null/blank");
        }

        String trimmed = line.strip();
        String[] parts = trimmed.split("\\|", -1);

        Instant time = Instant.parse(value(parts, "t"));
        String category = unescape(value(parts, "c"));
        String action = unescape(value(parts, "a"));

        Principal principal = new Principal(unescape(value(parts, "pt")), unescape(value(parts, "pn")));
        Purpose purpose = new Purpose(unescape(value(parts, "pu")));

        String oid = unescape(value(parts, "oid"));
        Optional<PkiId> objectId = oid.isBlank() ? Optional.empty() : Optional.of(new PkiId(oid));

        String fid = unescape(value(parts, "fid"));
        Optional<FormatId> formatId = fid.isBlank() ? Optional.empty() : Optional.of(new FormatId(fid));

        Map<String, String> details = decodeDetails(parts.length > 8 ? parts[8] : "");
        return new AuditEvent(time, category, action, principal, purpose, objectId, formatId, Map.copyOf(details));
    }

    private static Map<String, String> decodeDetails(String detailsPart) {
        Map<String, String> details = new TreeMap<>();
        if (detailsPart == null || detailsPart.isBlank()) {
            return details;
        }

        String[] kvs = detailsPart.split(",", -1);
        for (String kv : kvs) {
            int idx = kv.indexOf('=');
            if (idx <= 0) {
                continue;
            }
            String k = unescape(kv.substring(0, idx));
            String v = unescape(kv.substring(idx + 1));
            if (!k.isBlank()) {
                details.put(k, v);
            }
        }
        return details;
    }

    private static String value(String[] parts, String key) {
        String prefix = key + "=";
        for (String p : parts) {
            if (p.startsWith(prefix)) {
                return p.substring(prefix.length());
            }
        }
        throw new IllegalArgumentException("Missing required field: " + key);
    }

    private static String escape(String s) {
        String x = s.replace("\\", "\\\\");
        x = x.replace("|", "\\|");
        x = x.replace("\n", "\\n");
        x = x.replace("\r", "\\r");
        return x;
    }

    @SuppressWarnings("PMD")
    private static String unescape(String s) {
        StringBuilder out = new StringBuilder(s.length());
        boolean esc = false;
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            if (!esc) {
                if (ch == '\\') {
                    esc = true;
                } else {
                    out.append(ch);
                }
                continue;
            }
            esc = false;
            if (ch == 'n') {
                out.append('\n');
            } else if (ch == 'r') {
                out.append('\r');
            } else {
                out.append(ch);
            }
        }
        return out.toString();
    }

    private static byte[] sha256(byte[] input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(input);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 not available", ex);
        }
    }

    private static String toHex(byte[] bytes) {
        char[] hex = new char[bytes.length * 2];
        final char[] alphabet = "0123456789abcdef".toCharArray();
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            hex[i * 2] = alphabet[v >>> 4];
            hex[i * 2 + 1] = alphabet[v & 0x0F];
        }
        return new String(hex);
    }
}
