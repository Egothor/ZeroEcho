/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.core.audit;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import javax.crypto.SecretKey;

import org.junit.jupiter.api.Test;

class JulAuditListenerStdSecurityTest {
    private static final String SENSITIVE_TEXT = "controlled-sensitive-message";
    private static final AtomicInteger LOGGER_IDS = new AtomicInteger();

    @Test
    void keyLoggingUsesOnlySafeMetadataAndClearsPublicEncoding() {
        System.out.println("keyLoggingUsesOnlySafeMetadataAndClearsPublicEncoding");
        RecordingHandler handler = new RecordingHandler();
        JulAuditListenerStd listener = listener(handler);
        CountingSecretKey secretKey = new CountingSecretKey();
        CountingPrivateKey privateKey = new CountingPrivateKey();
        byte[] publicEncoding = { 1, 2, 3, 4 };
        PublicKey publicKey = new ControlledPublicKey(publicEncoding);

        listener.onKeyBuilt("secret", "provider", null, secretKey);
        listener.onKeyBuilt("private", "provider", null, privateKey);
        listener.onKeyBuilt("public", "provider", null, publicKey);

        assertEquals(0, secretKey.encodedCalls);
        assertEquals(0, privateKey.encodedCalls);
        assertArrayEquals(new byte[publicEncoding.length], publicEncoding);
        assertFalse(handler.rendered().contains(Arrays.toString(new byte[] { 1, 2, 3, 4 })));
        System.out.println("...records=" + handler.records.size());
        System.out.println("keyLoggingUsesOnlySafeMetadataAndClearsPublicEncoding...ok");
    }

    @Test
    void defaultFailureLoggingOmitsExceptionMessageAndThrowable() {
        System.out.println("defaultFailureLoggingOmitsExceptionMessageAndThrowable");
        RecordingHandler handler = new RecordingHandler();
        JulAuditListenerStd listener = listener(handler);

        listener.onFailure("context", "read", "attach", new IllegalStateException(SENSITIVE_TEXT));

        assertEquals(1, handler.records.size());
        assertFalse(handler.rendered().contains(SENSITIVE_TEXT));
        assertEquals(null, handler.records.get(0).getThrown());
        System.out.println("...failureRecords=1");
        System.out.println("defaultFailureLoggingOmitsExceptionMessageAndThrowable...ok");
    }

    private static JulAuditListenerStd listener(RecordingHandler handler) {
        Logger logger = Logger
                .getLogger(JulAuditListenerStdSecurityTest.class.getName() + "." + LOGGER_IDS.incrementAndGet());
        logger.setUseParentHandlers(false);
        logger.setLevel(Level.ALL);
        handler.setLevel(Level.ALL);
        logger.addHandler(handler);
        return JulAuditListenerStd.builder().logger(logger).build();
    }

    private static final class RecordingHandler extends Handler {
        private final List<LogRecord> records = new ArrayList<>();

        @Override
        public void publish(LogRecord record) {
            records.add(record);
        }

        @Override
        public void flush() {
            // No buffered state.
        }

        @Override
        public void close() {
            records.clear();
        }

        private String rendered() {
            StringBuilder result = new StringBuilder();
            for (LogRecord record : records) {
                result.append(record.getMessage());
                if (record.getParameters() != null) {
                    result.append(Arrays.toString(record.getParameters()));
                }
            }
            return result.toString();
        }
    }

    private static final class CountingSecretKey implements SecretKey {
        private static final long serialVersionUID = 1L;
        private int encodedCalls;

        @Override
        public String getAlgorithm() {
            return "CONTROLLED-SECRET";
        }

        @Override
        public String getFormat() {
            return "RAW";
        }

        @Override
        public byte[] getEncoded() {
            encodedCalls++;
            return SENSITIVE_TEXT.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        }
    }

    private static final class CountingPrivateKey implements PrivateKey {
        private static final long serialVersionUID = 1L;
        private int encodedCalls;

        @Override
        public String getAlgorithm() {
            return "CONTROLLED-PRIVATE";
        }

        @Override
        public String getFormat() {
            return "PKCS#8";
        }

        @Override
        public byte[] getEncoded() {
            encodedCalls++;
            return SENSITIVE_TEXT.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        }
    }

    private static final class ControlledPublicKey implements PublicKey {
        private static final long serialVersionUID = 1L;
        private final byte[] encoding;

        private ControlledPublicKey(byte[] encoding) {
            this.encoding = encoding;
        }

        @Override
        public String getAlgorithm() {
            return "CONTROLLED-PUBLIC";
        }

        @Override
        public String getFormat() {
            return "X.509";
        }

        @Override
        public byte[] getEncoded() {
            return encoding;
        }
    }
}
