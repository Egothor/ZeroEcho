package zeroecho.pki.impl.crypto.zeroecholib;

import zeroecho.core.spi.KeyringUnlockProvider;
import zeroecho.core.storage.KeyringPassword;

public final class TestKeyringUnlocks {
    private TestKeyringUnlocks() {
    }

    public static KeyringUnlockProvider provider() {
        return () -> new KeyringPassword(
                new char[] { 'p', 'k', 'i', '-', 't', 'e', 's', 't', '-', 'k', 'e', 'y' });
    }
}
