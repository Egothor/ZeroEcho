package zeroecho;

import zeroecho.core.spi.KeyringUnlockProvider;
import zeroecho.core.storage.KeyringPassword;

final class TestKeyringUnlocks {
    private TestKeyringUnlocks() {
    }

    static KeyringUnlockProvider provider() {
        return () -> new KeyringPassword(new char[] { 't', 'e', 's', 't', '-', 'k', 'e', 'y', 'r', 'i', 'n', 'g' });
    }
}
