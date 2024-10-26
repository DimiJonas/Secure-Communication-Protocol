package dstp.crypto;

import dstp.config.DSTPConfig;

public class CryptoProviderFactory {
    public static CryptoProvider createProvider(DSTPConfig config) {
        return new DefaultCryptoProvider(
                config
        );
    }
}