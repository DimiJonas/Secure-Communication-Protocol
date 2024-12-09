package crypto;

import dstp.config.DSTPConfig;

public class CryptoProviderFactory {
    /**
     * Creates a default crypto provider using javax.crypto
     * @param config
     * @return
     */
    public static CryptoProvider createProvider(DSTPConfig config) {
        return new DefaultCryptoProvider(
                config
        );
    }

    /**
     * Creates a Bouncycastle crypto provider
     * @param config
     * @return
     */
    public static CryptoProvider createBouncyCastleProvider(DSTPConfig config) {
        return new BouncyCastleCryptoProvider(
                config
        );
    }
}