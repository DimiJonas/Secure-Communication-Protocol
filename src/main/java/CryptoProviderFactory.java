import config.DSTPConfig;

public class CryptoProviderFactory {
    public static CryptoProvider createProvider(DSTPConfig config) {
        return new DefaultCryptoProvider(
                config.getConfidentiality().getAlgorithm(),
                config.getMac().getAlgorithm()
        );
    }
}