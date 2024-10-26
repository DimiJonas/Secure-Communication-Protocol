package dstp.crypto;

import dstp.config.DSTPConfig;
import dstp.config.TestConfigBuilder;
import dstp.util.Utils;
import org.junit.jupiter.api.Test;

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;

import static dstp.util.Utils.hexToBytes;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class DefaultCryptoProviderTest {

    @Test
    public void testAES_CTR_crypto() throws GeneralSecurityException {
        String testString = "Hello, World!";
        System.out.println("original String: " + testString);
        DSTPConfig config = new TestConfigBuilder()
                .generateSymmetricKey("AES/CTR/NoPadding", 128)
                .generateIv(16)
                .setIntegrity("hash")
                .setH("SHA-256")
                .build();
        CryptoProvider cryptoProvider = CryptoProviderFactory.createProvider(config);
        byte[] encryptedBytes = cryptoProvider.encrypt(testString.getBytes(), hexToBytes(config.getSymmetric_key()));
        String testStringEncrypted = new String(encryptedBytes);
        System.out.println("encrypted String: " + testStringEncrypted);
        byte[] decryptedBytes = cryptoProvider.decrypt(encryptedBytes, hexToBytes(config.getSymmetric_key()));
        String testStringDecrypted = new String(decryptedBytes);
        System.out.println("decrypted String: " + testStringDecrypted);
        assertEquals(testString, testStringDecrypted);
    }
}
