package dstp.crypto;

import dstp.config.DSTPConfig;
import dstp.config.TestConfigBuilder;
import dstp.util.Utils;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;

import static dstp.util.Utils.hexToBytes;
import static org.junit.jupiter.api.Assertions.*;

public class DefaultCryptoProviderTest {

    @Test
    public void testEncryption_AES_CTR() throws GeneralSecurityException {
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

    @Test
    public void testEncryption_AES_CTR_1mbfile() throws GeneralSecurityException, IOException {
        byte[] one_mb_file = Files.readAllBytes(Path.of("src/test/resources/1mb_file.txt"));
        System.out.println("original bytes length: " + one_mb_file.length);
        DSTPConfig config = new TestConfigBuilder()
                .generateSymmetricKey("AES/CTR/NoPadding", 128)
                .generateIv(16)
                .setIntegrity("hash")
                .setH("SHA-256")
                .build();
        CryptoProvider cryptoProvider = CryptoProviderFactory.createProvider(config);
        byte[] encryptedBytes = cryptoProvider.encrypt(one_mb_file, hexToBytes(config.getSymmetric_key()));
        System.out.println("encrypted bytes length: " + encryptedBytes.length);
        byte[] decryptedBytes = cryptoProvider.decrypt(encryptedBytes, hexToBytes(config.getSymmetric_key()));
        System.out.println("decrypted bytes length: " + decryptedBytes.length);
        assertArrayEquals(one_mb_file, decryptedBytes);
    }

    @Test
    public void testIntegrity_Hash_Sha256() throws GeneralSecurityException {
        DSTPConfig config = new TestConfigBuilder()
                .generateSymmetricKey("AES/CTR/NoPadding", 128)
                .generateIv(16)
                .setIntegrity("hash")
                .setH("SHA-256")
                .build();
        CryptoProvider cryptoProvider = CryptoProviderFactory.createProvider(config);
        String testString = "Hello, World!";
        System.out.println("original String: " + testString);

        byte[] hashBytes = cryptoProvider.generateIntegrityCheck(testString.getBytes(), hexToBytes(config.getMackey()));
        String hashString = new String(hashBytes);
        System.out.println("hashed String: " + hashString);

        assertTrue(cryptoProvider.verifyIntegrityCheck(testString.getBytes(), hashBytes, hexToBytes(config.getMackey())));
    }

    @Test
    public void testIntegrity_MAC_HMACSha512() throws GeneralSecurityException {
        DSTPConfig config = new TestConfigBuilder()
                .generateSymmetricKey("AES/CTR/NoPadding", 128)
                .generateIv(16)
                .setIntegrity("HMAC")
                .generateMacKey("HmacSHA512", 256)
                .build();
        CryptoProvider cryptoProvider = CryptoProviderFactory.createProvider(config);
        String testString = "Hello, World!";
        System.out.println("original String: " + testString);

        byte[] macBytes = cryptoProvider.generateIntegrityCheck(testString.getBytes(), hexToBytes(config.getMackey()));
        byte[] macBytes2 = cryptoProvider.generateIntegrityCheck(testString.getBytes(), hexToBytes(config.getMackey()));
        String hashString = new String(macBytes);
        System.out.println("hashed String: " + hashString);

        assertArrayEquals(macBytes, macBytes2);
        assertTrue(cryptoProvider.verifyIntegrityCheck(testString.getBytes(), macBytes, hexToBytes(config.getMackey())));
    }
}
