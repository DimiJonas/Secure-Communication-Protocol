package crypto;

import crypto.CryptoProvider;
import crypto.CryptoProviderFactory;
import dstp.config.DSTPConfig;
import dstp.config.TestConfigBuilder;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;

import static util.Utils.hexToBytes;
import static org.junit.jupiter.api.Assertions.*;

public class DefaultCryptoProviderTest {

    @Test
    void testEncryption_AES_CTR() throws GeneralSecurityException, InvalidCipherTextException {
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
    void testEncryption_AES_CTR_1mbfile() throws GeneralSecurityException, IOException, InvalidCipherTextException {
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
    void testIntegrity_Hash_Sha256() throws GeneralSecurityException {
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
    void testIntegrity_MAC_HMACSha512() throws GeneralSecurityException {
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

    @ParameterizedTest
    @ValueSource(ints = {128, 192, 256})
    void testAES_CTR_nopadding(int keysize) throws GeneralSecurityException, IOException, InvalidCipherTextException {
        byte[] one_mb_file = Files.readAllBytes(Path.of("src/test/resources/1mb_file.txt"));
        DSTPConfig config = new TestConfigBuilder()
                .generateSymmetricKey("AES/CTR/NoPadding", keysize)
                .generateIv(16)
                .setIntegrity("hash")
                .setH("SHA-256")
                .build();
        CryptoProvider cryptoProvider = CryptoProviderFactory.createProvider(config);
        byte[] encryptedBytes = cryptoProvider.encrypt(one_mb_file, hexToBytes(config.getSymmetric_key()));
        byte[] decryptedBytes = cryptoProvider.decrypt(encryptedBytes, hexToBytes(config.getSymmetric_key()));
        assertArrayEquals(one_mb_file, decryptedBytes);
    }

    @ParameterizedTest
    @ValueSource(ints = {128, 192, 256})
    void testAES_GCM_nopadding(int keysize) throws GeneralSecurityException, IOException, InvalidCipherTextException {
        byte[] one_mb_file = Files.readAllBytes(Path.of("src/test/resources/1mb_file.txt"));
        DSTPConfig config = new TestConfigBuilder()
                .generateSymmetricKey("AES/GCM/NoPadding", keysize)
                .generateIv(16)
                .setIntegrity("hash")
                .setH("SHA-256")
                .build();
        CryptoProvider cryptoProvider = CryptoProviderFactory.createProvider(config);
        byte[] encryptedBytes = cryptoProvider.encrypt(one_mb_file, hexToBytes(config.getSymmetric_key()));
        byte[] decryptedBytes = cryptoProvider.decrypt(encryptedBytes, hexToBytes(config.getSymmetric_key()));
        assertArrayEquals(one_mb_file, decryptedBytes);
    }

    @ParameterizedTest
    @ValueSource(ints = {64, 112, 128, 168, 256, 448})
    void testBLF_ECB_PKCS5(int keysize) throws GeneralSecurityException, IOException, InvalidCipherTextException {
        byte[] one_mb_file = Files.readAllBytes(Path.of("src/test/resources/1mb_file.txt"));
        DSTPConfig config = new TestConfigBuilder()
                .generateSymmetricKey("BLOWFISH/ECB/PKCS5Padding", keysize)
                .generateIv(16)
                .setIntegrity("hash")
                .setH("SHA-256")
                .build();
        CryptoProvider cryptoProvider = CryptoProviderFactory.createProvider(config);
        byte[] encryptedBytes = cryptoProvider.encrypt(one_mb_file, hexToBytes(config.getSymmetric_key()));
        byte[] decryptedBytes = cryptoProvider.decrypt(encryptedBytes, hexToBytes(config.getSymmetric_key()));
        assertArrayEquals(one_mb_file, decryptedBytes);
    }

    @ParameterizedTest
    @ValueSource(ints = {64, 112, 128, 168, 256, 448})
    void testBLF_CBC_PKCS5(int keysize) throws GeneralSecurityException, IOException, InvalidCipherTextException {
        byte[] one_mb_file = Files.readAllBytes(Path.of("src/test/resources/1mb_file.txt"));
        DSTPConfig config = new TestConfigBuilder()
                .generateSymmetricKey("BLOWFISH/CBC/PKCS5Padding", keysize)
                .generateIv(8)
                .setIntegrity("hash")
                .setH("SHA-256")
                .build();
        CryptoProvider cryptoProvider = CryptoProviderFactory.createProvider(config);
        byte[] encryptedBytes = cryptoProvider.encrypt(one_mb_file, hexToBytes(config.getSymmetric_key()));
        byte[] decryptedBytes = cryptoProvider.decrypt(encryptedBytes, hexToBytes(config.getSymmetric_key()));
        assertArrayEquals(one_mb_file, decryptedBytes);
    }

    @ParameterizedTest
    @ValueSource(ints = {64, 112, 128, 168, 256, 448})
    void testRC4(int keysize) throws GeneralSecurityException, IOException, InvalidCipherTextException {
        byte[] one_mb_file = Files.readAllBytes(Path.of("src/test/resources/1mb_file.txt"));
        DSTPConfig config = new TestConfigBuilder()
                .generateSymmetricKey("RC4", keysize)
                .generateIv(8)
                .setIntegrity("hash")
                .setH("SHA-256")
                .build();
        CryptoProvider cryptoProvider = CryptoProviderFactory.createProvider(config);
        byte[] encryptedBytes = cryptoProvider.encrypt(one_mb_file, hexToBytes(config.getSymmetric_key()));
        byte[] decryptedBytes = cryptoProvider.decrypt(encryptedBytes, hexToBytes(config.getSymmetric_key()));
        assertArrayEquals(one_mb_file, decryptedBytes);
    }

    @ParameterizedTest
    @ValueSource(ints = {112, 168})
    void testDESede_CBC_PKCS5Padding(int keysize) throws GeneralSecurityException, IOException, InvalidCipherTextException {
        byte[] one_mb_file = Files.readAllBytes(Path.of("src/test/resources/1mb_file.txt"));
        DSTPConfig config = new TestConfigBuilder()
                .generateSymmetricKey("DESede/CBC/PKCS5Padding", keysize)
                .generateIv(8)
                .setIntegrity("hash")
                .setH("SHA-256")
                .build();
        CryptoProvider cryptoProvider = CryptoProviderFactory.createProvider(config);
        byte[] encryptedBytes = cryptoProvider.encrypt(one_mb_file, hexToBytes(config.getSymmetric_key()));
        byte[] decryptedBytes = cryptoProvider.decrypt(encryptedBytes, hexToBytes(config.getSymmetric_key()));
        assertArrayEquals(one_mb_file, decryptedBytes);
    }

    @ParameterizedTest
    @ValueSource(strings = {"MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512", "SHA3-256"})
    void testIntegrity_Hashes(String hashAlgorithm) throws GeneralSecurityException, IOException {
        byte[] one_mb_file = Files.readAllBytes(Path.of("src/test/resources/1mb_file.txt"));
        DSTPConfig config = new TestConfigBuilder()
                .generateSymmetricKey("AES/CTR/NoPadding", 128)
                .generateIv(16)
                .setIntegrity("hash")
                .setH(hashAlgorithm)
                .build();
        CryptoProvider cryptoProvider = CryptoProviderFactory.createProvider(config);

        byte[] hashBytes = cryptoProvider.generateIntegrityCheck(one_mb_file, hexToBytes(config.getMackey()));

        assertTrue(cryptoProvider.verifyIntegrityCheck(one_mb_file, hashBytes, hexToBytes(config.getMackey())));
    }

    @ParameterizedTest
    @ValueSource(strings = {"HMACSHA512", "HMACSHA384", "HMACSHA256", "HMACSHA3-512"})
    void testIntegrity_MACs(String macAlgorithm) throws GeneralSecurityException, IOException {
        byte[] one_mb_file = Files.readAllBytes(Path.of("src/test/resources/1mb_file.txt"));
        DSTPConfig config = new TestConfigBuilder()
                .generateSymmetricKey("AES/CTR/NoPadding", 128)
                .generateIv(16)
                .setIntegrity("mac")
                .setMacAlgorithm(macAlgorithm)
                .generateMacKey(macAlgorithm, 256)
                .build();
        CryptoProvider cryptoProvider = CryptoProviderFactory.createProvider(config);

        byte[] hashBytes = cryptoProvider.generateIntegrityCheck(one_mb_file, hexToBytes(config.getMackey()));

        assertTrue(cryptoProvider.verifyIntegrityCheck(one_mb_file, hashBytes, hexToBytes(config.getMackey())));
    }

    @ParameterizedTest
    @ValueSource(ints = {256})
    void testChaCha20_poly1305(int keysize) throws IOException, GeneralSecurityException, InvalidCipherTextException {
        byte[] one_mb_file = Files.readAllBytes(Path.of("src/test/resources/1mb_file.txt"));
        System.out.println("original bytes length: " + one_mb_file.length);
        DSTPConfig config = new TestConfigBuilder()
                .generateSymmetricKey("ChaCha20", keysize)
                .setAlgorithm("ChaCha20-Poly1305")
                .generateIv(16)
                .build();
        CryptoProvider cryptoProvider = CryptoProviderFactory.createProvider(config);
        byte[] encryptedBytes = cryptoProvider.encrypt(one_mb_file, hexToBytes(config.getSymmetric_key()));
        System.out.println("encrypted bytes length: " + encryptedBytes.length);
        byte[] decryptedBytes = cryptoProvider.decrypt(encryptedBytes, hexToBytes(config.getSymmetric_key()));
        System.out.println("decrypted bytes length: " + decryptedBytes.length);
        assertArrayEquals(one_mb_file, decryptedBytes);
    }
}
