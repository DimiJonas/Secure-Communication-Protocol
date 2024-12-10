package crypto;

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

import static org.junit.jupiter.api.Assertions.*;
import static util.ByteUtils.hexToBytes;

public class BouncyCastleCryptoProviderTest {

    @ParameterizedTest
    @ValueSource(ints = {64, 112, 128, 168, 256, 448})
    void testRC6_CBC_PKCS5(int keysize) throws GeneralSecurityException, IOException, InvalidCipherTextException {
        byte[] one_mb_file = Files.readAllBytes(Path.of("src/test/resources/1mb_file.txt"));
        DSTPConfig config = new TestConfigBuilder()
                .generateSymmetricKey("BLOWFISH", keysize)
                .setAlgorithm("RC6/CBC/PKCS5Padding")
                .generateIv(16)
                .setIntegrity("hash")
                .setH("SHA-256")
                .build();
        CryptoProvider cryptoProvider = CryptoProviderFactory.createBouncyCastleProvider(config);
        byte[] encryptedBytes = cryptoProvider.encrypt(one_mb_file, hexToBytes(config.getSymmetric_key()));
        byte[] decryptedBytes = cryptoProvider.decrypt(encryptedBytes, hexToBytes(config.getSymmetric_key()));
        assertArrayEquals(one_mb_file, decryptedBytes);
    }

    @ParameterizedTest
    @ValueSource(ints = {64, 112, 128, 168, 256, 448})
    void testRC6_OFB_NoPadding(int keysize) throws GeneralSecurityException, IOException, InvalidCipherTextException {
        byte[] one_mb_file = Files.readAllBytes(Path.of("src/test/resources/1mb_file.txt"));
        DSTPConfig config = new TestConfigBuilder()
                .generateSymmetricKey("BLOWFISH", keysize)
                .setAlgorithm("RC6/OFB/NoPadding")
                .generateIv(16)
                .setIntegrity("hash")
                .setH("SHA-256")
                .build();
        CryptoProvider cryptoProvider = CryptoProviderFactory.createBouncyCastleProvider(config);
        byte[] encryptedBytes = cryptoProvider.encrypt(one_mb_file, hexToBytes(config.getSymmetric_key()));
        byte[] decryptedBytes = cryptoProvider.decrypt(encryptedBytes, hexToBytes(config.getSymmetric_key()));
        assertArrayEquals(one_mb_file, decryptedBytes);
    }

    @ParameterizedTest
    @ValueSource(ints = {64, 112, 128, 168, 256, 448})
    void test_IDEA_CTR_NoPadding(int keysize) throws GeneralSecurityException, IOException, InvalidCipherTextException {
        byte[] one_mb_file = Files.readAllBytes(Path.of("src/test/resources/1mb_file.txt"));
        DSTPConfig config = new TestConfigBuilder()
                .generateSymmetricKey("BLOWFISH", keysize)
                .setAlgorithm("IDEA/CTR/NoPadding")
                .generateIv(8)
                .setIntegrity("hash")
                .setH("SHA-256")
                .build();
        CryptoProvider cryptoProvider = CryptoProviderFactory.createBouncyCastleProvider(config);
        byte[] encryptedBytes = cryptoProvider.encrypt(one_mb_file, hexToBytes(config.getSymmetric_key()));
        byte[] decryptedBytes = cryptoProvider.decrypt(encryptedBytes, hexToBytes(config.getSymmetric_key()));
        assertArrayEquals(one_mb_file, decryptedBytes);
    }

    @ParameterizedTest
    @ValueSource(strings = {"MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512", "SHA3-256", "RIPEMD320"})
    void testIntegrity_Hashes(String hashAlgorithm) throws GeneralSecurityException, IOException {
        byte[] one_mb_file = Files.readAllBytes(Path.of("src/test/resources/1mb_file.txt"));
        DSTPConfig config = new TestConfigBuilder()
                .generateSymmetricKey("AES/CTR/NoPadding", 128)
                .generateIv(16)
                .setIntegrity("hash")
                .setH(hashAlgorithm)
                .build();
        CryptoProvider cryptoProvider = CryptoProviderFactory.createBouncyCastleProvider(config);
        byte[] hashBytes = cryptoProvider.generateIntegrityCheck(one_mb_file, hexToBytes(config.getMackey()));
        assertTrue(cryptoProvider.verifyIntegrityCheck(one_mb_file, hashBytes, hexToBytes(config.getMackey())));
    }

    @ParameterizedTest
    @ValueSource(strings = {"HMACSHA512", "HMACSHA384", "HMACSHA256", "HMACSHA3-512", "AESGMAC"})
    void testIntegrity_MACs(String macAlgorithm) throws GeneralSecurityException, IOException {
        byte[] one_mb_file = Files.readAllBytes(Path.of("src/test/resources/1mb_file.txt"));
        DSTPConfig config = new TestConfigBuilder()
                .generateSymmetricKey("AES/CTR/NoPadding", 128)
                .generateIv(16)
                .setIntegrity("mac")
                .setMacAlgorithm(macAlgorithm)
                .generateMacKey(macAlgorithm, 256)
                .build();
        CryptoProvider cryptoProvider = CryptoProviderFactory.createBouncyCastleProvider(config);
        byte[] hashBytes = cryptoProvider.generateIntegrityCheck(one_mb_file, hexToBytes(config.getMackey()));
        assertTrue(cryptoProvider.verifyIntegrityCheck(one_mb_file, hashBytes, hexToBytes(config.getMackey())));
    }

    @Test
    void testIntegrity_RC6GMAC() throws GeneralSecurityException, IOException {
        byte[] one_mb_file = Files.readAllBytes(Path.of("src/test/resources/1mb_file.txt"));
        DSTPConfig config = new TestConfigBuilder()
                .generateSymmetricKey("AES/CTR/NoPadding", 128)
                .generateIv(16)
                .setIntegrity("mac")
                .setMacAlgorithm("RC6GMAC")
                .build();
        config.setMackey(config.getSymmetric_key());
        config.setMackey_size(String.valueOf(config.getSymmetric_key_size()));
        CryptoProvider cryptoProvider = CryptoProviderFactory.createBouncyCastleProvider(config);
        byte[] hashBytes = cryptoProvider.generateIntegrityCheck(one_mb_file, hexToBytes(config.getMackey()));
        assertTrue(cryptoProvider.verifyIntegrityCheck(one_mb_file, hashBytes, hexToBytes(config.getMackey())));
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
