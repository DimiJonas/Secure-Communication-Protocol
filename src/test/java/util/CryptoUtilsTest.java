package util;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.SecretKey;
import java.security.*;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class CryptoUtilsTest {

    @BeforeAll
    static void setUp() {
        // Ensure BouncyCastle provider is added
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    void testGenerateMac() throws GeneralSecurityException {
        byte[] data = "Hello, World!".getBytes();
        byte[] key = "testkey".getBytes();
        byte[] mac = CryptoUtils.generateMac(data, key);

        assertNotNull(mac);
        assertTrue(mac.length > 0);

        // Verify MAC is consistent for same input
        byte[] mac2 = CryptoUtils.generateMac(data, key);
        assertArrayEquals(mac, mac2);
    }

    @Test
    void testVerifyMac() throws GeneralSecurityException {
        byte[] data = "Hello, World!".getBytes();
        byte[] key = "testkey".getBytes();
        byte[] mac = CryptoUtils.generateMac(data, key);

        assertTrue(CryptoUtils.verifyMac(data, mac, key));

        // Test with incorrect data
        byte[] wrongData = "Hello, World?".getBytes();
        assertFalse(CryptoUtils.verifyMac(wrongData, mac, key));
    }

    @Test
    void testGenerateECCKeyPair() throws GeneralSecurityException {
        KeyPair keyPair = CryptoUtils.generateECCKeyPair();

        assertNotNull(keyPair);
        assertNotNull(keyPair.getPrivate());
        assertNotNull(keyPair.getPublic());
        assertEquals("EC", keyPair.getPrivate().getAlgorithm());
        assertEquals("EC", keyPair.getPublic().getAlgorithm());
    }

    @Test
    void testGenerateNonce() throws NoSuchAlgorithmException {
        int length = 16;
        byte[] nonce = CryptoUtils.generateNonce(length);

        assertEquals(length, nonce.length);

        // Verify nonces are not always the same
        byte[] nonce2 = CryptoUtils.generateNonce(length);
        assertFalse(Arrays.equals(nonce, nonce2));
    }

    @Test
    void testGenerateHash() throws NoSuchAlgorithmException {
        byte[] input = "test input".getBytes();
        byte[] hash = CryptoUtils.generateHash(input, CryptoUtils.SHA256_ALGORITHM);

        assertNotNull(hash);
        assertEquals(32, hash.length); // SHA-256 produces 256-bit (32-byte) hash

        // Verify hash is consistent
        byte[] hash2 = CryptoUtils.generateHash(input, CryptoUtils.SHA256_ALGORITHM);
        assertArrayEquals(hash, hash2);
    }

    @Test
    void testGeneratePasswordHash() throws NoSuchAlgorithmException {
        String password = "mypassword";
        String salt = "mysalt";
        byte[] passwordHash = CryptoUtils.generatePasswordHash(password, salt);

        assertNotNull(passwordHash);
        assertEquals(32, passwordHash.length); // SHA-256 hash
    }

    @Test
    void testPBEEncryptDecrypt() throws GeneralSecurityException {
        char[] password = "testpassword".toCharArray();
        SecretKey pbeKey = (SecretKey) CryptoUtils.generatePBEKey(password);

        byte[] originalData = "Secret message".getBytes();
        byte[] encryptedData = CryptoUtils.PBEEncrypt(originalData, pbeKey);

        assertNotNull(encryptedData);
        assertNotEquals(originalData.length, encryptedData.length);

        byte[] decryptedData = CryptoUtils.PBEDecrypt(encryptedData, pbeKey);
        assertArrayEquals(originalData, decryptedData);
    }

    @Test
    void testECIESEncryptDecrypt() throws GeneralSecurityException {
        KeyPair keyPair = CryptoUtils.generateECCKeyPair();
        byte[] originalData = "Secret ECIES message".getBytes();

        byte[] encryptedData = CryptoUtils.ECIESEncrypt(originalData, keyPair.getPublic());

        assertNotNull(encryptedData);
        assertNotEquals(originalData.length, encryptedData.length);

        byte[] decryptedData = CryptoUtils.ECIESDecrypt(encryptedData, keyPair.getPrivate());
        assertArrayEquals(originalData, decryptedData);
    }

    @Test
    void testReconstructECCKeyPair() throws GeneralSecurityException {
        KeyPair originalKeyPair = CryptoUtils.generateECCKeyPair();

        byte[] privateKeyBytes = originalKeyPair.getPrivate().getEncoded();
        byte[] publicKeyBytes = originalKeyPair.getPublic().getEncoded();

        PublicKey reconstructedPublicKey = CryptoUtils.reconstructECCPublicKeyFromBytes(publicKeyBytes);
        assertNotNull(reconstructedPublicKey);
        PrivateKey reconstructedPrivateKey = CryptoUtils.reconstructECCPrivateKeyFromBytes(privateKeyBytes);
        assertNotNull(reconstructedPrivateKey);

        assertArrayEquals(privateKeyBytes, reconstructedPrivateKey.getEncoded());
        assertArrayEquals(publicKeyBytes, reconstructedPublicKey.getEncoded());
    }

    @Test
    void testECDSASignatureVerification() throws GeneralSecurityException {
        KeyPair keyPair = CryptoUtils.generateECCKeyPair();
        byte[] data = "Test message for signature".getBytes();

        byte[] signature = CryptoUtils.generateECDSASignature(data, keyPair.getPrivate());

        assertNotNull(signature);

        // Verify signature
        assertTrue(CryptoUtils.verifyECDSASignature(data, signature, keyPair.getPublic()));

        // Verify signature fails with wrong data
        byte[] wrongData = "Different message".getBytes();
        assertFalse(CryptoUtils.verifyECDSASignature(wrongData, signature, keyPair.getPublic()));
    }
}
