package util;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import shp.client.ClientECCKeyPair;
import shp.server.ServerECCKeyPair;

import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;
import static util.ByteUtils.bytesToHex;
import static util.CryptoUtils.*;

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
        byte[] passwordHash = generatePasswordHash(password, salt);

        assertNotNull(passwordHash);
        assertEquals(32, passwordHash.length); // SHA-256 hash
    }

    @Test
    void testGeneratePBEKey_isDeterministic() throws GeneralSecurityException {
        byte[] passwordHash = generatePasswordHash("testpassword", "SHP");
        String passwordHashString = bytesToHex(passwordHash);
        Key pbeKey = generatePBEKey(passwordHashString.toCharArray());
        Key pbeKey2 = generatePBEKey(passwordHashString.toCharArray());
        assertArrayEquals(pbeKey.getEncoded(), pbeKey2.getEncoded());
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

    @Test
    void testGenerateDHParams() throws GeneralSecurityException {
//        DHParameterSpec dhParams = CryptoUtils.generateDHParams();
//        System.out.println(dhParams.getP());
//        System.out.println(dhParams.getG());
//        System.out.println(dhParams.getL());
//        assertNotNull(dhParams);
    }

    @Test
    void testGenerateDHKeyPairDefault() throws GeneralSecurityException {
        KeyPair keyPair = generateDHKeyPair();

        assertNotNull(keyPair, "KeyPair should not be null");
        assertNotNull(keyPair.getPrivate(), "Private key should not be null");
        assertNotNull(keyPair.getPublic(), "Public key should not be null");
        assertTrue(keyPair.getPrivate() instanceof PrivateKey, "Private key should be a PrivateKey");
        assertTrue(keyPair.getPublic() instanceof PublicKey, "Public key should be a PublicKey");
    }

    @Test
    void testDoDHKeyAgreement() throws GeneralSecurityException {
        // Generate two key pairs
        KeyPair aliceKeyPair = generateDHKeyPair();
        KeyPair bobKeyPair = generateDHKeyPair();

        // Perform key agreement
        byte[] aliceSharedSecret = doDHKeyAgreement(aliceKeyPair, bobKeyPair.getPublic());
        byte[] bobSharedSecret = doDHKeyAgreement(bobKeyPair, aliceKeyPair.getPublic());

        // Shared secrets should be the same
        assertNotNull(aliceSharedSecret, "Alice's shared secret should not be null");
        assertNotNull(bobSharedSecret, "Bob's shared secret should not be null");
        assertArrayEquals(aliceSharedSecret, bobSharedSecret, "Shared secrets should be identical");
    }

    @Test
    void testDeriveKeyPBKDF2DefaultAlgorithm() throws GeneralSecurityException {
        String password = "testPassword";
        String[] algorithms = {"IDEA", "RC6", "ChaCha20-Poly1305", "AES"};

        for (String algorithm : algorithms) {
            SecretKey derivedKey = deriveKeyPBKDF2(password, algorithm);

            assertNotNull(derivedKey, "Derived key should not be null for " + algorithm);
            assertNotEquals(0, derivedKey.getEncoded().length, "Derived key should have non-zero length for " + algorithm);
        }
    }

    @Test
    void testDeriveKeyPBKDF2CustomParams() throws GeneralSecurityException {
        String pbkdfAlgorithm = "PBKDF2WithHmacSHA256";
        String password = "testPassword";
        byte[] salt = "randomsalt".getBytes();
        int iterations = 10000;
        int keyLength = 256;
        String usageAlgorithm = "AES";

        SecretKey derivedKey = deriveKeyPBKDF2(
                pbkdfAlgorithm,
                password,
                salt,
                iterations,
                keyLength,
                usageAlgorithm
        );

        assertNotNull(derivedKey, "Derived key should not be null");
        assertEquals(usageAlgorithm, derivedKey.getAlgorithm(), "Key algorithm should match usage algorithm");
        assertNotEquals(0, derivedKey.getEncoded().length, "Derived key should have non-zero length");
    }

    @Test
    void testDoDHKeyAgreementInvalidKey() {
        // Try to perform key agreement with incompatible keys
        KeyPair keyPair = assertDoesNotThrow(() ->
                generateDHKeyPair()
        );

        PublicKey invalidPublicKey = new PublicKey() {
            @Override
            public String getAlgorithm() {
                return "INVALID";
            }

            @Override
            public String getFormat() {
                return null;
            }

            @Override
            public byte[] getEncoded() {
                return new byte[0];
            }
        };

        assertThrows(GeneralSecurityException.class, () ->
                doDHKeyAgreement(keyPair, invalidPublicKey)
        );
    }

    @Test
    void printKeysizes() throws GeneralSecurityException {
        System.out.println(ClientECCKeyPair.getInstance().getPrivate().getEncoded().length * 8);
        System.out.println(ClientECCKeyPair.getInstance().getPrivate().getFormat());
        System.out.println(ClientECCKeyPair.getInstance().getPublic().getEncoded().length * 8);
        System.out.println(ClientECCKeyPair.getInstance().getPublic().getFormat());
        System.out.println(ServerECCKeyPair.getInstance().getPrivate().getEncoded().length * 8);
        System.out.println(ServerECCKeyPair.getInstance().getPublic().getEncoded().length * 8);
        System.out.println(DEFAULT_P.bitLength());
        System.out.println(DEFAULT_G.bitLength());
        KeyPair DHkeypair = generateDHKeyPair();
        System.out.println(DHkeypair.getPrivate().getEncoded().length * 8);
        System.out.println(DHkeypair.getPublic().getEncoded().length * 8);
    }
}
