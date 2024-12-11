package util;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Random;

import static util.SimpleCurves.secp256r1;

public class CryptoUtils {

    public static final String DEFAULT_PBE_SCHEME = "PBEWITHSHA256AND192BITAES-CBC-BC";
    public static final int DEFAULT_PBE_ITERATIONS = 2048;
    public static final byte[] DEFAULT_SALT = "SHP".getBytes();
    public static final String DEFAULT_ECC_CURVE = secp256r1.getAlgorithm();
    public static final String DEFAULT_ECC_ALGORITHM = "EC";
    public static final String DEFAULT_MAC_ALGORITHM = "HMacSHA256";
    public static final String DEFAULT_ECDSA_ALGORITHM = "SHA256withECDSA";
    public static final String SHA256_ALGORITHM = "SHA-256";
    public static final String ECIED_ALGORITHM = "ECIES";

    public static byte[] generateMac(byte[] data, String algorithm, byte[] key, byte[] iv) throws GeneralSecurityException {
        Mac mac = Mac.getInstance(algorithm, new BouncyCastleProvider());

        SecretKeySpec secretKey = new SecretKeySpec(key, algorithm);
        if (algorithm.toLowerCase().contains("gmac")) {
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            mac.init(secretKey, ivSpec);
        } else {
            mac.init(secretKey);
        }

        return mac.doFinal(data);
    }

    public static byte[] generateMac(byte[] data, String algorithm, byte[] key) throws GeneralSecurityException {
        return generateMac(data, algorithm, key, new byte[0]);
    }

    public static byte[] generateMac(byte[] data, byte[] key) throws GeneralSecurityException {
        return generateMac(data, DEFAULT_MAC_ALGORITHM, key);
    }

    public static boolean verifyMac(byte[] data, byte[] mac, String algorithm, byte[] key, byte[] iv) throws GeneralSecurityException {
        byte[] generatedMac = generateMac(data, algorithm, key, iv);
        return MessageDigest.isEqual(generatedMac, mac);
    }

    public static boolean verifyMac(byte[] data, byte[] mac, byte[] key) throws GeneralSecurityException {
        return verifyMac(data, mac, DEFAULT_MAC_ALGORITHM, key, new byte[0]);
    }

    public static byte[] generateNonce(int length) throws NoSuchAlgorithmException {
        byte[] nonce = new byte[length];
        new Random().nextBytes(nonce);
        return nonce;
    }

    public static byte[] generateHash(byte[] input, String algorithm) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(algorithm, new BouncyCastleProvider());
        return digest.digest(input);
    }

    public static byte[] generatePasswordHash(String password, String salt) throws NoSuchAlgorithmException {
        String input = password + salt;
        return generateHash(input.getBytes(), SHA256_ALGORITHM);
    }

    public static Key generatePBEKey(char[] password) throws GeneralSecurityException {
        PBEKeySpec pbeSpec = new PBEKeySpec(password);
        SecretKeyFactory keyFact = SecretKeyFactory.getInstance(DEFAULT_PBE_SCHEME, new BouncyCastleProvider());
        return keyFact.generateSecret(pbeSpec);
    }

    public static byte[] PBEEncrypt(byte[] input, Key pbeKey) throws GeneralSecurityException {
        return PBECrypto(input, pbeKey, DEFAULT_PBE_SCHEME, DEFAULT_SALT, DEFAULT_PBE_ITERATIONS, Cipher.ENCRYPT_MODE);
    }

    public static byte[] PBEDecrypt(byte[] input, Key pbeKey) throws GeneralSecurityException {
        return PBECrypto(input, pbeKey, DEFAULT_PBE_SCHEME, DEFAULT_SALT, DEFAULT_PBE_ITERATIONS, Cipher.DECRYPT_MODE);
    }

    private static byte[] PBECrypto(byte[] input, Key pbeKey, String pbeScheme, byte[] salt, int iterationCount, int mode) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(pbeScheme, new BouncyCastleProvider());
        cipher.init(mode, pbeKey, new PBEParameterSpec(salt, iterationCount));

        return cipher.doFinal(input);
    }

    public static byte[] ECIESEncrypt(byte[] data, PublicKey pubkey) throws GeneralSecurityException {
        return ECIESCrypto(data, pubkey, Cipher.ENCRYPT_MODE);
    }

    public static byte[] ECIESDecrypt(byte[] data, PrivateKey privkey) throws GeneralSecurityException {
        return ECIESCrypto(data, privkey, Cipher.DECRYPT_MODE);
    }

    public static byte[] ECIESCrypto(byte[] data, Key key, int mode) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(ECIED_ALGORITHM, new BouncyCastleProvider());
        cipher.init(mode, key);

        return cipher.doFinal(data);
    }

    public static KeyPair generateECCKeyPair() throws GeneralSecurityException {
        return generateECCKeyPair(DEFAULT_ECC_CURVE);
    }

    public static KeyPair generateECCKeyPair(String curve) throws GeneralSecurityException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(DEFAULT_ECC_ALGORITHM, new BouncyCastleProvider());
        ECGenParameterSpec ecSpec = new ECGenParameterSpec(curve);
        kpg.initialize(ecSpec, SecureRandom.getInstanceStrong());
        return kpg.generateKeyPair();
    }

    public static PrivateKey reconstructECCPrivateKeyFromBytes(byte[] privateKeyBytes) throws GeneralSecurityException {
        KeyFactory keyFactory = KeyFactory.getInstance(DEFAULT_ECC_ALGORITHM);

        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        return keyFactory.generatePrivate(privateKeySpec);
    }

    public static PublicKey reconstructECCPublicKeyFromBytes(byte[] publicKeyBytes) throws GeneralSecurityException {
        KeyFactory keyFactory = KeyFactory.getInstance(DEFAULT_ECC_ALGORITHM);

        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        return keyFactory.generatePublic(publicKeySpec);
    }

    public static byte[] generateECDSASignature(byte[] data, PrivateKey key) throws GeneralSecurityException {
        Signature signature = Signature.getInstance(DEFAULT_ECDSA_ALGORITHM, new BouncyCastleProvider());

        signature.initSign(key, new SecureRandom());
        signature.update(data);
        return signature.sign();
    }

    public static boolean verifyECDSASignature(byte[] data, byte[] signatureBytes, PublicKey key) throws GeneralSecurityException {
        Signature signature = Signature.getInstance(DEFAULT_ECDSA_ALGORITHM, new BouncyCastleProvider());

        signature.initVerify(key);
        signature.update(data);
        return signature.verify(signatureBytes);
    }
}
