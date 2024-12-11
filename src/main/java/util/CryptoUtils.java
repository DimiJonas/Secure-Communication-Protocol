package util;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.math.BigInteger;
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
    public static final String DH_ALGORITHM = "DH";
    public static final int DEFAULT_NUMBER_OF_BITS_DH = 2048;
    public static final BigInteger DEFAULT_P = new BigInteger("28405029833945599694020150324382168460265857192807020156157173557136735529809385147551938954390698527205286565709884557153477288942179285719968527754377513182297418076870083194436656093677545970599839651485503651553895257256559155102345455599845648530974178441359317292355448626162686623552957533617153426584894300068944192253632380728822081648379200003929534954482324289411872657638128671023045939798508459274917815570583461805531112522901322562311806456283629425632711265356659262499031897488662613605995714138461592123034523060396461645622953424167078017320300996171544436288208963020554349310636047699451939730367");
    public static final BigInteger DEFAULT_G = new BigInteger("15661621304946338216902567491348365942250760364301042093059696381376421829798645957292375984201167177694493681681301562563287754327689115480427275014453655390329518225863967777069341931698692255357436278864915318664631765811224151656776289446429563511442118608708648552025597266579034130091036708241663096209375248605015410496813233096877829735312063637867484613071771774419946294308246828637558216429907298827402127034214661325640554945319675488181440346080575203655432892988874183351544154841574382188574576571165251643172795578219141814768156167589789567008016211141454005936029036564549941054056478952000355832464");
    public static final int DEFAULT_PBKDF_ITERATIONS = 10000;
    public static final int DEFAULT_PBKDF_KEY_LENGTH = 256;
    public static final String DEFAULT_PBKDF_ALGORITHM = "PBKDF2WithHmacSHA256";

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

    public static byte[] generateSha256(byte[] input) throws NoSuchAlgorithmException {
        return generateHash(input, SHA256_ALGORITHM);
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

    public static PublicKey reconstructDHPublicKeyFromBytes(byte[] publicKeyBytes) throws GeneralSecurityException {
        KeyFactory keyFactory = KeyFactory.getInstance(DH_ALGORITHM);

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

    public static DHParameterSpec generateDHParams() throws GeneralSecurityException {
        return generateDHParams(DEFAULT_NUMBER_OF_BITS_DH);
    }

    public static DHParameterSpec generateDHParams(int numberOfBits) throws GeneralSecurityException {
        AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance(DH_ALGORITHM, new BouncyCastleProvider());
        paramGen.init(numberOfBits);
        AlgorithmParameters params = paramGen.generateParameters();
        return params.getParameterSpec(DHParameterSpec.class);
    }

    public static KeyPair generateDHKeyPair() throws GeneralSecurityException {
        return generateDHKeyPair(new DHParameterSpec(DEFAULT_P, DEFAULT_G));
    }

    public static KeyPair generateDHKeyPair(DHParameterSpec dhParams) throws GeneralSecurityException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(DH_ALGORITHM, new BouncyCastleProvider());
        keyGen.initialize(dhParams);
        return keyGen.generateKeyPair();
    }

    public static byte[] doDHKeyAgreement(KeyPair keyPair, PublicKey otherPublicKey) throws GeneralSecurityException {
        KeyAgreement keyAgreement = KeyAgreement.getInstance(DH_ALGORITHM, new BouncyCastleProvider());
        keyAgreement.init(keyPair.getPrivate());
        keyAgreement.doPhase(otherPublicKey, true);
        byte[] secret = keyAgreement.generateSecret();
        return generateSha256(secret);
    }

    public static SecretKey deriveKeyPBKDF2(String password, String usageAlgorithm) throws GeneralSecurityException {
        String keyGenerationAlgorithm = switch (usageAlgorithm.toLowerCase()) {
            case "idea" -> "BLOWFISH";
            case "rc6" -> "BLOWFISH";
            case "chacha20-poly1305" -> "ChaCha20";
            default -> usageAlgorithm;
        };
        return deriveKeyPBKDF2(DEFAULT_PBKDF_ALGORITHM, password, DEFAULT_SALT, DEFAULT_PBKDF_ITERATIONS, DEFAULT_PBKDF_KEY_LENGTH, keyGenerationAlgorithm);
    }

    public static SecretKey deriveKeyPBKDF2(String PBKDFalgorithm, String password, byte[] salt, int iterations, int keyLength, String usageAlgorithm) throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(
                password.toCharArray(),
                salt,
                iterations,
                keyLength
        );

        SecretKeyFactory skf = SecretKeyFactory.getInstance(PBKDFalgorithm);
        byte[] derivedKey = skf.generateSecret(spec).getEncoded();

        return new SecretKeySpec(derivedKey, usageAlgorithm);
    }
}
