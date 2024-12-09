package crypto;

import dstp.config.DSTPConfig;
import dstp.config.DSTPConfig.Integrity;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import static util.Utils.getBaseAlgorithm;
import static util.Utils.hexToBytes;

public class DefaultCryptoProvider implements CryptoProvider {
    private final DSTPConfig config;
    private static final String aadString = "Use some additional authenticated data";

    public DefaultCryptoProvider(DSTPConfig config) {
        this.config = config;
    }

    @Override
    public byte[] encrypt(byte[] data, byte[] key) throws GeneralSecurityException {
        String confidentialityAlgorithm = config.getConfidentiality().toLowerCase();
        switch (confidentialityAlgorithm.split("/")[0]) {
            case "rc4" -> {
                return encryptRC4(data, key);
            }
            case "chacha20-poly1305" -> {
                return encryptChaCha20Poly1305(data, key);
            }
            case "chacha20" -> {
                return encryptChaCha20(data, key);
            }
        }

        Cipher cipher = Cipher.getInstance(confidentialityAlgorithm);
        SecretKey secretKey = new SecretKeySpec(key, getBaseAlgorithm(confidentialityAlgorithm));

        int ivSize = config.getIv_size();
        byte[] iv = hexToBytes(config.getIv());

        if (confidentialityAlgorithm.contains("gcm")) {
            GCMParameterSpec spec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        } else if (confidentialityAlgorithm.contains("ctr")) {
            IvParameterSpec spec = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        } else if (confidentialityAlgorithm.contains("cbc")) {
            IvParameterSpec spec = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        } else if (confidentialityAlgorithm.contains("ecb")) {
            // ECB doesn't use IV
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return cipher.doFinal(data);
        }

        byte[] encrypted = cipher.doFinal(data);

        // Combine IV and encrypted data except for ECB
        if (!confidentialityAlgorithm.contains("ecb")) {
            byte[] result = new byte[ivSize+ encrypted.length];
            System.arraycopy(iv, 0, result, 0, ivSize);
            System.arraycopy(encrypted, 0, result, ivSize, encrypted.length);
            return result;
        }

        return encrypted;
    }

    private byte[] encryptRC4(byte[] data, byte[] key) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RC4");
        SecretKey secretKey = new SecretKeySpec(key, "RC4");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(data);
    }

    private byte[] encryptChaCha20Poly1305(byte[] data, byte[] key) throws GeneralSecurityException {
        byte[] nonce = getNonce();
        IvParameterSpec parameterSpec = new IvParameterSpec(nonce);
        return doChaCha20Encryption("ChaCha20-Poly1305", key, nonce, parameterSpec, data, aadString);
    }

    private byte[] encryptChaCha20(byte[] data, byte[] key) throws GeneralSecurityException {
        byte[] nonce = getNonce();
        ChaCha20ParameterSpec parameterSpec = new ChaCha20ParameterSpec(nonce, 1);
        return doChaCha20Encryption("ChaCha20", key, nonce, parameterSpec, data);
    }

    private byte[] doChaCha20Encryption(String cipherString, byte[] key, byte[] nonce, AlgorithmParameterSpec parameterSpec, byte[] data) throws GeneralSecurityException {
        return doChaCha20Encryption(cipherString, key, nonce, parameterSpec, data, null);
    }

    private byte[] doChaCha20Encryption(String cipherString, byte[] key, byte[] nonce, AlgorithmParameterSpec parameterSpec, byte[] data, String aad) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(cipherString);
        SecretKey secretKey = new SecretKeySpec(key, "ChaCha20");

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        if (aad != null) {
            cipher.updateAAD(aad.getBytes());
        }
        byte[] encrypted = cipher.doFinal(data);

        // Combine nonce and encrypted data
        byte[] result = new byte[nonce.length + encrypted.length];
        System.arraycopy(nonce, 0, result, 0, nonce.length);
        System.arraycopy(encrypted, 0, result, nonce.length, encrypted.length);
        return result;
    }

    private byte[] getNonce() throws NoSuchAlgorithmException {
        byte[] nonce = new byte[12];
        SecureRandom.getInstanceStrong().nextBytes(nonce);
        return nonce;
    }

    @Override
    public byte[] decrypt(byte[] data, byte[] key) throws GeneralSecurityException {
        String confidentialityAlgorithm = config.getConfidentiality().toLowerCase();
        switch (confidentialityAlgorithm.split("/")[0]) {
            case "rc4" -> {
                return decryptRC4(data, key);
            }
            case "chacha20-poly1305" -> {
                return decryptChaCha20Poly1305(data, key);
            }
            case "chacha20" -> {
                return decryptChaCha20(data, key);
            }
        }

        Cipher cipher = Cipher.getInstance(confidentialityAlgorithm);
        SecretKey secretKey = new SecretKeySpec(key, getBaseAlgorithm(confidentialityAlgorithm));

        if (confidentialityAlgorithm.contains("ecb")) {
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return cipher.doFinal(data);
        }

        // Extract IV and encrypted data
        int ivSize = config.getIv_size();
        byte[] iv = Arrays.copyOfRange(data, 0, ivSize);
        byte[] encrypted = Arrays.copyOfRange(data, ivSize, data.length);

        if (confidentialityAlgorithm.contains("gcm")) {
            GCMParameterSpec spec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
        } else if (confidentialityAlgorithm.contains("ctr") ||
                confidentialityAlgorithm.contains("cbc")) {
            IvParameterSpec spec = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
        }

        return cipher.doFinal(encrypted);
    }

    private byte[] decryptRC4(byte[] data, byte[] key) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RC4");
        SecretKey secretKey = new SecretKeySpec(key, "RC4");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(data);
    }

    private byte[] decryptChaCha20Poly1305(byte[] data, byte[] key) throws GeneralSecurityException {
        return doChaCha20Decryption(data, key, "ChaCha20-Poly1305", aadString);
    }

    private byte[] decryptChaCha20(byte[] data, byte[] key) throws GeneralSecurityException {
        return doChaCha20Decryption(data, key, "ChaCha20");
    }

    private byte[] doChaCha20Decryption(byte[] data, byte[] key, String cipherString) throws GeneralSecurityException {
        return doChaCha20Decryption(data, key, cipherString, null);
    }
    private byte[] doChaCha20Decryption(byte[] data, byte[] key, String cipherString, String aad) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(cipherString);
        SecretKey secretKey = new SecretKeySpec(key, "ChaCha20");

        byte[] nonce = Arrays.copyOfRange(data, 0, 12);
        byte[] encrypted = Arrays.copyOfRange(data, 12, data.length);

        AlgorithmParameterSpec parameterSpec;
        if (cipherString.equalsIgnoreCase("ChaCha20-Poly1305")) {
            parameterSpec = new IvParameterSpec(nonce);
        } else {
            parameterSpec = new ChaCha20ParameterSpec(nonce, 1);
        }
        cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);
        if (aad != null) {
            cipher.updateAAD(aad.getBytes());
        }
        return cipher.doFinal(encrypted);
    }

    @Override
    public byte[] generateIntegrityCheck(byte[] data, byte[] key) throws GeneralSecurityException {
        Integrity integrity = config.getIntegrity();
        switch (integrity) {
            case MAC:
                Mac mac = Mac.getInstance(config.getMac());
                SecretKey secretKey = new SecretKeySpec(key, config.getMac());
                mac.init(secretKey);
                return mac.doFinal(data);
            case HASH:
                MessageDigest digest = MessageDigest.getInstance(config.getH());
                return digest.digest(data);
            case NONE:
                // no explicit integrity check
                return new byte[0];
            default:
                throw new NoSuchAlgorithmException("Invalid integrity algorithm");
        }
    }

    @Override
    public boolean verifyIntegrityCheck(byte[] data, byte[] check, byte[] key)
            throws GeneralSecurityException {
        byte[] computed = generateIntegrityCheck(data, key);
        return MessageDigest.isEqual(check, computed);
    }
}