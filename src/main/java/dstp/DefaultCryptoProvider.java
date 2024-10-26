package dstp;

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
import java.util.Arrays;

import static dstp.util.Utils.hexToBytes;

public class DefaultCryptoProvider implements CryptoProvider {
    private final DSTPConfig config;

    public DefaultCryptoProvider(DSTPConfig config) {
        this.config = config;
    }

    @Override
    public byte[] encrypt(byte[] data, byte[] key) throws GeneralSecurityException {
        String confidentialityAlgorithm = config.getConfidentiality();
        switch (confidentialityAlgorithm) {
            case "RC4" -> {
                return encryptRC4(data, key);
            }
            case "CHACHA20-Poly1305" -> {
                return encryptChaCha20Poly1305(data, key);
            }
            case "ChaCha20" -> {
                return encryptChaCha20(data, key);
            }
        }

        Cipher cipher = Cipher.getInstance(confidentialityAlgorithm);
        SecretKey secretKey = new SecretKeySpec(key, getBaseAlgorithm(confidentialityAlgorithm));

        byte[] iv = hexToBytes(config.getIv());

        if (confidentialityAlgorithm.contains("GCM")) {
            GCMParameterSpec spec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        } else if (confidentialityAlgorithm.contains("CTR")) {
            IvParameterSpec spec = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        } else if (confidentialityAlgorithm.contains("CBC")) {
            IvParameterSpec spec = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        } else if (confidentialityAlgorithm.contains("ECB")) {
            // ECB doesn't use IV
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return cipher.doFinal(data);
        }

        byte[] encrypted = cipher.doFinal(data);

        // Combine IV and encrypted data except for ECB
        if (!confidentialityAlgorithm.contains("ECB")) {
            byte[] result = new byte[iv.length + encrypted.length];
            System.arraycopy(iv, 0, result, 0, iv.length);
            System.arraycopy(encrypted, 0, result, iv.length, encrypted.length);
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
        return doChaCha20Encryption(Cipher.getInstance("ChaCha20-Poly1305"), key, data);
    }

    private byte[] encryptChaCha20(byte[] data, byte[] key) throws GeneralSecurityException {
        return doChaCha20Encryption(Cipher.getInstance("ChaCha20"), key, data);
    }

    private byte[] doChaCha20Encryption(Cipher cipher, byte[] key, byte[] data) throws GeneralSecurityException {
        SecretKey secretKey = new SecretKeySpec(key, "ChaCha20");

        byte[] nonce = new byte[12];
        SecureRandom.getInstanceStrong().nextBytes(nonce);
        ChaCha20ParameterSpec spec = new ChaCha20ParameterSpec(nonce, 1);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        byte[] encrypted = cipher.doFinal(data);

        // Combine nonce and encrypted data
        byte[] result = new byte[nonce.length + encrypted.length];
        System.arraycopy(nonce, 0, result, 0, nonce.length);
        System.arraycopy(encrypted, 0, result, nonce.length, encrypted.length);
        return result;
    }

    @Override
    public byte[] decrypt(byte[] data, byte[] key) throws GeneralSecurityException {
        String confidentialityAlgorithm = config.getConfidentiality();
        switch (confidentialityAlgorithm) {
            case "RC4" -> {
                return decryptRC4(data, key);
            }
            case "CHACHA20-Poly1305" -> {
                return decryptChaCha20Poly1305(data, key);
            }
            case "ChaCha20" -> {
                return decryptChaCha20(data, key);
            }
        }

        Cipher cipher = Cipher.getInstance(confidentialityAlgorithm);
        SecretKey secretKey = new SecretKeySpec(key, getBaseAlgorithm(confidentialityAlgorithm));

        if (confidentialityAlgorithm.contains("ECB")) {
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return cipher.doFinal(data);
        }

        // Extract IV and encrypted data
        int ivSize = config.getIv_size();
        byte[] iv = Arrays.copyOfRange(data, 0, ivSize);
        byte[] encrypted = Arrays.copyOfRange(data, ivSize, data.length);

        if (confidentialityAlgorithm.contains("GCM")) {
            GCMParameterSpec spec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
        } else if (confidentialityAlgorithm.contains("CTR") ||
                confidentialityAlgorithm.contains("CBC")) {
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
        return doChaCha20Decryption(data, key, Cipher.getInstance("ChaCha20-Poly1305"));
    }

    private byte[] decryptChaCha20(byte[] data, byte[] key) throws GeneralSecurityException {
        return doChaCha20Decryption(data, key, Cipher.getInstance("ChaCha20"));
    }

    private byte[] doChaCha20Decryption(byte[] data, byte[] key, Cipher cipher) throws GeneralSecurityException {
        SecretKey secretKey = new SecretKeySpec(key, "ChaCha20");

        byte[] nonce = Arrays.copyOfRange(data, 0, 12);
        byte[] encrypted = Arrays.copyOfRange(data, 12, data.length);

        ChaCha20ParameterSpec spec = new ChaCha20ParameterSpec(nonce, 1);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
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

    // Helper methods
    private String getBaseAlgorithm(String fullAlgorithm) {
        return fullAlgorithm.split("/")[0];
    }
}