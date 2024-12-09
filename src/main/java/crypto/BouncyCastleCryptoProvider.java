package crypto;

import dstp.config.DSTPConfig;
import dstp.config.DSTPConfig.Integrity;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.ChaChaEngine;
import org.bouncycastle.crypto.engines.RC4Engine;
import org.bouncycastle.crypto.modes.ChaCha20Poly1305;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

import static util.SafeCurves.Curve25519;
import static util.Utils.*;
import static util.Utils.bytesToHex;

public class BouncyCastleCryptoProvider implements CryptoProvider {
    private final DSTPConfig config;
    private static final byte[] AAD_BYTES = "Use some additional authenticated data".getBytes();
    private static final Provider BC_PROVIDER = new BouncyCastleProvider();

    public BouncyCastleCryptoProvider(DSTPConfig config) {
        this.config = config;
        Security.addProvider(BC_PROVIDER);
    }

    @Override
    public byte[] encrypt(byte[] data, byte[] key) throws GeneralSecurityException, InvalidCipherTextException {
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

        Cipher cipher = Cipher.getInstance(confidentialityAlgorithm, BC_PROVIDER);
        SecretKeySpec secretKey = new SecretKeySpec(key, getBaseAlgorithm(confidentialityAlgorithm));

        int ivSize = config.getIv_size();
        byte[] iv = hexToBytes(config.getIv());
        AlgorithmParameterSpec spec;
        if (confidentialityAlgorithm.contains("gcm")) {
            spec = new GCMParameterSpec(128, iv);
        } else if (confidentialityAlgorithm.contains("ecb")) {
            // ECB doesn't use IV
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return cipher.doFinal(data);
        } else {
            spec = new IvParameterSpec(iv);
        }

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        byte[] encrypted = cipher.doFinal(data);

        // Combine IV and encrypted data
        byte[] result = new byte[ivSize + encrypted.length];
        System.arraycopy(iv, 0, result, 0, ivSize);
        System.arraycopy(encrypted, 0, result, ivSize, encrypted.length);
        return result;
    }

    private byte[] encryptRC4(byte[] data, byte[] key) {
        RC4Engine engine = new RC4Engine();
        KeyParameter keyParam = new KeyParameter(key);

        byte[] output = new byte[data.length];
        engine.init(true, keyParam);
        engine.processBytes(data, 0, data.length, output, 0);

        return output;
    }

    private byte[] encryptChaCha20Poly1305(byte[] data, byte[] key) throws GeneralSecurityException, InvalidCipherTextException {
        byte[] nonce = getNonce();
        return doChaCha20Poly1305Encryption(data, key, nonce);
    }

    private byte[] doChaCha20Poly1305Encryption(byte[] data, byte[] key, byte[] nonce) throws InvalidCipherTextException {
        ChaCha20Poly1305 cipher = new ChaCha20Poly1305();
        KeyParameter keyParam = new KeyParameter(key);
        ParametersWithIV params = new ParametersWithIV(keyParam, nonce);

        cipher.init(true, params);
        cipher.processAADBytes(AAD_BYTES, 0, AAD_BYTES.length);

        byte[] output = new byte[cipher.getOutputSize(data.length)];
        int processedLength = cipher.processBytes(data, 0, data.length, output, 0);
        cipher.doFinal(output, processedLength);

        // Combine nonce and encrypted data
        byte[] result = new byte[nonce.length + output.length];
        System.arraycopy(nonce, 0, result, 0, nonce.length);
        System.arraycopy(output, 0, result, nonce.length, output.length);
        return result;
    }

    private byte[] encryptChaCha20(byte[] data, byte[] key) throws GeneralSecurityException {
        byte[] nonce = getNonce();
        ChaChaEngine engine = new ChaChaEngine();

        KeyParameter keyParam = new KeyParameter(key);
        ParametersWithIV params = new ParametersWithIV(keyParam, nonce);

        engine.init(true, params);
        byte[] output = new byte[data.length];
        engine.processBytes(data, 0, data.length, output, 0);

        // Combine nonce and encrypted data
        byte[] result = new byte[nonce.length + output.length];
        System.arraycopy(nonce, 0, result, 0, nonce.length);
        System.arraycopy(output, 0, result, nonce.length, output.length);
        return result;
    }

    private byte[] getNonce() throws NoSuchAlgorithmException {
        byte[] nonce = new byte[12];
        SecureRandom.getInstanceStrong().nextBytes(nonce);
        return nonce;
    }

    @Override
    public byte[] decrypt(byte[] data, byte[] key) throws GeneralSecurityException, InvalidCipherTextException {
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

        // Fallback to standard JCE providers with BouncyCastle as the preferred provider
        Cipher cipher = Cipher.getInstance(confidentialityAlgorithm, BC_PROVIDER);
        SecretKeySpec secretKey = new SecretKeySpec(key, getBaseAlgorithm(confidentialityAlgorithm));

        if (confidentialityAlgorithm.contains("ecb")) {
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return cipher.doFinal(data);
        }

        // Extract IV and encrypted data
        int ivSize = config.getIv_size();
        byte[] iv = Arrays.copyOfRange(data, 0, ivSize);
        byte[] encrypted = Arrays.copyOfRange(data, ivSize, data.length);
        AlgorithmParameterSpec spec;

        if (confidentialityAlgorithm.contains("gcm")) {
            spec = new GCMParameterSpec(128, iv);
        } else {
            spec = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
        }

        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
        return cipher.doFinal(encrypted);
    }

    private byte[] decryptRC4(byte[] data, byte[] key) {
        RC4Engine engine = new RC4Engine();
        KeyParameter keyParam = new KeyParameter(key);

        byte[] output = new byte[data.length];
        engine.init(false, keyParam);
        engine.processBytes(data, 0, data.length, output, 0);

        return output;
    }

    private byte[] decryptChaCha20Poly1305(byte[] data, byte[] key) throws InvalidCipherTextException {
        byte[] nonce = Arrays.copyOfRange(data, 0, 12);
        byte[] encrypted = Arrays.copyOfRange(data, 12, data.length);

        ChaCha20Poly1305 cipher = new ChaCha20Poly1305();
        KeyParameter keyParam = new KeyParameter(key);
        ParametersWithIV params = new ParametersWithIV(keyParam, nonce);

        cipher.init(false, params);
        cipher.processAADBytes(AAD_BYTES, 0, AAD_BYTES.length);

        byte[] output = new byte[cipher.getOutputSize(encrypted.length)];
        int processedLength = cipher.processBytes(encrypted, 0, encrypted.length, output, 0);
        cipher.doFinal(output, processedLength);

        return output;
    }

    private byte[] decryptChaCha20(byte[] data, byte[] key) {
        byte[] nonce = Arrays.copyOfRange(data, 0, 12);
        byte[] encrypted = Arrays.copyOfRange(data, 12, data.length);

        ChaChaEngine engine = new ChaChaEngine();
        KeyParameter keyParam = new KeyParameter(key);
        ParametersWithIV params = new ParametersWithIV(keyParam, nonce);

        engine.init(false, params);
        byte[] output = new byte[encrypted.length];
        engine.processBytes(encrypted, 0, encrypted.length, output, 0);

        return output;
    }

    @Override
    public byte[] generateIntegrityCheck(byte[] data, byte[] key) throws GeneralSecurityException {
        Integrity integrity = config.getIntegrity();
        switch (integrity) {
            case MAC:
                String algorithm = config.getMac().toLowerCase();
                Mac mac = Mac.getInstance(algorithm, BC_PROVIDER);

                SecretKeySpec secretKey = new SecretKeySpec(key, algorithm);
                if (algorithm.contains("gmac")){
                    IvParameterSpec ivSpec = new IvParameterSpec(hexToBytes(config.getIv()));
                    mac.init(secretKey, ivSpec);
                } else {
                    mac.init(secretKey);
                }

                return mac.doFinal(data);
            case HASH:
                MessageDigest digest = MessageDigest.getInstance(config.getH(), BC_PROVIDER);
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