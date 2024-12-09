package dstp.config;

import util.Utils;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import static util.Utils.getBaseAlgorithm;

// Builder class for DSTPConfig
public class TestConfigBuilder {
    private String algorithm;
    private String symmetric_key;
    private String symmetric_key_size;
    private String iv;
    private String iv_size;
    private String integrity;
    private String h;
    private String macAlgorithm;
    private String mackey;
    private String mackey_size;


    public TestConfigBuilder setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
        return this;
    }

    public TestConfigBuilder setSymmetricKey(String key) {
        this.symmetric_key = key;
        return this;
    }

    public TestConfigBuilder setSymmetricKeySize(String keysize) {
        this.symmetric_key_size = keysize;
        return this;
    }

    public TestConfigBuilder setIv(String iv) {
        this.iv = iv;
        return this;
    }

    public TestConfigBuilder setIvSize(String ivsize) {
        this.iv_size = ivsize;
        return this;
    }

    public TestConfigBuilder setIntegrity(String integrity) {
        this.integrity = integrity;
        return this;
    }

    public TestConfigBuilder setH(String hashAlgorithm) {
        this.h = hashAlgorithm;
        return this;
    }

    public TestConfigBuilder setMacAlgorithm(String macAlgorithm) {
        this.macAlgorithm = macAlgorithm;
        return this;
    }

    public TestConfigBuilder setMacKey(String macKey) {
        this.mackey = macKey;
        return this;
    }

    public TestConfigBuilder setMacKeySize(String macKeySize) {
        this.mackey_size = macKeySize;
        return this;
    }

    /**
     * automatically generates a symmetric encryption key
     * sets the fields @symmetric_key and @symmetric_key_size
     * <p>
     * valid keysizes:
     * AES key: 128, 192, or 256 bits
     * DES key: 56 bits
     * Triple DES key: 168 bits
     * Blowfish key: anywhere from 32 to 448 bits
     *
     * @throws NoSuchAlgorithmException
     */
    public TestConfigBuilder generateSymmetricKey(final String algorithm, final int keysize) throws NoSuchAlgorithmException {
        String key = generateKey(getBaseAlgorithm(algorithm), keysize);
        setAlgorithm(algorithm);
        setSymmetricKey(key);
        setSymmetricKeySize(String.valueOf(keysize));
        return this;
    }

    public TestConfigBuilder generateMacKey(final String algorithm, final int keysize) throws NoSuchAlgorithmException {
        String key = generateKey(algorithm, keysize);
        setIntegrity("mac");
        setMacAlgorithm(algorithm);
        setMacKey(key);
        setMacKeySize(String.valueOf(keysize));
        return this;
    }

    private String generateKey(final String algorithm, final int keysize) throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance(algorithm);
        SecureRandom secureRandom = new SecureRandom();
        keyGen.init(keysize, secureRandom);
        SecretKey key = keyGen.generateKey();
        return Utils.bytesToHex(key.getEncoded());
    }

    public TestConfigBuilder generateIv(final int ivsize) {
        String iv = generateIvInHex(ivsize);
        setIv(iv);
        setIvSize(String.valueOf(ivsize));
        return this;
    }

    private String generateIvInHex(final int ivsize) {
        byte[] iv = new byte[ivsize];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);
        return Utils.bytesToHex(new IvParameterSpec(iv).getIV());
    }

    public DSTPConfig build() {
        DSTPConfig config = new DSTPConfig();
        config.setConfidentiality(algorithm);
        config.setSymmetric_key(symmetric_key);
        config.setSymmetric_key_size(symmetric_key_size);
        config.setIv(iv);
        config.setIv_size(iv_size);
        config.setIntegrity(integrity);
        config.setH(h);
        config.setMac(macAlgorithm);
        config.setMackey(mackey);
        config.setMackey_size(mackey_size);
        return config;

    }
}
