import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Arrays;

public class DefaultCryptoProvider implements CryptoProvider {
    private final String confidentialityAlgorithm;
    private final String integrityAlgorithm;

    public DefaultCryptoProvider(String confidentialityAlgorithm,
                                 String integrityAlgorithm) {
        this.confidentialityAlgorithm = confidentialityAlgorithm;
        this.integrityAlgorithm = integrityAlgorithm;
    }

    @Override
    public byte[] encrypt(byte[] data, byte[] key) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(confidentialityAlgorithm);
        SecretKey secretKey = new SecretKeySpec(key, "AES");

        if (confidentialityAlgorithm.contains("GCM")) {
            byte[] iv = new byte[12];
            SecureRandom.getInstanceStrong().nextBytes(iv);
            GCMParameterSpec spec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
            byte[] encrypted = cipher.doFinal(data);

            // Combine IV and encrypted data
            byte[] result = new byte[iv.length + encrypted.length];
            System.arraycopy(iv, 0, result, 0, iv.length);
            System.arraycopy(encrypted, 0, result, iv.length, encrypted.length);
            return result;
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return cipher.doFinal(data);
        }
    }

    @Override
    public byte[] decrypt(byte[] data, byte[] key) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(confidentialityAlgorithm);
        SecretKey secretKey = new SecretKeySpec(key, "AES");

        if (confidentialityAlgorithm.contains("GCM")) {
            // Extract IV and encrypted data
            byte[] iv = Arrays.copyOfRange(data, 0, 12);
            byte[] encrypted = Arrays.copyOfRange(data, 12, data.length);

            GCMParameterSpec spec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
            return cipher.doFinal(encrypted);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return cipher.doFinal(data);
        }
    }

    @Override
    public byte[] generateMac(byte[] data, byte[] key) throws GeneralSecurityException {
        Mac mac = Mac.getInstance(integrityAlgorithm);
        SecretKey secretKey = new SecretKeySpec(key, integrityAlgorithm);
        mac.init(secretKey);
        return mac.doFinal(data);
    }

    @Override
    public boolean verifyMac(byte[] data, byte[] macBytes, byte[] key)
            throws GeneralSecurityException {
        byte[] computedMac = generateMac(data, key);
        return MessageDigest.isEqual(macBytes, computedMac);
    }
}