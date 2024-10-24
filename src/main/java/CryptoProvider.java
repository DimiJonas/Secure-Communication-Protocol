import java.security.GeneralSecurityException;
import java.security.PrivateKey;

public interface CryptoProvider {
    byte[] encrypt(byte[] data, byte[] key) throws GeneralSecurityException;
    byte[] decrypt(byte[] data, byte[] key) throws GeneralSecurityException;
    byte[] generateMac(byte[] data, byte[] key) throws GeneralSecurityException;
    boolean verifyMac(byte[] data, byte[] mac, byte[] key) throws GeneralSecurityException;
}
