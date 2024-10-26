package dstp.crypto;

import java.security.GeneralSecurityException;

public interface CryptoProvider {
    byte[] encrypt(byte[] data, byte[] key) throws GeneralSecurityException;
    byte[] decrypt(byte[] data, byte[] key) throws GeneralSecurityException;
    byte[] generateIntegrityCheck(byte[] data, byte[] key) throws GeneralSecurityException;
    boolean verifyIntegrityCheck(byte[] data, byte[] mac, byte[] key) throws GeneralSecurityException;
}
