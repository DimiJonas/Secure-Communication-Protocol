package crypto;

import org.bouncycastle.crypto.InvalidCipherTextException;

import java.security.GeneralSecurityException;

public interface CryptoProvider {
    byte[] encrypt(byte[] data, byte[] key) throws GeneralSecurityException, InvalidCipherTextException;
    byte[] decrypt(byte[] data, byte[] key) throws GeneralSecurityException, InvalidCipherTextException;
    byte[] generateIntegrityCheck(byte[] data, byte[] key) throws GeneralSecurityException;
    boolean verifyIntegrityCheck(byte[] data, byte[] mac, byte[] key) throws GeneralSecurityException;
}
