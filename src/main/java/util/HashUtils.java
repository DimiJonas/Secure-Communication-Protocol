package util;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;

import static util.Utils.bytesToHex;

public class HashUtils {

    public static String generateSha256Hash(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256", new BouncyCastleProvider());
            byte[] hashBytes = digest.digest(input.getBytes());
            return bytesToHex(hashBytes);
        } catch (GeneralSecurityException e) {
            System.out.println("Error generating SHA-256 hash: " + e.getMessage());
        }
        return null;
    }
}
