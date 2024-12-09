package util;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;

import static util.SimpleCurves.secp256r1;

public class CryptoUtils {

    public static KeyPair generateECCKeyPair() throws GeneralSecurityException {
        return generateECCKeyPair(secp256r1.getAlgorithm());
    }

    public static KeyPair generateECCKeyPair(String curve) throws GeneralSecurityException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
        ECGenParameterSpec ecSpec = new ECGenParameterSpec(curve);
        kpg.initialize(ecSpec, SecureRandom.getInstanceStrong());
        return kpg.generateKeyPair();
    }
}
