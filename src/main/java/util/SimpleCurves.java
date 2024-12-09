package util;

import java.security.spec.ECGenParameterSpec;

public enum SimpleCurves {
    secp384r1 ("secp384r1"),
    secp256r1 ("secp256r1"),
    secp192r1("secp192r1"),
    sect571k1("sect571k1"),
    sect283k1("sect283k1"),
    secp256k1("secp256k1"),
    sect233k1("sect233k1"),
    sect409r1("sect409r1");

    private final String algorithm;

    SimpleCurves(String algorithm) {
        this.algorithm = algorithm;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public String toString() {
        return algorithm;
    }
}
