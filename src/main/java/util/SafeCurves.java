package util;

/**
 * Enum of safe curves for elliptic curve cryptography as found here: https://safecurves.cr.yp.to/
 */
public enum SafeCurves {
    M_221 ("M-221"),
    E_222 ("E-222"),
    Curve1174("Curve1174"),
    Curve25519("Curve25519"),
    E_382("E-382"),
    M_383("M-383"),
    Curve383187("Curve383187"),
    Ed448_Goldilocks("Ed448-Goldilocks"),
    M_511("M-511"),
    E_521("E-521");

    private final String algorithm;

    SafeCurves(String algorithm) {
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
