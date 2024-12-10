package shp;

import util.CryptoUtils;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.lang.String.format;
import static util.ByteUtils.hexToBytes;
import static util.CryptoUtils.reconstructECCPrivateKeyFromBytes;
import static util.CryptoUtils.reconstructECCPublicKeyFromBytes;

public abstract class KeyFileManager {
    protected static Pattern keyFilePattern = Pattern.compile("Curve: (?<curve>[a-zA-Z0-9-]+)\\nPrivateKey: (?<privkey>[a-zA-Z0-9]+)\\nPublicKey: (?<pubkey>a-zA-Z0-9]+)");
    protected static KeyFileManager instance;

    protected String curve;
    protected PrivateKey privkey;
    protected PublicKey pubkey;

    protected KeyFileManager(String keyFilePath) {
        String fileContentString;
        try (BufferedReader br = new BufferedReader(new FileReader(keyFilePath))) {
            StringBuilder fileContent = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) {
                fileContent.append(line).append(System.lineSeparator());
            }
            fileContentString = fileContent.toString();
        } catch (IOException e) {
            throw new RuntimeException(format("Could not read key file '%s'%n", keyFilePath), e);
        }
        Matcher matcher = keyFilePattern.matcher(fileContentString);
        if (!matcher.matches()) {
            throw new RuntimeException(format("Could not parse key file '%s'%n", keyFilePath));
        }
        curve = matcher.group("curve");
        byte[] privkeyBytes = hexToBytes(matcher.group("privkey"));
        byte[] pubkeyBytes = hexToBytes(matcher.group("pubkey"));
        try {
            privkey = reconstructECCPrivateKeyFromBytes(privkeyBytes);
            pubkey = reconstructECCPublicKeyFromBytes(pubkeyBytes);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(format("Could not reconstruct key pair from key file '%s'%n", keyFilePath), e);
        }
    }

    public String getCurve() {
        return curve;
    }

    public PrivateKey getPrivate() {
        return privkey;
    }

    public PublicKey getPublic() {
        return pubkey;
    }
}
