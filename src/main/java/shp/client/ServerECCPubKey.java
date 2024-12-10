package shp.client;

import shp.KeyFileManager;
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

public class ServerECCPubKey {
    private static final String SERVER_KEYFILE_PATH = "src/main/resources/pa2/client/ServerECCKeyPair.txt";
    private static Pattern keyFilePattern = Pattern.compile("Curve: (?<curve>[a-zA-Z0-9-]+)\\nPublicKey: (?<pubkey>a-zA-Z0-9]+)");
    private static ServerECCPubKey instance;

    private String curve;
    private PublicKey pubkey;

    private ServerECCPubKey() {
        String fileContentString;
        try (BufferedReader br = new BufferedReader(new FileReader(SERVER_KEYFILE_PATH))) {
            StringBuilder fileContent = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) {
                fileContent.append(line).append(System.lineSeparator());
            }
            fileContentString = fileContent.toString();
        } catch (IOException e) {
            throw new RuntimeException(format("Could not read key file '%s'%n", SERVER_KEYFILE_PATH), e);
        }
        Matcher matcher = keyFilePattern.matcher(fileContentString);
        if (!matcher.matches()) {
            throw new RuntimeException(format("Could not parse key file '%s'%n", SERVER_KEYFILE_PATH));
        }
        curve = matcher.group("curve");
        byte[] pubkeyBytes = hexToBytes(matcher.group("pubkey"));
        try {
            pubkey = CryptoUtils.reconstructECCPublicKeyFromBytes(pubkeyBytes);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(format("Could not reconstruct key pair from key file '%s'%n", SERVER_KEYFILE_PATH), e);
        }
    }

    public static ServerECCPubKey getInstance() {
        if (instance == null) {
            instance = new ServerECCPubKey();
        }
        return instance;
    }

    public String getCurve() {
        return curve;
    }

    public PublicKey getPublic() {
        return pubkey;
    }
}
