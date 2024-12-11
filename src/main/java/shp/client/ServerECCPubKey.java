package shp.client;

import util.CryptoUtils;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.lang.String.format;
import static util.ByteUtils.hexToBytes;

public class ServerECCPubKey {
    public static final String DEFAULT_SERVER_KEYFILE_PATH = "src/main/resources/pa2/client/ServerECCPubKey.txt";
    private static String keyfilePath;
    private static final Pattern KEY_FILE_PATTERN = Pattern.compile("Curve:\\s*(?<curve>[0-9a-zA-Z]+)\\s*PublicKey:\\s*(?<pubkey>[0-9a-fA-F]+)");
    private static ServerECCPubKey instance;

    private final String curve;
    private final PublicKey pubkey;

    private ServerECCPubKey() {
        String fileContentString;
        try (BufferedReader br = new BufferedReader(new FileReader(getKeyFilePath()))) {
            StringBuilder fileContent = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) {
                fileContent.append(line).append(System.lineSeparator());
            }
            fileContentString = fileContent.toString();
        } catch (IOException e) {
            throw new RuntimeException(format("Could not read key file '%s'%n", getKeyFilePath()), e);
        }
        Matcher matcher = KEY_FILE_PATTERN.matcher(fileContentString);
        if (!matcher.find()) {
            throw new RuntimeException(format("Could not parse key file '%s'%n", getKeyFilePath()));
        }
        curve = matcher.group("curve");
        byte[] pubkeyBytes = hexToBytes(matcher.group("pubkey"));
        try {
            pubkey = CryptoUtils.reconstructECCPublicKeyFromBytes(pubkeyBytes);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(format("Could not reconstruct key pair from key file '%s'%n", getKeyFilePath()), e);
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

    public static String getKeyFilePath() {
        return keyfilePath != null ? keyfilePath : DEFAULT_SERVER_KEYFILE_PATH;
    }

    public static void setKeyFilePath(String path) {
        keyfilePath = path;
    }
}
