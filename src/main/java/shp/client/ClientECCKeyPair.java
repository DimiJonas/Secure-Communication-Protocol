package shp.client;

import shp.KeyFileManager;

public class ClientECCKeyPair extends KeyFileManager {
    public static final String DEFAULT_CLIENT_KEYFILE_PATH = "src/main/resources/pa2/client/ClientECCKeyPair.sec";
    private static String keyfilePath;
    private static ClientECCKeyPair instance;

    private ClientECCKeyPair() {
        super(getKeyFilePath());
    }

    public static ClientECCKeyPair getInstance() {
        if (instance == null) {
            instance = new ClientECCKeyPair();
        }
        return instance;
    }

    public static String getKeyFilePath() {
        return keyfilePath != null ? keyfilePath : DEFAULT_CLIENT_KEYFILE_PATH;
    }

    public static void setKeyFilePath(String path) {
        keyfilePath = path;
    }
}
