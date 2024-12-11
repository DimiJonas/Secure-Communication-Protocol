package shp.server;

import shp.KeyFileManager;

public class ServerECCKeyPair extends KeyFileManager {
    public static final String DEFAULT_SERVER_KEYFILE_PATH = "src/main/resources/pa2/server/ServerECCKeyPair.sec";
    private static String keyfilePath;
    private static ServerECCKeyPair instance;

    private ServerECCKeyPair() {
        super(getKeyFilePath());
    }

    public static ServerECCKeyPair getInstance() {
        if (instance == null) {
            instance = new ServerECCKeyPair();
        }
        return instance;
    }

    public static String getKeyFilePath() {
        return keyfilePath != null ? keyfilePath : DEFAULT_SERVER_KEYFILE_PATH;
    }

    public static void setKeyFilePath(String path) {
        keyfilePath = path;
    }
}
