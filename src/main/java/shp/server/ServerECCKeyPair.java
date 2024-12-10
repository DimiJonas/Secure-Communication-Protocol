package shp.server;

import shp.KeyFileManager;

public class ServerECCKeyPair extends KeyFileManager {
    private static final String SERVER_KEYFILE_PATH = "src/main/resources/pa2/server/ServerECCKeyPair.sec";
    private static ServerECCKeyPair instance;

    private ServerECCKeyPair() {
        super(SERVER_KEYFILE_PATH);
    }

    public static ServerECCKeyPair getInstance() {
        if (instance == null) {
            instance = new ServerECCKeyPair();
        }
        return instance;
    }
}
