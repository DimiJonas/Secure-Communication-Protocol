package shp.client;

import shp.KeyFileManager;

public class ClientECCKeyPair extends KeyFileManager {
    private static final String CLIENT_KEYFILE_PATH = "src/main/resources/pa2/client/ClientECCKeyPair.sec";
    private static ClientECCKeyPair instance;

    private ClientECCKeyPair() {
        super(CLIENT_KEYFILE_PATH);
    }

    public static ClientECCKeyPair getInstance() {
        if (instance == null) {
            instance = new ClientECCKeyPair();
        }
        return instance;
    }
}
