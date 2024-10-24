import config.DSTPConfig;
import exception.InvalidConfigurationException;

import java.io.IOException;

public class Main {
    public static void main(String[] args) throws IOException, InvalidConfigurationException {
        // create a config object that read the specified file
        String configPath = "cryptoconfig.txt";
        DSTPConfig dstpConfig = new DSTPConfig(configPath);
    }
}
