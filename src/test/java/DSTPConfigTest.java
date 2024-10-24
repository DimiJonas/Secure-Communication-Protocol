import config.DSTPConfig;
import exception.InvalidConfigurationException;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertNotNull;

public class DSTPConfigTest {
    @Test
    public void testDSTPConfig() throws IOException, InvalidConfigurationException {
        String configPath = "src/test/resources/testconfig.txt";
        DSTPConfig dstpConfig = new DSTPConfig(configPath);
        assertNotNull(dstpConfig);
    }
}
