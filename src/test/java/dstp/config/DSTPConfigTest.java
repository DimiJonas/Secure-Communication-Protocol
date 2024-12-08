package dstp.config;

import org.junit.jupiter.api.Test;

import static dstp.config.DSTPConfig.Integrity.MAC;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class DSTPConfigTest {

    @Test
    public void testConfigParsesFileCorrectly_regularFile() {
        String configPath = "src/test/resources/regularconfigfile.txt";
        DSTPConfig dstpConfig = new DSTPConfig(configPath);
        assertEquals("AES/CTR/NoPadding", dstpConfig.getConfidentiality());
        assertEquals("ab15b9112e5ee3162174353d9bf153640bdbe1c9d846749181fc4b32272c2d00", dstpConfig.getSymmetric_key());
        assertEquals(256, dstpConfig.getSymmetric_key_size());
        assertEquals(128, dstpConfig.getIv_size());
        assertEquals(MAC, dstpConfig.getIntegrity());
        assertEquals("SHA512", dstpConfig.getH());
        assertEquals("HMACSHA512", dstpConfig.getMac());
        assertEquals("af843ef2ff8732dbbb66e3b15ebb45df4080731dd1fb70fb015f6eecfbfee8d2", dstpConfig.getMackey());
        assertEquals(256, dstpConfig.getMackey_size());
    }

    @Test
    public void testConfigParsesFileCorrectly_scuffedFile() {
        String configPath = "src/test/resources/scuffedconfigfile.txt";
        DSTPConfig dstpConfig = new DSTPConfig(configPath);
        assertEquals("AES/CTR/NoPadding", dstpConfig.getConfidentiality());
        assertEquals("abc", dstpConfig.getSymmetric_key());
        assertEquals(256, dstpConfig.getSymmetric_key_size());
        assertEquals(128, dstpConfig.getIv_size());
        assertEquals(MAC, dstpConfig.getIntegrity());
        assertEquals("", dstpConfig.getH());
        assertEquals("HMACSHA512", dstpConfig.getMac());
        assertEquals("", dstpConfig.getMackey());
        assertEquals(99999, dstpConfig.getMackey_size());
    }
}
