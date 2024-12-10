package util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ByteUtilsTest {

    @Test
    public void testHexToBytes(){
        String hex = "48656c6c6f2c20576f726c6421";
        byte[] bytes = ByteUtils.hexToBytes(hex);
        String str = new String(bytes);
        assertEquals("Hello, World!", str);
    }

    @Test
    public void testBytesToHex(){
        String str = "Hello, World!";
        byte[] bytes = str.getBytes();
        String hex = ByteUtils.bytesToHex(bytes);
        assertEquals("48656c6c6f2c20576f726c6421", hex);
    }

    @Test
    public void testHexByteConversion(){
        String str = "Hello, World!";
        byte[] bytes = str.getBytes();
        String hex = ByteUtils.bytesToHex(bytes);
        bytes = ByteUtils.hexToBytes(hex);
        assertEquals(str, new String(bytes));
    }
}
