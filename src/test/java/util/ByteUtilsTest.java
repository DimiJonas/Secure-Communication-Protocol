package util;

import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;
import static util.ByteUtils.incrementByteNumber;
import static util.CryptoUtils.generateNonce;

class ByteUtilsTest {

    @Test
    void testBytesToHex() {
        byte[] input = {(byte)0xDE, (byte)0xAD, (byte)0xBE, (byte)0xEF};
        String expected = "deadbeef";
        assertEquals(expected, ByteUtils.bytesToHex(input));

        // Test empty array
        byte[] emptyInput = {};
        assertEquals("", ByteUtils.bytesToHex(emptyInput));
    }

    @Test
    void testHexToBytes() {
        String hex = "deadbeef";
        byte[] expected = {(byte)0xDE, (byte)0xAD, (byte)0xBE, (byte)0xEF};
        assertArrayEquals(expected, ByteUtils.hexToBytes(hex));

        // Test invalid hex string cases
        assertThrows(IllegalArgumentException.class, () -> ByteUtils.hexToBytes(null));
        assertThrows(IllegalArgumentException.class, () -> ByteUtils.hexToBytes("abc"));
        assertThrows(IllegalArgumentException.class, () -> ByteUtils.hexToBytes("abcg"));
    }

    @Test
    void testByteToNibbles() {
        // Test different byte values
        byte input1 = (byte)0xA5;  // Binary: 10100101
        int[] expected1 = {10, 5}; // High nibble: 10 (decimal), Low nibble: 5 (decimal)
        assertArrayEquals(expected1, ByteUtils.byteToNibbles(input1));

        byte input2 = (byte)0x0F;  // Binary: 00001111
        int[] expected2 = {0, 15};
        assertArrayEquals(expected2, ByteUtils.byteToNibbles(input2));
    }

    @Test
    void testNibblesToByte() {
        // Test combining nibbles into a byte
        int highNibble1 = 10;   // Hexadecimal: A
        int lowNibble1 = 5;     // Hexadecimal: 5
        byte expected1 = (byte)0xA5;
        assertEquals(expected1, ByteUtils.nibblesToByte(highNibble1, lowNibble1));

        // Test with overflow values
        int highNibble2 = 20;  // Will be masked to 4 (0x14 & 0x0F)
        int lowNibble2 = 30;   // Will be masked to 14 (0x1E & 0x0F)
        byte expected2 = (byte)0x4E;
        assertEquals(expected2, ByteUtils.nibblesToByte(highNibble2, lowNibble2));
    }

    @Test
    void testCompareByteArrayNumbers() {
        // Equal arrays
        byte[] a1 = {0x01, 0x02, 0x03};
        byte[] b1 = {0x01, 0x02, 0x03};
        assertEquals(0, ByteUtils.compareByteArrayNumbers(a1, b1));

        // Different length arrays but same number
        byte[] a2 = {0x00, 0x01, 0x02, 0x03};
        byte[] b2 = {0x01, 0x02, 0x03};
        assertEquals(0, ByteUtils.compareByteArrayNumbers(a2, b2));

        // Different values
        byte[] a3 = {(byte)0xFF, (byte)0xFF};
        byte[] b3 = {0x00, 0x00};
        assertTrue(ByteUtils.compareByteArrayNumbers(a3, b3) > 0);
        assertTrue(ByteUtils.compareByteArrayNumbers(b3, a3) < 0);
    }

    @Test
    void testIsExactlyOneLarger() {
        // Simple increment case
        byte[] base1 = {0x00, 0x01};
        byte[] compare1 = {0x00, 0x02};
        assertTrue(ByteUtils.isExactlyOnelarger(base1, compare1));

        // Carry over case
        byte[] base2 = {0x00, (byte)0xFF};
        byte[] compare2 = {0x01, 0x00};
        assertTrue(ByteUtils.isExactlyOnelarger(base2, compare2));

        // Increment at the end of 16-byte array
        byte[] base3 = new byte[16];
        base3[15] = (byte)0xFF;
        byte[] compare3 = new byte[16];
        compare3[14] = 0x01;
        assertTrue(ByteUtils.isExactlyOnelarger(base3, compare3));

        // False cases
        byte[] base4 = {0x00, 0x01};
        byte[] compare4 = {0x00, 0x03};
        assertFalse(ByteUtils.isExactlyOnelarger(base4, compare4));

        // Different length arrays
        byte[] base5 = {0x01, 0x02};
        byte[] compare5 = {0x01, 0x02, 0x03};
        assertFalse(ByteUtils.isExactlyOnelarger(base5, compare5));
    }

    @Test
    void testIncrementByteNumber() {
        // Test incrementing a simple case
        byte[] number1 = {(byte)0x00, (byte)0x01};
        incrementByteNumber(number1);
        assertArrayEquals(new byte[]{(byte)0x00, (byte)0x02}, number1);

        // Test carry over
        byte[] number2 = {(byte)0xFF, (byte)0xFF};
        incrementByteNumber(number2);
        assertArrayEquals(new byte[]{(byte)0x00, (byte)0x00}, number2);

        // Test 128-bit number (16 bytes)
        byte[] number3 = new byte[16];
        number3[15] = (byte)0xFF;  // Last byte is 0xFF
        incrementByteNumber(number3);
        assertEquals(0x00, number3[15]);
        assertEquals(0x01, number3[14]);
    }

    @Test
    void testIncrementNonce() throws NoSuchAlgorithmException {
        byte[] nonce = generateNonce(16);
        byte[] incrementedNonce = Arrays.copyOf(nonce, nonce.length);
        incrementByteNumber(incrementedNonce);
        assertFalse(Arrays.equals(nonce, incrementedNonce));
        assertNotEquals(0, ByteUtils.compareByteArrayNumbers(nonce, incrementedNonce));
        assertTrue(ByteUtils.isExactlyOnelarger(nonce, incrementedNonce));
    }

    @Test
    void testGetBaseAlgorithm() {
        assertEquals("AES", ByteUtils.getBaseAlgorithm("AES/CTR/NoPadding"));
        assertEquals("RSA", ByteUtils.getBaseAlgorithm("RSA/ECB/PKCS1Padding"));

        // Test with minimal algorithm name
        assertEquals("DES", ByteUtils.getBaseAlgorithm("DES"));
    }
}