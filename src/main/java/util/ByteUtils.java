package util;

import java.util.Arrays;

public class ByteUtils {
    /**
     * Utility method to convert bytes to hex string
     */
    public static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }

    /**
     * Utility method to convert hex string to bytes
     */
    public static byte[] hexToBytes(String hex) {
        if (hex == null || hex.length() % 2 != 0) {
            throw new IllegalArgumentException("Invalid hex string");
        }

        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < hex.length(); i += 2) {
            String byteStr = hex.substring(i, i + 2);
            bytes[i / 2] = (byte) Integer.parseInt(byteStr, 16);
        }
        return bytes;
    }

    /**
     * Function to split a byte into two nibbles
     */
    public static int[] byteToNibbles(byte inputByte) {
        int highNibble = (inputByte >> 4) & 0x0F;
        int lowNibble = inputByte & 0x0F;
        return new int[]{highNibble, lowNibble};
    }

    /**
     * Function to combine two nibbles into a byte
     */
    public static byte nibblesToByte(int highNibble, int lowNibble) {
        // Ensure nibbles are within valid range (0-15)
        highNibble = highNibble & 0x0F;
        lowNibble = lowNibble & 0x0F;
        return (byte)((highNibble << 4) | lowNibble);
    }

    /**
     * Increment a 128-bit number represented as a byte array
     */
    public static void incrementByteNumber(byte[] number) {

        // Start from the least significant byte (end of the array)
        for (int i = number.length - 1; i >= 0; i--) {
            number[i]++;
            if (number[i] != 0) {
                // If there is no carry (byte does not overflow), stop
                break;
            }
        }
    }

    /**
     * Compare two byte arrays as unsigned big-endian numbers
     *
     * @param a First byte array to compare
     * @param b Second byte array to compare
     * @return Negative if a < b, 0 if a == b, Positive if a > b
     */
    public static int compareByteArrayNumbers(byte[] a, byte[] b) {
        // Ensure arrays are same length by padding with zeros if needed
        int maxLength = Math.max(a.length, b.length);
        byte[] paddedA = new byte[maxLength];
        byte[] paddedB = new byte[maxLength];

        System.arraycopy(a, 0, paddedA, maxLength - a.length, a.length);
        System.arraycopy(b, 0, paddedB, maxLength - b.length, b.length);

        // Compare byte by byte
        for (int i = 0; i < maxLength; i++) {
            // Convert to unsigned comparison
            int unsignedA = paddedA[i] & 0xFF;
            int unsignedB = paddedB[i] & 0xFF;

            if (unsignedA != unsignedB) {
                return Integer.compare(unsignedA, unsignedB);
            }
        }

        return 0;
    }

    /**
     * Check if one byte array is exactly 1 larger than another
     *
     * @param base The base byte array
     * @param compare The array to compare against base
     * @return true if compare is exactly 1 larger than base, false otherwise
     */
    public static boolean isExactlyOnelarger(byte[] base, byte[] compare) {
        // Arrays must be the same length
        if (base.length != compare.length) {
            return false;
        }

        // Create a copy of base to increment
        byte[] incrementedBase = Arrays.copyOf(base, base.length);
        incrementByteNumber(incrementedBase);

        // Compare incrementedBase with compare
        return Arrays.equals(incrementedBase, compare);
    }

    /**
     * Utility method to get the base algorithm
     *
     * e.g. get 'AES' from 'AES/CTR/NoPadding'
     * @param fullAlgorithm
     * @return
     */
    public static String getBaseAlgorithm(final String fullAlgorithm) {
        return fullAlgorithm.split("/")[0];
    }
}
