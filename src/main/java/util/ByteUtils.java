package util;

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
