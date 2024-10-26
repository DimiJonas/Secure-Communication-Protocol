package dstp.util;

public class Utils {
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
}
