package dstp;

import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;

public class DSTPPacket {
    private final byte[] encryptedData;
    private final byte[] integrityBytes;

    public DSTPPacket(byte[] encryptedData, byte[] mac) {
        this.encryptedData = encryptedData;
        this.integrityBytes = mac;
    }

    public byte[] serialize() {
        // Calculate total length needed
        int totalLength = 4 + encryptedData.length +  // Length + encrypted data
                4 + integrityBytes.length;                        // Length + MAC

        ByteBuffer buffer = ByteBuffer.allocate(totalLength);

        // Write encrypted data with length prefix
        buffer.putInt(encryptedData.length);
        buffer.put(encryptedData);

        // Write MAC with length prefix
        buffer.putInt(integrityBytes.length);
        buffer.put(integrityBytes);

        return buffer.array();
    }

    public static DSTPPacket deserialize(byte[] data, int offset, int length)
            throws IOException {
        ByteBuffer buffer = ByteBuffer.wrap(data, offset, length);

        try {
            // Read encrypted data
            int encryptedLength = buffer.getInt();
            if (encryptedLength < 0 || encryptedLength > length - 8) {
                throw new IOException("Invalid encrypted data length");
            }
            byte[] encryptedData = new byte[encryptedLength];
            buffer.get(encryptedData);

            // Read MAC
            int macLength = buffer.getInt();
            if (macLength < 0 || macLength > length - encryptedLength - 8) {
                throw new IOException("Invalid MAC length");
            }
            byte[] mac = new byte[macLength];
            buffer.get(mac);

            return new DSTPPacket(encryptedData, mac);

        } catch (BufferUnderflowException e) {
            throw new IOException("Packet data truncated", e);
        }
    }

    // Getters for the fields
    public byte[] getEncryptedData() { return encryptedData; }
    public byte[] getIntegrityBytes() { return integrityBytes; }
}
