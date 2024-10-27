package dstp.socket;

import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;

public class DSTPPacket {
    public static final short version = 1;
    public static final byte release = 0;
    private static final int VERSION_LENGTH = 2;
    private static final int RELEASE_LENGTH = 1;
    private static final int PAYLOAD_LENGTH_FIELD = 2;
    private static final int SEQUENCE_NUM_LENGTH = 2;

    private final byte[] encryptedData;
    private final byte[] integrityBytes;
    private final short sequenceNumber;

    public DSTPPacket(byte[] encryptedData, byte[] integrityBytes, short sequenceNumber) {
        this.encryptedData = encryptedData;
        this.integrityBytes = integrityBytes;
        this.sequenceNumber = sequenceNumber;
    }

    public byte[] serialize() {
        // Calculate total length needed
        short payloadLength = (short) (encryptedData.length);
        int totalLength = VERSION_LENGTH +
                RELEASE_LENGTH +
                PAYLOAD_LENGTH_FIELD +
                SEQUENCE_NUM_LENGTH +
                payloadLength +
                integrityBytes.length;

        ByteBuffer buffer = ByteBuffer.allocate(totalLength);
        buffer.putShort(version);
        buffer.put(release);
        buffer.putShort(payloadLength);
        buffer.putShort(sequenceNumber);
        buffer.put(encryptedData);
        buffer.put(integrityBytes);

        return buffer.array();
    }

    public static DSTPPacket deserialize(byte[] data, int offset, int length) {
        ByteBuffer buffer = ByteBuffer.wrap(data, offset, length);

        short version = buffer.getShort();
        byte release = buffer.get();
        short payloadLength = buffer.getShort();
        short sequenceNumber = buffer.getShort();
        byte[] encryptedData = new byte[payloadLength];
        buffer.get(encryptedData);
        // Extract remaining bytes as integrity bytes
        byte[] integrityBytes = new byte[buffer.remaining()];
        buffer.get(integrityBytes);

        return new DSTPPacket(encryptedData, integrityBytes, sequenceNumber);
    }

    // Getters for the fields
    public byte[] getEncryptedData() { return encryptedData; }
    public byte[] getIntegrityBytes() { return integrityBytes; }
    public short getSequenceNumber() { return sequenceNumber; }
}
