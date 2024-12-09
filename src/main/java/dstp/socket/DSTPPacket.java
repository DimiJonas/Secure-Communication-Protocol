package dstp.socket;

import java.nio.ByteBuffer;

public class DSTPPacket {
    public static final short version = 1;
    public static final byte release = 0;
    private static final int VERSION_LENGTH = 2;
    private static final int RELEASE_LENGTH = 1;
    private static final int DATA_LENGTH_FIELD = 4;
    private static final int INTEGRITY_LENGTH_FIELD = 4;
    private static final int SEQUENCE_NUM_LENGTH = 2;

    private final byte[] encryptedData;
    private final int dataLength;
    private final byte[] integrityBytes;
    private final int integrityLength;
    private final short sequenceNumber;

    public DSTPPacket(byte[] encryptedData, byte[] integrityBytes, short sequenceNumber) {
        this.encryptedData = encryptedData;
        this.dataLength = encryptedData.length;
        this.integrityBytes = integrityBytes;
        this.integrityLength = integrityBytes.length;
        this.sequenceNumber = sequenceNumber;
    }

    public byte[] serialize() {
        // Calculate total length needed
        int headerLength = VERSION_LENGTH + RELEASE_LENGTH + DATA_LENGTH_FIELD + INTEGRITY_LENGTH_FIELD;
        int payloadLength = SEQUENCE_NUM_LENGTH + dataLength + integrityBytes.length;
        int totalLength = headerLength + payloadLength;

        ByteBuffer buffer = ByteBuffer.allocate(totalLength);
        buffer.putShort(version);
        buffer.put(release);
        buffer.putInt(dataLength);
        buffer.putInt(integrityLength);
        buffer.putShort(sequenceNumber);
        buffer.put(encryptedData);
        buffer.put(integrityBytes);

        return buffer.array();
    }

    public static DSTPPacket deserialize(byte[] data, int offset, int length) {
        ByteBuffer buffer = ByteBuffer.wrap(data, offset, length);

        if (buffer.remaining() < length) {
            throw new IllegalArgumentException("Insufficient data for packet deserialization. Actual: " + buffer.remaining() + " Expected: " + length);
        }

        short version = buffer.getShort();
        byte release = buffer.get();
        int dataLength = buffer.getInt();
        int integrityLength = buffer.getInt();

        if (buffer.remaining() < SEQUENCE_NUM_LENGTH + dataLength + integrityLength) {
            throw new IllegalArgumentException("Not enough remaining bytes in the packet! Actual: " + buffer.remaining() + " Expected: " + (SEQUENCE_NUM_LENGTH + dataLength + integrityLength));
        }

        short sequenceNumber = buffer.getShort();

        if (dataLength < 0 || dataLength > buffer.remaining()) {
            throw new IllegalArgumentException("Invalid data length given: " + dataLength + " Remaining bytes in buffer: " + buffer.remaining());
        }

        byte[] encryptedData = new byte[dataLength];
        buffer.get(encryptedData);

        if (integrityLength > buffer.remaining()) {
            throw new IllegalArgumentException("Invalid integrity length given: " + integrityLength + " Remaining bytes in buffer: " + buffer.remaining());
        }
        byte[] integrityBytes = new byte[integrityLength];
        buffer.get(integrityBytes);

        return new DSTPPacket(encryptedData, integrityBytes, sequenceNumber);
    }

    // Getters for the fields
    public byte[] getEncryptedData() {
        return encryptedData;
    }

    public byte[] getIntegrityBytes() {
        return integrityBytes;
    }

    public short getSequenceNumber() {
        return sequenceNumber;
    }
}
