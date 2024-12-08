package dstp.socket;

import java.nio.ByteBuffer;

public class DSTPPacket {
    public static final short version = 2;
    public static final byte release = 0;
    private static final int VERSION_LENGTH = 2;
    private static final int RELEASE_LENGTH = 1;
    private static final int TOTAL_FRAGMENTS = 2;
    private static final int FRAGMENT_INDEX = 2;
    private static final int PAYLOAD_LENGTH_FIELD = 4;
    private static final int SEQUENCE_NUM_LENGTH = 2;

    private final byte[] encryptedData;
    private final byte[] integrityBytes;
    private final short sequenceNumber;
    private final short totalFragments;
    private final short fragmentIndex;

    public DSTPPacket(byte[] encryptedData, byte[] integrityBytes, short sequenceNumber) {
        this.encryptedData = encryptedData;
        this.integrityBytes = integrityBytes;
        this.sequenceNumber = sequenceNumber;
        this.totalFragments = 1;
        this.fragmentIndex = 0;
    }

    public DSTPPacket(byte[] encryptedData, byte[] integrityBytes, short sequenceNumber, short totalFragments, short fragmentIndex) {
        this.encryptedData = encryptedData;
        this.integrityBytes = integrityBytes;
        this.sequenceNumber = sequenceNumber;
        this.totalFragments = totalFragments;
        this.fragmentIndex = fragmentIndex;
    }

    public byte[] serialize() {
        // Calculate total length needed
        int headerLength = VERSION_LENGTH + RELEASE_LENGTH + TOTAL_FRAGMENTS + FRAGMENT_INDEX + PAYLOAD_LENGTH_FIELD;
        int payloadLength = SEQUENCE_NUM_LENGTH + encryptedData.length + integrityBytes.length;
        int totalLength = headerLength + payloadLength;

        ByteBuffer buffer = ByteBuffer.allocate(totalLength);
        buffer.putShort(version);
        buffer.put(release);
        buffer.putShort(totalFragments);
        buffer.putShort(fragmentIndex);
        buffer.putInt(encryptedData.length);
        buffer.putShort(sequenceNumber);
        buffer.put(encryptedData);
        buffer.put(integrityBytes);

        return buffer.array();
    }

    public static DSTPPacket deserialize(byte[] data, int offset, int length) {
        ByteBuffer buffer = ByteBuffer.wrap(data, offset, length);

        if (buffer.remaining() < VERSION_LENGTH + RELEASE_LENGTH + TOTAL_FRAGMENTS + FRAGMENT_INDEX + PAYLOAD_LENGTH_FIELD + SEQUENCE_NUM_LENGTH) {
            throw new IllegalArgumentException("Insufficient data for packet deserialization");
        }

        short version = buffer.getShort();
        byte release = buffer.get();
        short totalFragments = buffer.getShort();
        short fragmentIndex = buffer.getShort();
        int dataLength = buffer.getInt();

        if (buffer.remaining() < SEQUENCE_NUM_LENGTH + dataLength) {
            throw new IllegalArgumentException("Insufficient data for encrypted payload");
        }

        short sequenceNumber = buffer.getShort();

        if (dataLength < 0 || dataLength > buffer.remaining()) {
            throw new IllegalArgumentException("Invalid data length: " + dataLength);
        }

        byte[] encryptedData = new byte[dataLength];
        buffer.get(encryptedData);
        // Extract remaining bytes as integrity bytes
        byte[] integrityBytes = new byte[buffer.remaining()];
        buffer.get(integrityBytes);

        return new DSTPPacket(encryptedData, integrityBytes, sequenceNumber, totalFragments, fragmentIndex);
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

    public short getTotalFragments() {
        return totalFragments;
    }

    public short getFragmentIndex() {
        return fragmentIndex;
    }
}
