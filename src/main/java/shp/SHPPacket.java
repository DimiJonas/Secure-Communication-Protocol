package shp;

import java.nio.ByteBuffer;

import static util.ByteUtils.byteToNibbles;
import static util.ByteUtils.nibblesToByte;

public class SHPPacket {
    private static final int version = 1;
    private static final int release = 0;
    private static final float VERSION_LENGTH = 0.5f;
    private static final float RELEASE_LENGTH = 0.5f;
    private static final int TYPE_LENGTH = 1;

    private final MessageType type;
    protected byte[] payload;

    public SHPPacket(byte[] payload, MessageType type) {
        this.payload = payload;
        this.type = type;
    }

    public static int headerLength() {
        return (int) (VERSION_LENGTH + RELEASE_LENGTH + TYPE_LENGTH);
    }

    public static MessageType extractMessageType(byte[] header) {
        return MessageType.getTypeFromString(String.valueOf(header[1]));
    }

    public byte[] serialize() {
        int totalLength = headerLength() + payload.length;

        ByteBuffer buffer = ByteBuffer.allocate(totalLength);
        byte versionRelease = nibblesToByte(version, release);
        buffer.put(versionRelease);
        buffer.put(type.getValue());
        buffer.put(payload);
        return buffer.array();
    }

    public SHPPacket deserialize(byte[] data, int offset, int length) {
        ByteBuffer buffer = ByteBuffer.wrap(data, offset, length);

        if (buffer.remaining() < length) {
            throw new IllegalArgumentException("Insufficient data for packet deserialization. Actual: " + buffer.remaining() + " Expected: " + length);
        }

        int[] versionRelease = byteToNibbles(buffer.get());
        int version = versionRelease[0];
        int release = versionRelease[1];
        MessageType type = MessageType.valueOf(String.valueOf(buffer.get()));
        byte[] payload = new byte[buffer.remaining()];

        return new SHPPacket(payload, type);
    }

    public MessageType getType() {
        return type;
    }

    public byte[] getData() {
        return payload;
    }
}
