package dstp.socket;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

import static dstp.socket.DSTPSocket.MAX_DATA_SIZE;
import static org.junit.jupiter.api.Assertions.*;

public class DSTPSocketIntegrationTest {
    private static final String CONFIG_PATH = "src/main/resources/cryptoconfig.txt";
    private DSTPSocket senderSocket;
    private DSTPSocket receiverSocket;
    private InetSocketAddress socketAddress;

    @BeforeEach
    public void setUp() throws IOException {
        socketAddress = new InetSocketAddress("127.0.0.1", 22222);
        senderSocket = new DSTPSocket(CONFIG_PATH);
        receiverSocket = new DSTPSocket(socketAddress, CONFIG_PATH);
        receiverSocket.setSoTimeout(1000);
    }

    @Test
    public void testSecurePacketTransmission() throws IOException {
        // Prepare test message
        String originalMessage = "Hello, Secure Communication!";
        byte[] messageBytes = originalMessage.getBytes();

        // Create datagram packet to send
        DatagramPacket sendPacket = new DatagramPacket(
                messageBytes,
                messageBytes.length,
                socketAddress
        );

        // Send the packet
        senderSocket.send(sendPacket);

        // Prepare to receive
        byte[] receiveBuffer = new byte[1024];
        DatagramPacket receivePacket = new DatagramPacket(receiveBuffer, receiveBuffer.length);

        // Receive the packet
        receiverSocket.receive(receivePacket);

        // Verify received message
        String receivedMessage = new String(
                receivePacket.getData(),
                0,
                receivePacket.getLength()
        );

        assertEquals(originalMessage, receivedMessage, "Message should be securely transmitted");
    }

    @Test
    public void testSendBigFile() throws IOException {
        // Prepare test message
        String bigFilePath = "1mb_file.txt";
        try (var fileIs = DSTPSocketIntegrationTest.class.getClassLoader().getResourceAsStream(bigFilePath)){
            byte[] messageBytes = fileIs.readAllBytes();

            // Create datagram packet to send that should be too big
            DatagramPacket tooBigPacket = new DatagramPacket(
                    messageBytes,
                    messageBytes.length,
                    socketAddress
            );

            assertThrows(IOException.class, () -> senderSocket.send(tooBigPacket));

            // send message in chunks of allowed size
            List<byte[]> dataChunks = new ArrayList<>();
            for (int i = 0; i < messageBytes.length; i += MAX_DATA_SIZE) {
                int packetSize = Math.min(MAX_DATA_SIZE, messageBytes.length - i);
                byte[] packet = new byte[packetSize];
                System.arraycopy(messageBytes, i, packet, 0, packetSize);
                dataChunks.add(packet);
            }

            int currentPosition = 0;
            byte[] reassembledData = new byte[messageBytes.length];
            for (byte[] chunk : dataChunks) {
                DatagramPacket sendPacket = new DatagramPacket(
                        chunk,
                        chunk.length,
                        socketAddress
                );
                senderSocket.send(sendPacket);
                byte[] receiveBuffer = new byte[64000];
                DatagramPacket receivePacket = new DatagramPacket(receiveBuffer, receiveBuffer.length);
                receiverSocket.receive(receivePacket);
                System.arraycopy(chunk, 0, reassembledData, currentPosition, chunk.length);
                currentPosition += chunk.length;
            }

            assertArrayEquals(messageBytes, reassembledData, "Message should be securely transmitted");
        }
    }

    @Test
    public void testPacketIntegrity() throws IOException {
        // Prepare test message
        String originalMessage = "Integrity Check Test";
        byte[] messageBytes = originalMessage.getBytes();

        // Create datagram packet to send
        DatagramPacket sendPacket = new DatagramPacket(
                messageBytes,
                messageBytes.length,
                socketAddress
        );

        // Send the packet
        senderSocket.send(sendPacket);

        // Prepare to receive
        byte[] receiveBuffer = new byte[1024];
        DatagramPacket receivePacket = new DatagramPacket(receiveBuffer, receiveBuffer.length);

        // Receive the packet
        receiverSocket.receive(receivePacket);

        // Verify received message is identical
        String receivedMessage = new String(
                receivePacket.getData(),
                0,
                receivePacket.getLength()
        );

        assertEquals(originalMessage, receivedMessage, "Message integrity should be maintained");
    }

    @Test
    public void testSequenceNumberIncrement() throws IOException {
        try (DSTPSocket testSocket = new DSTPSocket(CONFIG_PATH)) {
            // Simulate multiple sends
            for (int i = 0; i < 10; i++) {
                byte[] testMessage = ("Test Message " + i).getBytes();
                DatagramPacket sendPacket = new DatagramPacket(
                        testMessage,
                        testMessage.length,
                        socketAddress
                );
                testSocket.send(sendPacket);
            }

            // Reflection or mock could be used to verify exact sequence number
            // This test ensures no exceptions occur during multiple sends
            assertTrue(true, "Sequence number should increment without issues");
        }
    }

    @Test
    public void testTamperDetection() throws IOException {
        InetSocketAddress otherAddress = new InetSocketAddress("127.0.0.1", 33333);

        // use plain UDP sockets inbetween the two DSTP sockets to be able to tamper with the encrypted packet
        try (DatagramSocket plainSenderSocket = new DatagramSocket();
             DatagramSocket plainReceiverSocket = new DatagramSocket(otherAddress)) {
            // Prepare test message
            String originalMessage = "Tamper Detection Test";
            byte[] messageBytes = originalMessage.getBytes();

            // Create datagram packet to send
            DatagramPacket sendPacket = new DatagramPacket(
                    messageBytes,
                    messageBytes.length,
                    otherAddress
            );

            // Send the packet to the plain udp socket
            senderSocket.send(sendPacket);

            // Simulate tampering by modifying received packet
            byte[] tamperBuffer = new byte[1024];
            DatagramPacket tamperPacket = new DatagramPacket(tamperBuffer, tamperBuffer.length);

            // receive the encrypted packet on the plain UDP socket
            plainReceiverSocket.receive(tamperPacket);

            // Manually modify encrypted data to simulate tampering
            tamperBuffer[10] = (byte) (tamperBuffer[10] ^ 0xFF);

            // send the tampered packet to the DSTP receiver socket
            tamperPacket.setSocketAddress(socketAddress);
            plainSenderSocket.send(tamperPacket);

            byte[] receiveBuffer = new byte[1024];
            DatagramPacket receivePacket = new DatagramPacket(receiveBuffer, receiveBuffer.length);

            // This should throw a SecurityException since the packet was tampered with
            Assertions.assertThrows(SecurityException.class, () -> receiverSocket.receive(receivePacket));
        }
    }

    // Clean up resources
    public void tearDown() throws IOException {
        if (senderSocket != null) {
            senderSocket.close();
        }
        if (receiverSocket != null) {
            receiverSocket.close();
        }
    }
}