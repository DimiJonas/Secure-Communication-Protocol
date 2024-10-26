package dstp;

import dstp.config.DSTPConfig;
import dstp.config.TestConfigBuilder;
import dstp.socket.DSTPSocket;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetSocketAddress;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class DSTPSocketTest {

    @Test
    public void testSendReceive() throws NoSuchAlgorithmException, IOException {
        DSTPConfig config = new TestConfigBuilder()
                .generateSymmetricKey("AES/CTR/NoPadding", 128)
                .generateIv(16)
                .setIntegrity("hash")
                .setH("SHA-256")
                .build();
        InetSocketAddress socketAddress = new InetSocketAddress("127.0.0.1", 11111);

        DSTPSocket sendingSocket = new DSTPSocket("src/test/resources/dstp_socket_test_config.txt");
        DSTPSocket receivingSocket = new DSTPSocket(socketAddress, "src/test/resources/dstp_socket_test_config.txt");

        String message = "Hello, World!";
        byte[] messageBytes = message.getBytes();
        DatagramPacket sendPacket = new DatagramPacket(messageBytes, messageBytes.length, socketAddress);

        sendingSocket.send(sendPacket);

        byte[] buffer = new byte[4 * 1024];
        DatagramPacket receivePacket = new DatagramPacket(buffer, buffer.length);

        receivingSocket.receive(receivePacket);
        byte[] receivedBytes = receivePacket.getData();
        String receivedMessage = new String(receivedBytes);

        assertEquals(message, receivedMessage);
    }
}
