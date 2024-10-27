package dstp.socket;

import dstp.config.DSTPConfig;
import dstp.config.TestConfigBuilder;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetSocketAddress;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class DSTPSocketTest {

    @Test
    public void testSendReceive() throws NoSuchAlgorithmException, IOException {
        String configPath = "src/test/resources/dstp_socket_test_config.txt";
        InetSocketAddress socketAddress = new InetSocketAddress("127.0.0.1", 11111);

        DSTPSocket sendingSocket = new DSTPSocket(configPath);
        DSTPSocket receivingSocket = new DSTPSocket(socketAddress, configPath);

        String message = "Hello, World!";
        byte[] messageBytes = message.getBytes();
        DatagramPacket sendPacket = new DatagramPacket(messageBytes, messageBytes.length, socketAddress);

        sendingSocket.send(sendPacket);

        byte[] receiveBuffer = new byte[4 * 1024];
        DatagramPacket receivePacket = new DatagramPacket(receiveBuffer, receiveBuffer.length);

        receivingSocket.receive(receivePacket);
        
        byte[] trimmedReceivedBytes = new byte[message.getBytes().length];
        System.arraycopy(receivePacket.getData(), 0, trimmedReceivedBytes, 0, trimmedReceivedBytes.length);
        String receivedMessage = new String(trimmedReceivedBytes);

        assertEquals(message, receivedMessage);
    }
}
