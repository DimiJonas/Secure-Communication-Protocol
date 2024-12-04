package dstp.socket;

import dstp.config.DSTPConfig;
import dstp.config.TestConfigBuilder;
import dstp.crypto.CryptoProvider;
import dstp.crypto.CryptoProviderFactory;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;

import static dstp.util.Utils.hexToBytes;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class DSTPSocketTest {

    @Test
    public void testSendReceive() throws NoSuchAlgorithmException, IOException {
        String configPath = "src/test/resources/dstp_socket_test_config.txt";
        byte[] messageBytes = Files.readAllBytes(Path.of("src/test/resources/1mb_file.txt"));
        DatagramPacket receivePacket = getDatagramPacket(configPath, messageBytes);

        byte[] trimmedReceivedBytes = new byte[messageBytes.length];
        System.arraycopy(receivePacket.getData(), 0, trimmedReceivedBytes, 0, trimmedReceivedBytes.length);

        assertArrayEquals(messageBytes, receivePacket.getData());
    }

    private static DatagramPacket getDatagramPacket(String configPath, byte[] messageBytes) throws IOException {
        InetSocketAddress socketAddress = new InetSocketAddress("127.0.0.1", 11111);

        DSTPSocket sendingSocket = new DSTPSocket(configPath);
        DSTPSocket receivingSocket = new DSTPSocket(socketAddress, configPath);

        DatagramPacket sendPacket = new DatagramPacket(messageBytes, messageBytes.length, socketAddress);

        sendingSocket.send(sendPacket);

        byte[] receiveBuffer = new byte[4 * 1024];
        DatagramPacket receivePacket = new DatagramPacket(receiveBuffer, receiveBuffer.length);

        receivingSocket.receive(receivePacket);
        return receivePacket;
    }

    @Test
    void testChaCha20_poly1305() throws IOException, GeneralSecurityException {
        byte[] one_mb_file = Files.readAllBytes(Path.of("src/test/resources/1mb_file.txt"));
        System.out.println("original bytes length: " + one_mb_file.length);
        DSTPConfig config = new TestConfigBuilder()
                .generateSymmetricKey("ChaCha20", 256)
                .setAlgorithm("ChaCha20-Poly1305")
                .generateIv(16)
                .build();
        CryptoProvider cryptoProvider = CryptoProviderFactory.createProvider(config);
        byte[] encryptedBytes = cryptoProvider.encrypt(one_mb_file, hexToBytes(config.getSymmetric_key()));
        System.out.println("encrypted bytes length: " + encryptedBytes.length);
        byte[] decryptedBytes = cryptoProvider.decrypt(encryptedBytes, hexToBytes(config.getSymmetric_key()));
        System.out.println("decrypted bytes length: " + decryptedBytes.length);
        assertArrayEquals(one_mb_file, decryptedBytes);
    }
}
