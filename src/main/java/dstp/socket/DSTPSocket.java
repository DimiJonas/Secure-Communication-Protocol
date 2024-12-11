package dstp.socket;

import dstp.config.DSTPConfig;
import crypto.CryptoProvider;
import crypto.CryptoProviderFactory;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.io.IOException;
import java.net.*;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import static util.ByteUtils.hexToBytes;


public class DSTPSocket extends MulticastSocket {
    private final CryptoProvider cryptoProvider;
    private final DSTPConfig config;
    private short sequenceNumber = 0;

    public static final int MAX_DATA_SIZE = 60000;
    private static final int MAX_PACKET_SIZE = 65536;

    public DSTPSocket(final String configpath) throws IOException {
        super();
        this.config = new DSTPConfig(configpath);
        this.cryptoProvider = CryptoProviderFactory.createBouncyCastleProvider(config);
    }

    public DSTPSocket(final InetSocketAddress inetSocketAddress, final String configpath) throws IOException {
        super(inetSocketAddress);
        this.config = new DSTPConfig(configpath);
        this.cryptoProvider = CryptoProviderFactory.createBouncyCastleProvider(config);
    }

    public DSTPSocket(int port, final String configpath) throws IOException {
        super(port);
        this.config = new DSTPConfig(configpath);
        this.cryptoProvider = CryptoProviderFactory.createBouncyCastleProvider(config);
    }

    public DSTPSocket(SocketAddress bindaddr, final String configpath) throws IOException {
        super(bindaddr);
        this.config = new DSTPConfig(configpath);
        this.cryptoProvider = CryptoProviderFactory.createBouncyCastleProvider(config);
    }

    public DSTPSocket(final DSTPConfig config) throws IOException {
        super();
        this.config = config;
        this.cryptoProvider = CryptoProviderFactory.createBouncyCastleProvider(config);
    }

    public DSTPSocket(final InetSocketAddress inetSocketAddress, final DSTPConfig config) throws IOException {
        super(inetSocketAddress);
        this.config = config;
        this.cryptoProvider = CryptoProviderFactory.createBouncyCastleProvider(config);
    }

    public DSTPSocket(int port, final DSTPConfig config) throws IOException {
        super(port);
        this.config = config;
        this.cryptoProvider = CryptoProviderFactory.createBouncyCastleProvider(config);
    }

    public DSTPSocket(SocketAddress bindaddr, final DSTPConfig config) throws IOException {
        super(bindaddr);
        this.config = config;
        this.cryptoProvider = CryptoProviderFactory.createBouncyCastleProvider(config);
    }

    @Override
    public void send(DatagramPacket packet) throws IOException {
        try {
            // Extract the original data
            byte[] originalData = Arrays.copyOfRange(packet.getData(), packet.getOffset(), packet.getLength());
            // reject packets that are too long
            if (originalData.length > MAX_DATA_SIZE) {
                throw new SocketException("Packet too large. Max allowed size is " + MAX_DATA_SIZE);
            }
            // Apply security transforms
            byte[] encryptedData = cryptoProvider.encrypt(originalData, hexToBytes(config.getSymmetric_key()));
            byte[] integrityBytes = cryptoProvider.generateIntegrityCheck(encryptedData, hexToBytes(config.getMackey()));

            // Create secured packet
            DSTPPacket securePacket = new DSTPPacket(encryptedData, integrityBytes, sequenceNumber);
            sequenceNumber++;
            byte[] serializedPacket = securePacket.serialize();
            // Send the secured packet
            DatagramPacket securedDatagram = new DatagramPacket(
                    serializedPacket, serializedPacket.length,
                    packet.getAddress(), packet.getPort()
            );
            super.send(securedDatagram);
        } catch (GeneralSecurityException | InvalidCipherTextException e) {
            throw new IOException("Security operation failed", e);
        }
    }

    @Override
    public void receive(DatagramPacket packet) throws IOException {
        // Creating a maximum sized buffer to receive all data
        // Needed because the TFTP application does not consider that there is data (security overhead) added
        // to the packet thus puts a buffer in the datagram that is too small
        byte[] originalBuffer = packet.getData();
        packet.setData(new byte[MAX_PACKET_SIZE]);
        super.receive(packet);
        try {
            // Parse the secure packet
            DSTPPacket securePacket = DSTPPacket.deserialize(packet.getData(), packet.getOffset(), packet.getLength());
            // Verify security properties
            if (!cryptoProvider.verifyIntegrityCheck(securePacket.getEncryptedData(),
                    securePacket.getIntegrityBytes(), hexToBytes(config.getMackey()))) {
                throw new SecurityException("Integrity verification failed");
            }

            // Decrypt the data
            byte[] decryptedData = cryptoProvider.decrypt(securePacket.getEncryptedData(), hexToBytes(config.getSymmetric_key()));
            // Copy the decrypted data to the original packet
            if(originalBuffer.length < decryptedData.length) {
                throw new IOException("Supplied receive packet buffer too small for decrypted data. Required: "
                        + decryptedData.length + " Supplied: " + originalBuffer.length);
            }
            System.arraycopy(decryptedData, 0, originalBuffer, 0, decryptedData.length);
            packet.setData(originalBuffer);
            packet.setLength(decryptedData.length);

        } catch (GeneralSecurityException | InvalidCipherTextException e) {
            throw new IOException("Security operation failed", e);
        }
    }
}
