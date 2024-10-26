package dstp.socket;

import dstp.config.DSTPConfig;
import dstp.crypto.CryptoProvider;
import dstp.crypto.CryptoProviderFactory;

import java.io.IOException;
import java.net.*;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import static dstp.util.Utils.hexToBytes;


public class DSTPSocket extends MulticastSocket {
    private final CryptoProvider cryptoProvider;
    private final DSTPConfig config;

    public DSTPSocket(final String configpath) throws IOException {
        super();
        this.config = new DSTPConfig(configpath);
        this.cryptoProvider = CryptoProviderFactory.createProvider(config);
    }

    public DSTPSocket(final InetSocketAddress inetSocketAddress, final String configpath) throws IOException {
        super(inetSocketAddress);
        this.config = new DSTPConfig(configpath);
        this.cryptoProvider = CryptoProviderFactory.createProvider(config);
    }

    public DSTPSocket(int port, final String configpath) throws IOException {
        super(port);
        this.config = new DSTPConfig(configpath);
        this.cryptoProvider = CryptoProviderFactory.createProvider(config);
    }

    public DSTPSocket(SocketAddress bindaddr, final String configpath) throws IOException {
        super(bindaddr);
        this.config = new DSTPConfig(configpath);
        this.cryptoProvider = CryptoProviderFactory.createProvider(config);
    }

    @Override
    public void send(DatagramPacket packet) throws IOException {
        try {
            // Extract the original data
            byte[] originalData = Arrays.copyOfRange(packet.getData(),
                    packet.getOffset(), packet.getLength());

            // Apply security transforms
            byte[] encryptedData = cryptoProvider.encrypt(originalData, hexToBytes(config.getSymmetric_key()));
            byte[] integrityBytes = cryptoProvider.generateIntegrityCheck(encryptedData, hexToBytes(config.getMackey()));

            // Create secured packet
            DSTPPacket securePacket = new DSTPPacket(encryptedData, integrityBytes);
            byte[] serializedPacket = securePacket.serialize();

            // Send the secured packet
            DatagramPacket securedDatagram = new DatagramPacket(
                    serializedPacket, serializedPacket.length,
                    packet.getAddress(), packet.getPort()
            );
            super.send(securedDatagram);

        } catch (GeneralSecurityException e) {
            throw new IOException("Security operation failed", e);
        }
    }

    @Override
    public void receive(DatagramPacket packet) throws IOException {
        // Receive the raw packet
        super.receive(packet);

        try {
            // Parse the secure packet
            DSTPPacket securePacket = DSTPPacket.deserialize(
                    packet.getData(), packet.getOffset(), packet.getLength()
            );

            // Verify security properties
            if (!cryptoProvider.verifyIntegrityCheck(securePacket.getEncryptedData(),
                    securePacket.getIntegrityBytes(), hexToBytes(config.getMackey()))) {
                throw new SecurityException("Integrity verification failed");
            }

            // Decrypt the data
            byte[] decryptedData = cryptoProvider.decrypt(
                    securePacket.getEncryptedData(), hexToBytes(config.getSymmetric_key())
            );

            // Update the packet with decrypted data
            packet.setData(decryptedData);

        } catch (GeneralSecurityException e) {
            throw new IOException("Security operation failed", e);
        }
    }
}
