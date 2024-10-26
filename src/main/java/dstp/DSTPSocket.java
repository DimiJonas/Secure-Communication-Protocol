package dstp;

import dstp.config.DSTPConfig;
import dstp.util.Utils;

import java.io.IOException;
import java.net.*;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import static dstp.util.Utils.hexToBytes;


public class DSTPSocket extends MulticastSocket {
    private static final String cryptoconfig = "cryptoconfig.txt";
    private final CryptoProvider cryptoProvider;
    private final DSTPConfig config;
//    private final SecretKey encryptionKey;
//    private final SecretKey macKey;

    public DSTPSocket() throws IOException {
        super();
        this.config = new DSTPConfig(cryptoconfig);
        this.cryptoProvider = CryptoProviderFactory.createProvider(config);

//        this.encryptionKey = new SecretKeySpec(config.getSymmetric_key().getBytes(), config.getConfidentiality().getAlgorithm());
//        this.macKey = new SecretKeySpec(Base64.getDecoder().decode(config.getMackey()), config.getMac().getAlgorithm());
    }

    public DSTPSocket(InetSocketAddress inetSocketAddress) throws IOException {
        super(inetSocketAddress);
        this.config = new DSTPConfig(cryptoconfig);
        this.cryptoProvider = CryptoProviderFactory.createProvider(config);
    }

    public DSTPSocket(int port) throws IOException {
        super(port);
        this.config = new DSTPConfig(cryptoconfig);
        this.cryptoProvider = CryptoProviderFactory.createProvider(config);
    }

    public DSTPSocket(SocketAddress bindaddr) throws IOException {
        super(bindaddr);
        this.config = new DSTPConfig(cryptoconfig);
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
