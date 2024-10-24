import config.DSTPConfig;
import exception.InvalidConfigurationException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Base64;

public class DSTPSocket extends DatagramSocket {
    private final CryptoProvider cryptoProvider;
    private final DSTPConfig config;
    private final SecretKey encryptionKey;
    private final SecretKey macKey;

    public DSTPSocket(DSTPConfig config, InetSocketAddress inetSocketAddress) throws IOException, GeneralSecurityException, InvalidConfigurationException {
        super(inetSocketAddress);
        this.config = config;
        this.cryptoProvider = CryptoProviderFactory.createProvider(config);

        this.encryptionKey = new SecretKeySpec(config.getSymmetric_key().getBytes(), config.getConfidentiality().getAlgorithm());
        this.macKey = new SecretKeySpec(Base64.getDecoder().decode(config.getMackey()), config.getMac().getAlgorithm());
    }

    @Override
    public void send(DatagramPacket packet) throws IOException {
        try {
            // Extract the original data
            byte[] originalData = Arrays.copyOfRange(packet.getData(),
                    packet.getOffset(), packet.getLength());

            // Apply security transforms
            byte[] encryptedData = cryptoProvider.encrypt(originalData, encryptionKey.getEncoded());
            byte[] mac = cryptoProvider.generateMac(encryptedData, macKey.getEncoded());

            // Create secured packet
            DSTPPacket securePacket = new DSTPPacket(encryptedData, mac);
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
            if (!cryptoProvider.verifyMac(securePacket.getEncryptedData(),
                    securePacket.getMac(), macKey.getEncoded())) {
                throw new SecurityException("MAC verification failed");
            }

            // Decrypt the data
            byte[] decryptedData = cryptoProvider.decrypt(
                    securePacket.getEncryptedData(), encryptionKey.getEncoded()
            );

            // Update the packet with decrypted data
            packet.setData(decryptedData);

        } catch (GeneralSecurityException e) {
            throw new IOException("Security operation failed", e);
        }
    }
}
