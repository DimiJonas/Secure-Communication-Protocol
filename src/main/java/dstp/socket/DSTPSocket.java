package dstp.socket;

import dstp.config.DSTPConfig;
import dstp.crypto.CryptoProvider;
import dstp.crypto.CryptoProviderFactory;
import dstp.util.Utils;

import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.*;

import static dstp.util.Utils.bytesToHex;
import static dstp.util.Utils.hexToBytes;


public class DSTPSocket extends MulticastSocket {
    private static final int MAX_FRAGMENT_SIZE = 60000; // 64KB

    private final CryptoProvider cryptoProvider;
    private final DSTPConfig config;
    private short sequenceNumber = 0;

    private Map<Short, List<DSTPPacket>> fragmentBuffer = new HashMap<>();

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

            // If data is larger than MAX_FRAGMENT_SIZE, fragment it
            if (originalData.length > MAX_FRAGMENT_SIZE) {
                sendFragmentedPacket(originalData, packet.getAddress(), packet.getPort());
            } else {
                sendSinglePacket(originalData, packet.getAddress(), packet.getPort());
            }

        } catch (GeneralSecurityException e) {
            throw new IOException("Security operation failed", e);
        }
    }

    private void sendFragmentedPacket(byte[] originalData, InetAddress address, int port) throws IOException, GeneralSecurityException {
        // Calculate total fragments
        int totalFragments = (int) Math.ceil((double) originalData.length / MAX_FRAGMENT_SIZE);

        for (int fragmentIndex = 0; fragmentIndex < totalFragments; fragmentIndex++) {
            // Calculate fragment details
            int offset = fragmentIndex * MAX_FRAGMENT_SIZE;
            int fragmentLength = Math.min(MAX_FRAGMENT_SIZE, originalData.length - offset);

            // Extract fragment
            byte[] fragmentData = Arrays.copyOfRange(originalData, offset, offset + fragmentLength);

            // Encrypt and generate integrity check for fragment
            byte[] encryptedData = cryptoProvider.encrypt(fragmentData, hexToBytes(config.getSymmetric_key()));
            byte[] integrityBytes = cryptoProvider.generateIntegrityCheck(encryptedData, hexToBytes(config.getMackey()));

            // Create fragmented packet with metadata
            DSTPPacket fragmentPacket = new DSTPPacket(
                    encryptedData,
                    integrityBytes,
                    sequenceNumber,
                    (short)totalFragments,
                    (short)fragmentIndex
            );

            // Serialize and send fragment
            byte[] serializedFragment = fragmentPacket.serialize();
            DatagramPacket fragmentDatagram = new DatagramPacket(
                    serializedFragment, serializedFragment.length, address, port
            );
            super.send(fragmentDatagram);
        }

        sequenceNumber++;
    }

    private void sendSinglePacket(byte[] originalData, InetAddress address, int port) throws IOException, GeneralSecurityException {
        // Apply security transforms
        byte[] encryptedData = cryptoProvider.encrypt(originalData, hexToBytes(config.getSymmetric_key()));
        byte[] integrityBytes = cryptoProvider.generateIntegrityCheck(encryptedData, hexToBytes(config.getMackey()));
        // Create secured packet
        DSTPPacket securePacket = new DSTPPacket(encryptedData, integrityBytes, sequenceNumber);
        sequenceNumber++;
        byte[] serializedPacket = securePacket.serialize();
        // Send the secured packet
        DatagramPacket securedDatagram = new DatagramPacket(serializedPacket, serializedPacket.length, address, port);
        super.send(securedDatagram);
    }

    @Override
    public void receive(DatagramPacket packet) throws IOException {
        // Receive the raw packet
        super.receive(packet);
        System.out.println("Received packet length: " + packet.getLength());
        System.out.println("Received packet data (hex): " + bytesToHex(packet.getData()));
        try {
            DSTPPacket securePacket;
            try {
                // Parse the secure packet
                securePacket = DSTPPacket.deserialize(
                        packet.getData(), packet.getOffset(), packet.getLength()
                );
            } catch (IllegalArgumentException e) {
                // Log the error or handle incomplete/malformed packets
                System.err.println("Received malformed packet: " + e.getMessage());
                return; // Skip this packet
            }
            // Verify security properties
            if (!cryptoProvider.verifyIntegrityCheck(securePacket.getEncryptedData(),
                    securePacket.getIntegrityBytes(), hexToBytes(config.getMackey()))) {
                throw new SecurityException("Integrity verification failed");
            }

            // Buffer fragments - unfragmented packets are also buffered to simplify the code
            fragmentBuffer.computeIfAbsent(securePacket.getSequenceNumber(), k -> new ArrayList<>())
                    .add(securePacket);

            // Check if all fragments are received
            List<DSTPPacket> fragments = fragmentBuffer.get(securePacket.getSequenceNumber());
            if (fragments.size() == securePacket.getTotalFragments()) {
                // Sort fragments
                fragments.sort(Comparator.comparingInt(DSTPPacket::getFragmentIndex));

                // Reassemble full packet
                byte[] reassembledData = reassembleFragments(fragments);

                // Decrypt reassembled data
                byte[] decryptedData = cryptoProvider.decrypt(reassembledData, hexToBytes(config.getSymmetric_key())
                );

                // Update the packet with decrypted data
                System.arraycopy(decryptedData, 0, packet.getData(), 0, decryptedData.length);
                packet.setLength(decryptedData.length);

                // Clear buffer
                fragmentBuffer.remove(securePacket.getSequenceNumber());
            }
        } catch (GeneralSecurityException e) {
            throw new IOException("Security operation failed", e);
        }
    }

    private byte[] reassembleFragments(List<DSTPPacket> fragments) {
        int totalLength = fragments.stream()
                .mapToInt(f -> f.getEncryptedData().length)
                .sum();

        ByteBuffer reassembledBuffer = ByteBuffer.allocate(totalLength);
        for (DSTPPacket fragment : fragments) {
            reassembledBuffer.put(fragment.getEncryptedData());
        }

        return reassembledBuffer.array();
    }
}
