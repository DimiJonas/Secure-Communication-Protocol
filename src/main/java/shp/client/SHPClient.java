package shp.client;

import crypto.CryptoProvider;
import crypto.CryptoProviderFactory;
import dstp.config.DSTPConfig;
import shp.MessageType;
import shp.SHPPacket;
import shp.SHPPacketFactory;
import shp.SHPResult;

import java.io.*;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Key;

import static shp.server.UserDB.SALT;
import static util.ByteUtils.bytesToHex;
import static util.ByteUtils.hexToBytes;
import static util.CryptoUtils.*;

public class SHPClient {

    private final String host;
    private final int tcpPort;
    private final String username;
    private final String password;
    private final String request;
    private final int udpPort;

    public SHPClient(String host, int tcpPort, String username, String password, String request, int udpPort) {
        this.host = host;
        this.tcpPort = tcpPort;
        this.username = username;
        this.password = password;
        this.request = request;
        this.udpPort = udpPort;
    }

    public SHPResult executeHandshake() {
        try (Socket socket = new Socket(host, tcpPort)) {
            // initialize tcp connection
            InputStream input = socket.getInputStream();
            OutputStream output = socket.getOutputStream();
            BufferedInputStream bufferedInput = new BufferedInputStream(input);
            BufferedOutputStream bufferedOutput = new BufferedOutputStream(output);

            // send packet 1
            SHPPacket msgOne = SHPPacketFactory.createTypeOnePacket(username);
            bufferedOutput.write(msgOne.serialize());

            // receive packet 2
            byte[] receivedData = new byte[SHPPacket.headerLength()];
            int bytesRead = bufferedInput.read(receivedData);
            if (bytesRead != SHPPacket.headerLength()) {
                throw new RuntimeException("Failed to read SHP packet 2 header");
            }

            MessageType packetType = SHPPacket.extractMessageType(receivedData);
            if (packetType != MessageType.TWO) {
                throw new RuntimeException("Expected SHP packet type 2, but received: " + packetType);
            }

            // handle packet 2
            byte[] nonceData = new byte[48];
            bytesRead = bufferedInput.read(nonceData);
            if (bytesRead != 48) {
                throw new RuntimeException("Failed to read nonce data");
            }
            ByteBuffer nonceBuffer = ByteBuffer.wrap(nonceData);
            byte[] nonce1 = new byte[16];
            nonceBuffer.get(nonce1);
            byte[] nonce2 = new byte[16];
            nonceBuffer.get(nonce2);
            byte[] nonce3 = new byte[16];
            nonceBuffer.get(nonce3);
            // TODO: check if nonces were received before
            // keep them in a list or map or something

            // create PBE key
            byte[] passwordHash = generatePasswordHash(password, SALT);
            Key pbeKey = generatePBEKey(bytesToHex(passwordHash).toCharArray());

            // send packet 3
            SHPPacket msgThree = SHPPacketFactory.createTypeThreePacket(request, username, nonce3, udpPort, pbeKey);
            bufferedOutput.write(msgThree.serialize());

            // receive packet 4
            receivedData = new byte[SHPPacket.headerLength()];
            bytesRead = bufferedInput.read(receivedData);
            if (bytesRead != SHPPacket.headerLength()) {
                throw new RuntimeException("Failed to read SHP packet 4 header");
            }

            packetType = SHPPacket.extractMessageType(receivedData);
            if (packetType != MessageType.FOUR) {
                throw new RuntimeException("Expected SHP packet type 4, but received: " + packetType);
            }

            // handle packet 4
            // read encrypted data
            byte[] lengthBytes = new byte[4];
            bytesRead = bufferedInput.read(lengthBytes);
            int encryptedDataLength = ByteBuffer.wrap(lengthBytes).getInt();
            byte[] encryptedData = new byte[encryptedDataLength];
            bytesRead = bufferedInput.read(encryptedData);
            if (bytesRead != encryptedDataLength) {
                throw new RuntimeException("Failed to read encrypted data in packet 4. Expected: " + encryptedDataLength + "Bytes. Actual: " + bytesRead + "Bytes");
            }
            // read signature
            bufferedInput.read(lengthBytes);
            int signatureLength = ByteBuffer.wrap(lengthBytes).getInt();
            byte[] signature = new byte[signatureLength];
            bytesRead = bufferedInput.read(signature);
            if (bytesRead != signatureLength) {
                throw new RuntimeException("Failed to read signature in packet 4. Expected: " + signatureLength + "Bytes. Actual: " + bytesRead + "Bytes");
            }
            // read mac
            bufferedInput.read(lengthBytes);
            int macLength = ByteBuffer.wrap(lengthBytes).getInt();
            byte[] mac = new byte[macLength];
            bytesRead = bufferedInput.read(mac);
            if (bytesRead != macLength) {
                throw new RuntimeException("Failed to read mac in packet 4. Expected: " + macLength + "Bytes. Actual: " + bytesRead + "Bytes");
            }

            // verify mac
            if (!verifyMac(encryptedData, mac, pbeKey.getEncoded())) {
                throw new SecurityException("Integrity verification of packet 4 failed");
            }

            // verify signature
            if (!verifyECDSASignature(encryptedData, signature, ServerECCPubKey.getInstance().getPublic())) {
                throw new SecurityException("Signature verification of packet 4 failed");
            }

            // decrypt data
            byte[] decryptedData = PBEDecrypt(encryptedData, ClientECCKeyPair.getInstance().getPrivate());
            ByteBuffer dataBuffer = ByteBuffer.wrap(decryptedData);

            // extract data
            int requestConfirmationLength = dataBuffer.getInt();
            byte[] requestConfirmationBytes = new byte[requestConfirmationLength];
            dataBuffer.get(requestConfirmationBytes);
            String requestConfirmation = new String(requestConfirmationBytes);
            if (!requestConfirmation.equals(request)) {
                throw new SecurityException("Request confirmation does not match request: request was '" +
                        request + "' but confirmation was '" + requestConfirmation + "'");
            }
            byte[] nonce4Plus1 = new byte[16];
            dataBuffer.get(nonce4Plus1);
            // TODO: verify nonce4Plus1
            byte[] nonce5 = new byte[16];
            dataBuffer.get(nonce5);
            byte[] cryptoConfigBytes = new byte[dataBuffer.remaining()];
            dataBuffer.get(cryptoConfigBytes);
            String cryptoConfigString = new String(cryptoConfigBytes);
            DSTPConfig cryptoConfig = new DSTPConfig(new StringReader(cryptoConfigString));
            CryptoProvider cryptoProvider = CryptoProviderFactory.createBouncyCastleProvider(cryptoConfig);

            // send packet 5
            SHPPacket msgFive = SHPPacketFactory.createTypeFivePacket(nonce5, cryptoProvider,
                    hexToBytes(cryptoConfig.getSymmetric_key()), hexToBytes(cryptoConfig.getMackey()));
            bufferedOutput.write(msgFive.serialize());

            return new SHPResult(cryptoConfig, host, udpPort, request, username);
        } catch (IOException e) {
            throw new RuntimeException("socket IO error");
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("crypto error");
        }
    }
}
