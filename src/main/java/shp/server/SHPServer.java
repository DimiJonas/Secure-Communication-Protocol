package shp.server;

import crypto.CryptoProvider;
import crypto.CryptoProviderFactory;
import dstp.config.DSTPConfig;
import org.bouncycastle.crypto.InvalidCipherTextException;
import shp.MessageType;
import shp.SHPPacket;
import shp.SHPPacketFactory;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PublicKey;

import static util.ByteUtils.hexToBytes;
import static util.CryptoUtils.*;

public class SHPServer {
    private static final String CRYPTO_CONFIG_PATH = "src/main/resources/pa2/server/ciphersuite.conf";

    private final int port;

    public SHPServer(int port) {
        this.port = port;
    }

    public void executeHandshake() {
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            // initialize tcp connection
            Socket clientSocket = serverSocket.accept();

            InputStream input = clientSocket.getInputStream();
            OutputStream output = clientSocket.getOutputStream();
            BufferedInputStream bufferedInput = new BufferedInputStream(input);
            BufferedOutputStream bufferedOutput = new BufferedOutputStream(output);

            // receive packet 1
            byte[] headerData = new byte[SHPPacket.headerLength()];
            int bytesRead = bufferedInput.read(headerData);
            if (bytesRead != SHPPacket.headerLength()) {
                throw new RuntimeException("Failed to read SHP packet 1 header");
            }

            MessageType packetType = SHPPacket.extractMessageType(headerData);
            if (packetType != MessageType.ONE) {
                throw new RuntimeException("Expected SHP packet type 1, but received: " + packetType);
            }

            // handle packet 1
            byte[] userID = new byte[320];
            bytesRead = bufferedInput.read(userID);
            ByteBuffer idBuffer = ByteBuffer.wrap(userID, 0, bytesRead);
            String username = new String(idBuffer.array());
            AuthRecord userRecord = UserDB.getInstance().getRecord(username);
            if (userRecord == null) {
                throw new RuntimeException("Username from packet 1 not found in user database");
            }

            // send packet 2
            SHPPacket msgTwo = SHPPacketFactory.createTypeTwoPacket();
            bufferedOutput.write(msgTwo.serialize());

            // receive packet 3
            // TODO: check if it works reusing this headerData buffer - otherwise create new buffer
            bytesRead = bufferedInput.read(headerData);
            if (bytesRead != SHPPacket.headerLength()) {
                throw new RuntimeException("Failed to read SHP packet 3 header");
            }

            packetType = SHPPacket.extractMessageType(headerData);
            if (packetType != MessageType.THREE) {
                throw new RuntimeException("Expected SHP packet type 3, but received: " + packetType);
            }

            // handle packet 3
            // read encrypted data
            byte[] lengthBytes = new byte[4];
            bufferedInput.read(lengthBytes);
            int encryptedDataLength = ByteBuffer.wrap(lengthBytes).getInt();
            byte[] encryptedData = new byte[encryptedDataLength];
            bytesRead = bufferedInput.read(encryptedData);
            if (bytesRead != encryptedDataLength) {
                throw new RuntimeException("Failed to read encrypted data in packet 3. Expected: " + encryptedDataLength + "Bytes. Actual: " + bytesRead + "Bytes");
            }
            // read signature
            bufferedInput.read(lengthBytes);
            int signatureLength = ByteBuffer.wrap(lengthBytes).getInt();
            byte[] signature = new byte[signatureLength];
            bytesRead = bufferedInput.read(signature);
            if (bytesRead != signatureLength) {
                throw new RuntimeException("Failed to read signature in packet 3. Expected: " + signatureLength + "Bytes. Actual: " + bytesRead + "Bytes");
            }
            // read mac
            bufferedInput.read(lengthBytes);
            int macLength = ByteBuffer.wrap(lengthBytes).getInt();
            byte[] mac = new byte[macLength];
            bytesRead = bufferedInput.read(mac);
            if (bytesRead != macLength) {
                throw new RuntimeException("Failed to read mac in packet 3. Expected: " + macLength + "Bytes. Actual: " + bytesRead + "Bytes");
            }

            // verify mac
            Key pbeKey = generatePBEKey(userRecord.passwordhash().toCharArray());
            if (!verifyMac(encryptedData, mac, pbeKey.getEncoded())) {
                throw new SecurityException("Integrity verification of packet 3 failed");
            }

            // verify signature
            PublicKey clientPubkey = reconstructECCPublicKeyFromBytes(hexToBytes(userRecord.pubkey()));
            if (!verifyECDSASignature(encryptedData, signature, clientPubkey)) {
                throw new SecurityException("Signature verification of packet 3 failed");
            }

            // decrypt data
            byte[] decryptedData = PBEDecrypt(encryptedData, pbeKey);
            ByteBuffer dataBuffer = ByteBuffer.wrap(decryptedData);

            // extract data
            int requestLength = decryptedData.length - username.length() - 16 - 16 - 4; // nonce3+1, nonce4, udpPort
            byte[] requestBytes = new byte[requestLength];
            dataBuffer.get(requestBytes);
            String request = new String(requestBytes);
            byte[] userIDBytes = new byte[username.length()];
            dataBuffer.get(userIDBytes);
            String username2 = new String(userIDBytes);
            if (!username.equals(username2)) {
                throw new SecurityException("Username mismatch. Packet 1: " + username + " Packet 3: " + username2);
            }
            byte[] nonce3Plus1 = new byte[16];
            dataBuffer.get(nonce3Plus1);
            // TODO: verify nonce3Plus1
            byte[] nonce4 = new byte[16];
            dataBuffer.get(nonce4);
            int udpPort = dataBuffer.getInt();

            // send packet 4
            DSTPConfig cryptoConfig = new DSTPConfig(CRYPTO_CONFIG_PATH);
            byte[] cryptoConfigBytes = cryptoConfig.serialize().getBytes();
            SHPPacket msgFour = SHPPacketFactory.createTypeFourPacket(request, nonce4, clientPubkey, pbeKey, cryptoConfigBytes);
            bufferedOutput.write(msgFour.serialize());

            // receive packet 5
            bytesRead = bufferedInput.read(headerData);
            if (bytesRead != SHPPacket.headerLength()) {
                throw new RuntimeException("Failed to read SHP packet 5 header");
            }

            packetType = SHPPacket.extractMessageType(headerData);
            if (packetType != MessageType.FIVE) {
                throw new RuntimeException("Expected SHP packet type 5, but received: " + packetType);
            }

            // handle packet 5
            CryptoProvider cryptoProvider = CryptoProviderFactory.createBouncyCastleProvider(cryptoConfig);

            // read encrypted data
            bufferedInput.read(lengthBytes);
            encryptedDataLength = ByteBuffer.wrap(lengthBytes).getInt();
            encryptedData = new byte[encryptedDataLength];
            bytesRead = bufferedInput.read(encryptedData);
            if (bytesRead != encryptedDataLength) {
                throw new RuntimeException("Failed to read encrypted data in packet 5. Expected: " + encryptedDataLength + "Bytes. Actual: " + bytesRead + "Bytes");
            }
            // read mac
            bufferedInput.read(lengthBytes);
            macLength = ByteBuffer.wrap(lengthBytes).getInt();
            mac = new byte[macLength];
            bytesRead = bufferedInput.read(mac);
            if (bytesRead != signatureLength) {
                throw new RuntimeException("Failed to read mac in packet 5. Expected: " + macLength + "Bytes. Actual: " + bytesRead + "Bytes");
            }

            // verify mac
            if (!cryptoProvider.verifyIntegrityCheck(encryptedData, mac, hexToBytes(cryptoConfig.getMackey()))) {
                throw new SecurityException("Integrity verification of packet 5 failed");
            }

            // decrypt data
            decryptedData = cryptoProvider.decrypt(encryptedData, hexToBytes(cryptoConfig.getSymmetric_key()));
            dataBuffer = ByteBuffer.wrap(decryptedData);
            int goStringLength = decryptedData.length - 16; // only nonce5Plus1
            byte[] goStringBytes = new byte[goStringLength];
            dataBuffer.get(goStringBytes);
            String goString = new String(goStringBytes);
            byte[] nonce5Plus1 = new byte[16];
            dataBuffer.get(nonce5Plus1);
            // TODO: verify nonce5Plus1
        } catch (IOException e) {
            throw new RuntimeException("socket IO error");
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("crypto error");
        } catch (InvalidCipherTextException e) {
            throw new RuntimeException("invalid crypto config for decryption");
        }
    }
}
