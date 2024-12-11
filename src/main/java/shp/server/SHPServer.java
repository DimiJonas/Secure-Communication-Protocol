package shp.server;

import crypto.CryptoProvider;
import crypto.CryptoProviderFactory;
import dstp.config.DSTPConfig;
import org.bouncycastle.crypto.InvalidCipherTextException;
import shp.MessageType;
import shp.SHPPacket;
import shp.SHPPacketFactory;
import shp.SHPResult;
import util.ByteUtils;

import javax.crypto.SecretKey;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

import static dstp.config.DSTPConfig.Integrity.MAC;
import static java.lang.String.format;
import static util.ByteUtils.*;
import static util.CryptoUtils.*;

public class SHPServer {
    private static final String DEFAULT_CRYPTO_CONFIG_PATH = "src/main/resources/pa2/server/ciphersuite.conf";
    private static String configPath;
    private final List<Integer> nonces;
    private final List<String> macs;
    private final int port;
    private final int phase = 2;

    public SHPServer(int port) {
        this.nonces = new ArrayList<>();
        this.macs = new ArrayList<>();
        this.port = port;
    }

    public SHPServer(int port, String configPath, String userDBPath, String serverKeypairPath) {
        this.nonces = new ArrayList<>();
        this.macs = new ArrayList<>();
        this.port = port;
        setConfigPath(configPath);
        UserDB.setDbPath(userDBPath);
        ServerECCKeyPair.setKeyFilePath(serverKeypairPath);
    }

    public static String getConfigPath() {
        return configPath != null ? configPath : DEFAULT_CRYPTO_CONFIG_PATH;
    }

    public static void setConfigPath(String path) {
        configPath = path;
    }

    public SHPResult executeHandshake() {
        if (phase == 1) {
            return phase1();
        } else {
            return phase2();
        }
    }

    private SHPResult phase1() {
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            // initialize tcp connection
            serverSocket.setSoTimeout(5000);
            System.out.println("[SHPServer] Initializing TCP connection");
            System.out.println("[SHPServer] Listening on port " + port);
            Socket clientSocket = serverSocket.accept();
            String host = clientSocket.getInetAddress().getHostAddress();
            System.out.println("[SHPServer] Accepted connection from " + clientSocket.getInetAddress());

            InputStream input = clientSocket.getInputStream();
            OutputStream output = clientSocket.getOutputStream();
            BufferedInputStream bufferedInput = new BufferedInputStream(input);
            BufferedOutputStream bufferedOutput = new BufferedOutputStream(output);

            // receive packet 1
            System.out.println("[SHPServer] Waiting for packet 1");
            while (bufferedInput.available() == 0) {
                Thread.sleep(100);
            }
            System.out.println("[SHPServer] Receiving packet 1");
            byte[] headerData = new byte[SHPPacket.headerLength()];
            int bytesRead = bufferedInput.read(headerData);
            if (bytesRead != SHPPacket.headerLength()) {
                throw new RuntimeException("Failed to read SHP packet 1 header");
            }
            System.out.println("[SHPServer] Received packet 1");

            MessageType packetType = SHPPacket.extractMessageType(headerData);
            if (packetType != MessageType.ONE) {
                throw new RuntimeException("Expected SHP packet type 1, but received: " + packetType);
            }

            // handle packet 1
            System.out.println("[SHPServer] Processing packet 1");
            byte[] userID = new byte[320];
            bytesRead = bufferedInput.read(userID);
            ByteBuffer idBuffer = ByteBuffer.wrap(userID, 0, bytesRead);
            String username = new String(idBuffer.array()).trim();
            AuthRecord userRecord = UserDB.getInstance().getRecord(username);
            if (userRecord == null) {
                throw new RuntimeException(format("Username '%s' from packet 1 not found in user database", username));
            }

            byte[] nonce1 = generateNonce(16);
            checkAndAddNonce(nonce1);
            byte[] nonce2 = generateNonce(16);
            checkAndAddNonce(nonce2);
            byte[] nonce3 = generateNonce(16);
            checkAndAddNonce(nonce3);
            System.out.println("[SHPServer] Processed packet 1");

            // send packet 2
            System.out.println("[SHPServer] Sending packet 2");
            SHPPacket msgTwo = SHPPacketFactory.createTypeTwoPacket(nonce1, nonce2, nonce3);
            bufferedOutput.write(msgTwo.serialize());
            bufferedOutput.flush();
            System.out.println("[SHPServer] Sent packet 2");

            // receive packet 3
            System.out.println("[SHPServer] Waiting for packet 3");
            while (bufferedInput.available() == 0) {
                Thread.sleep(100);
            }
            System.out.println("[SHPServer] Receiving packet 3");
            bytesRead = bufferedInput.read(headerData);
            if (bytesRead != SHPPacket.headerLength()) {
                throw new RuntimeException("Failed to read SHP packet 3 header");
            }
            System.out.println("[SHPServer] Received packet 3");

            packetType = SHPPacket.extractMessageType(headerData);
            if (packetType != MessageType.THREE) {
                throw new RuntimeException("Expected SHP packet type 3, but received: " + packetType);
            }

            // handle packet 3
            System.out.println("[SHPServer] Processing packet 3");
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
            checkAndAddMac(mac);

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
            verifyNonceChallenge(nonce3, nonce3Plus1);
            byte[] nonce4 = new byte[16];
            dataBuffer.get(nonce4);
            checkAndAddNonce(nonce4);
            int udpPort = dataBuffer.getInt();
            System.out.println("[SHPServer] Processed packet 3");

            byte[] nonce5 = generateNonce(16);

            // send packet 4
            System.out.println("[SHPServer] Sending packet 4");
            DSTPConfig cryptoConfig = new DSTPConfig(getConfigPath());
            byte[] cryptoConfigBytes = cryptoConfig.serialize().getBytes();
            SHPPacket msgFour = SHPPacketFactory.createTypeFourPacket(request, nonce4, nonce5, clientPubkey, pbeKey, cryptoConfigBytes);
            bufferedOutput.write(msgFour.serialize());
            bufferedOutput.flush();
            System.out.println("[SHPServer] Sent packet 4");

            // receive packet 5
            System.out.println("[SHPServer] Waiting for packet 5");
            while (bufferedInput.available() == 0) {
                Thread.sleep(100);
            }
            System.out.println("[SHPServer] Receiving packet 5");
            bytesRead = bufferedInput.read(headerData);
            if (bytesRead != SHPPacket.headerLength()) {
                throw new RuntimeException("Failed to read SHP packet 5 header");
            }
            System.out.println("[SHPServer] Received packet 5");

            packetType = SHPPacket.extractMessageType(headerData);
            if (packetType != MessageType.FIVE) {
                throw new RuntimeException("Expected SHP packet type 5, but received: " + packetType);
            }

            // handle packet 5
            System.out.println("[SHPServer] Processing packet 5");
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
            if (bytesRead != macLength) {
                throw new RuntimeException("Failed to read mac in packet 5. Expected: " + macLength + "Bytes. Actual: " + bytesRead + "Bytes");
            }
            checkAndAddMac(mac);

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
            verifyNonceChallenge(nonce5, nonce5Plus1);
            System.out.println("[SHPServer] Processed packet 5");

            System.out.println("[SHPServer] Handshake successful");
            return new SHPResult(cryptoConfig, host, udpPort, request, username);
        } catch (IOException e) {
            throw new RuntimeException("socket IO error");
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("crypto error");
        } catch (InvalidCipherTextException e) {
            throw new RuntimeException("invalid crypto config for decryption");
        } catch (InterruptedException e) {
            throw new RuntimeException("thread interrupted while sleeping");
        }
    }

    private SHPResult phase2() {
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            // initialize tcp connection
            serverSocket.setSoTimeout(5000);
            System.out.println("[SHPServer] Initializing TCP connection");
            System.out.println("[SHPServer] Listening on port " + port);
            Socket clientSocket = serverSocket.accept();
            String host = clientSocket.getInetAddress().getHostAddress();
            System.out.println("[SHPServer] Accepted connection from " + clientSocket.getInetAddress());

            InputStream input = clientSocket.getInputStream();
            OutputStream output = clientSocket.getOutputStream();
            BufferedInputStream bufferedInput = new BufferedInputStream(input);
            BufferedOutputStream bufferedOutput = new BufferedOutputStream(output);

            // receive packet 1
            System.out.println("[SHPServer] Waiting for packet 1");
            while (bufferedInput.available() == 0) {
                Thread.sleep(100);
            }
            System.out.println("[SHPServer] Receiving packet 1");
            byte[] headerData = new byte[SHPPacket.headerLength()];
            int bytesRead = bufferedInput.read(headerData);
            if (bytesRead != SHPPacket.headerLength()) {
                throw new RuntimeException("Failed to read SHP packet 1 header");
            }
            System.out.println("[SHPServer] Received packet 1");

            MessageType packetType = SHPPacket.extractMessageType(headerData);
            if (packetType != MessageType.ONE) {
                throw new RuntimeException("Expected SHP packet type 1, but received: " + packetType);
            }

            // handle packet 1
            System.out.println("[SHPServer] Processing packet 1");
            byte[] userID = new byte[320];
            bytesRead = bufferedInput.read(userID);
            ByteBuffer idBuffer = ByteBuffer.wrap(userID, 0, bytesRead);
            String username = new String(idBuffer.array()).trim();
            AuthRecord userRecord = UserDB.getInstance().getRecord(username);
            if (userRecord == null) {
                throw new RuntimeException(format("Username '%s' from packet 1 not found in user database", username));
            }

            byte[] nonce1 = generateNonce(16);
            checkAndAddNonce(nonce1);
            byte[] nonce2 = generateNonce(16);
            checkAndAddNonce(nonce2);
            byte[] nonce3 = generateNonce(16);
            checkAndAddNonce(nonce3);
            System.out.println("[SHPServer] Processed packet 1");

            // send packet 2
            System.out.println("[SHPServer] Sending packet 2");
            SHPPacket msgTwo = SHPPacketFactory.createTypeTwoPacket(nonce1, nonce2, nonce3);
            bufferedOutput.write(msgTwo.serialize());
            bufferedOutput.flush();
            System.out.println("[SHPServer] Sent packet 2");

            // receive packet 32
            System.out.println("[SHPServer] Waiting for packet 3");
            while (bufferedInput.available() == 0) {
                Thread.sleep(100);
            }
            System.out.println("[SHPServer] Receiving packet 3");
            bytesRead = bufferedInput.read(headerData);
            if (bytesRead != SHPPacket.headerLength()) {
                throw new RuntimeException("Failed to read SHP packet 3 header");
            }
            System.out.println("[SHPServer] Received packet 3");

            packetType = SHPPacket.extractMessageType(headerData);
            if (packetType != MessageType.THREE2) {
                throw new RuntimeException("Expected SHP packet type 3, but received: " + packetType);
            }

            // handle packet 32
            System.out.println("[SHPServer] Processing packet 3");
            // read encrypted data
            byte[] lengthBytes = new byte[4];
            bufferedInput.read(lengthBytes);
            int encryptedDataLength = ByteBuffer.wrap(lengthBytes).getInt();
            byte[] encryptedData = new byte[encryptedDataLength];
            bytesRead = bufferedInput.read(encryptedData);
            if (bytesRead != encryptedDataLength) {
                throw new RuntimeException("Failed to read encrypted data in packet 3. Expected: " + encryptedDataLength + "Bytes. Actual: " + bytesRead + "Bytes");
            }
            // ydh-client
            byte[] ydhCLengthBytes = new byte[4];
            bufferedInput.read(ydhCLengthBytes);
            int ydhCLength = ByteBuffer.wrap(ydhCLengthBytes).getInt();
            byte[] ydhC = new byte[ydhCLength];
            bytesRead = bufferedInput.read(ydhC);
            if (bytesRead != ydhCLength) {
                throw new RuntimeException("Failed to read ydh-server in packet 4. Expected: " + ydhCLength + "Bytes. Actual: " + bytesRead + "Bytes");
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
            checkAndAddMac(mac);

            // verify mac
            ByteBuffer toMac = ByteBuffer.allocate(encryptedData.length + ydhC.length + signature.length);
            toMac.put(encryptedData);
            toMac.put(ydhC);
            toMac.put(signature);
            Key pbeKey = generatePBEKey(userRecord.passwordhash().toCharArray());
            if (!verifyMac(toMac.array(), mac, pbeKey.getEncoded())) {
                throw new SecurityException("Integrity verification of packet 3 failed");
            }

            // verify signature
            ByteBuffer toSign = ByteBuffer.allocate(encryptedData.length + ydhC.length);
            toSign.put(encryptedData);
            toSign.put(ydhC);
            PublicKey clientPubkey = reconstructECCPublicKeyFromBytes(hexToBytes(userRecord.pubkey()));
            if (!verifyECDSASignature(toSign.array(), signature, clientPubkey)) {
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
            verifyNonceChallenge(nonce3, nonce3Plus1);
            byte[] nonce4 = new byte[16];
            dataBuffer.get(nonce4);
            checkAndAddNonce(nonce4);
            int udpPort = dataBuffer.getInt();
            System.out.println("[SHPServer] Processed packet 3");

            // create cryptoConfig, nonce5 and DH keypair
            DSTPConfig cryptoConfig = new DSTPConfig(getConfigPath());
            byte[] cryptoConfigBytes = cryptoConfig.serialize().getBytes();
            byte[] nonce5 = generateNonce(16);
            KeyPair DHKeypair = generateDHKeyPair();
            // generate DH Sessionkey
            byte[] DHSessionKey = doDHKeyAgreement(DHKeypair, reconstructDHPublicKeyFromBytes(ydhC));
            // generate and set DH derived keys and set them in the config
            SecretKey symmetricKey = deriveKeyPBKDF2(bytesToHex(DHSessionKey), getBaseAlgorithm(cryptoConfig.getConfidentiality()));
            cryptoConfig.setSymmetric_key(bytesToHex(symmetricKey.getEncoded()));
            cryptoConfig.setSymmetric_key_size(String.valueOf(symmetricKey.getEncoded().length * 8));
            SecretKey macKey = null;
            if (cryptoConfig.getIntegrity().equals(MAC)) {
                macKey = deriveKeyPBKDF2(bytesToHex(DHSessionKey), getBaseAlgorithm(cryptoConfig.getMac()));
            }
            if (macKey != null) {
                cryptoConfig.setMackey(bytesToHex(macKey.getEncoded()));
                cryptoConfig.setMackey_size(String.valueOf(macKey.getEncoded().length * 8));
            }
            // send packet 42
            System.out.println("[SHPServer] Sending packet 4");
            SHPPacket msgFour = SHPPacketFactory.createTypeFourPacket2(request, nonce4, nonce5, clientPubkey, pbeKey, cryptoConfigBytes, DHKeypair.getPublic().getEncoded());
            bufferedOutput.write(msgFour.serialize());
            bufferedOutput.flush();
            System.out.println("[SHPServer] Sent packet 4");

            // receive packet 5
            System.out.println("[SHPServer] Waiting for packet 5");
            while (bufferedInput.available() == 0) {
                Thread.sleep(100);
            }
            System.out.println("[SHPServer] Receiving packet 5");
            bytesRead = bufferedInput.read(headerData);
            if (bytesRead != SHPPacket.headerLength()) {
                throw new RuntimeException("Failed to read SHP packet 5 header");
            }
            System.out.println("[SHPServer] Received packet 5");

            packetType = SHPPacket.extractMessageType(headerData);
            if (packetType != MessageType.FIVE) {
                throw new RuntimeException("Expected SHP packet type 5, but received: " + packetType);
            }

            // handle packet 5
            System.out.println("[SHPServer] Processing packet 5");
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
            if (bytesRead != macLength) {
                throw new RuntimeException("Failed to read mac in packet 5. Expected: " + macLength + "Bytes. Actual: " + bytesRead + "Bytes");
            }
            checkAndAddMac(mac);

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
            verifyNonceChallenge(nonce5, nonce5Plus1);
            System.out.println("[SHPServer] Processed packet 5");

            System.out.println("[SHPServer] Handshake successful");
            return new SHPResult(cryptoConfig, host, udpPort, request, username);
        } catch (IOException e) {
            throw new RuntimeException("socket IO error");
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("crypto error");
        } catch (InvalidCipherTextException e) {
            throw new RuntimeException("invalid crypto config for decryption");
        } catch (InterruptedException e) {
            throw new RuntimeException("thread interrupted while sleeping");
        }
    }

    private void checkAndAddNonce(byte[] nonce) {
        int nonceInt = ByteBuffer.wrap(nonce).getInt();
        if (nonces.contains(nonceInt)) {
            throw new RuntimeException("Nonce already used: " + nonceInt);
        }
        nonces.add(nonceInt);
    }

    private void checkAndAddMac(byte[] mac) {
        String macString = bytesToHex(mac);
        if (macs.contains(macString)) {
            throw new RuntimeException("Mac already used: " + macString);
        }
        macs.add(macString);
    }

    private void verifyNonceChallenge(byte[] challenge, byte[] challengeResponse) {
        if (!ByteUtils.isExactlyOnelarger(challenge, challengeResponse)) {
            throw new RuntimeException("Nonce challenge failed");
        }
    }
}
