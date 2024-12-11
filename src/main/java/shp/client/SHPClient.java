package shp.client;

import crypto.CryptoProvider;
import crypto.CryptoProviderFactory;
import dstp.config.DSTPConfig;
import shp.MessageType;
import shp.SHPPacket;
import shp.SHPPacketFactory;
import shp.SHPResult;

import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;

import static dstp.config.DSTPConfig.Integrity.MAC;
import static shp.server.UserDB.SALT;
import static util.ByteUtils.*;
import static util.CryptoUtils.*;

public class SHPClient {

    private final List<Integer> nonces;
    private final List<String> macs;
    private final String host;
    private final int tcpPort;
    private final String username;
    private final String password;
    private final String request;
    private final int udpPort;
    private final int phase = 2;

    public SHPClient(String host, int tcpPort, String username, String password, String request, int udpPort) {
        this.nonces = new ArrayList<>();
        this.macs = new ArrayList<>();
        this.host = host;
        this.tcpPort = tcpPort;
        this.username = username;
        this.password = password;
        this.request = request;
        this.udpPort = udpPort;
    }

    public SHPClient(String host, int tcpPort, String username, String password, String request, int udpPort, String clientKeypairPath, String serverPubkeyPath) {
        this.nonces = new ArrayList<>();
        this.macs = new ArrayList<>();
        this.host = host;
        this.tcpPort = tcpPort;
        this.username = username;
        this.password = password;
        this.request = request;
        this.udpPort = udpPort;
        ClientECCKeyPair.setKeyFilePath(clientKeypairPath);
        ServerECCPubKey.setKeyFilePath(serverPubkeyPath);
    }

    public SHPResult executeHandshake() {
        if (phase == 1) {
            return phase1();
        } else {
            return phase2();
        }
    }

    private void checkAndAddMac(byte[] mac) {
        String macString = bytesToHex(mac);
        if (macs.contains(macString)) {
            throw new RuntimeException("Mac already used: " + macString);
        }
        macs.add(macString);
    }

    private SHPResult phase1() {
        try (Socket socket = new Socket(host, tcpPort)) {
            // initialize tcp connection
            socket.setSoTimeout(5000);
            System.out.println("[SHPClient] Initializing TCP connection");
            System.out.println("[SHPClient] Connecting to " + host + " on port " + tcpPort);
            InputStream input = socket.getInputStream();
            OutputStream output = socket.getOutputStream();
            BufferedInputStream bufferedInput = new BufferedInputStream(input);
            BufferedOutputStream bufferedOutput = new BufferedOutputStream(output);

            // send packet 1
            System.out.println("[SHPClient] Sending packet 1");
            SHPPacket msgOne = SHPPacketFactory.createTypeOnePacket(username);
            bufferedOutput.write(msgOne.serialize());
            bufferedOutput.flush();
            System.out.println("[SHPClient] Sent packet 1");

            // receive packet 2
            System.out.println("[SHPClient] Waiting for packet 2");
            while (bufferedInput.available() == 0) {
                Thread.sleep(100);
            }
            System.out.println("[SHPClient] Receiving packet 2");
            byte[] receivedData = new byte[SHPPacket.headerLength()];
            int bytesRead = bufferedInput.read(receivedData);
            if (bytesRead != SHPPacket.headerLength()) {
                throw new RuntimeException("Failed to read SHP packet 2 header");
            }
            System.out.println("[SHPClient] Received packet 1");


            MessageType packetType = SHPPacket.extractMessageType(receivedData);
            if (packetType != MessageType.TWO) {
                throw new RuntimeException("Expected SHP packet type 2, but received: " + packetType);
            }

            // handle packet 2
            System.out.println("[SHPClient] Processing packet 2");
            byte[] nonceData = new byte[48];
            bytesRead = bufferedInput.read(nonceData);
            if (bytesRead != 48) {
                throw new RuntimeException("Failed to read nonce data");
            }
            ByteBuffer nonceBuffer = ByteBuffer.wrap(nonceData);
            byte[] nonce1 = new byte[16];
            nonceBuffer.get(nonce1);
            checkAndAddNonce(nonce1);
            byte[] nonce2 = new byte[16];
            nonceBuffer.get(nonce2);
            checkAndAddNonce(nonce2);
            byte[] nonce3 = new byte[16];
            nonceBuffer.get(nonce3);
            checkAndAddNonce(nonce3);

            // create PBE key
            byte[] passwordHash = generatePasswordHash(password, SALT);
            Key pbeKey = generatePBEKey(bytesToHex(passwordHash).toCharArray());
            byte[] nonce4 = generateNonce(16);
            checkAndAddNonce(nonce4);
            System.out.println("[SHPClient] Processed packet 2");


            // send packet 3
            System.out.println("[SHPClient] Sending packet 3");
            SHPPacket msgThree = SHPPacketFactory.createTypeThreePacket(request, username, nonce3, nonce4, udpPort, pbeKey);
            bufferedOutput.write(msgThree.serialize());
            bufferedOutput.flush();
            System.out.println("[SHPClient] Sent packet 3");

            // receive packet 4
            System.out.println("[SHPClient] Waiting for packet 4");
            while (bufferedInput.available() == 0) {
                Thread.sleep(100);
            }
            System.out.println("[SHPClient] Receiving packet 4");
            receivedData = new byte[SHPPacket.headerLength()];
            bytesRead = bufferedInput.read(receivedData);
            if (bytesRead != SHPPacket.headerLength()) {
                throw new RuntimeException("Failed to read SHP packet 4 header");
            }
            System.out.println("[SHPClient] Received packet 4");

            packetType = SHPPacket.extractMessageType(receivedData);
            if (packetType != MessageType.FOUR) {
                throw new RuntimeException("Expected SHP packet type 4, but received: " + packetType);
            }

            // handle packet 4
            System.out.println("[SHPClient] Processing packet 4");
            // read encrypted data
            byte[] lengthBytes = new byte[4];
            bufferedInput.read(lengthBytes);
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
            checkAndAddMac(mac);

            // verify mac
            if (!verifyMac(encryptedData, mac, pbeKey.getEncoded())) {
                throw new SecurityException("Integrity verification of packet 4 failed");
            }

            // verify signature
            if (!verifyECDSASignature(encryptedData, signature, ServerECCPubKey.getInstance().getPublic())) {
                throw new SecurityException("Signature verification of packet 4 failed");
            }

            // decrypt data
            byte[] decryptedData = ECIESDecrypt(encryptedData, ClientECCKeyPair.getInstance().getPrivate());
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
            verifyNonceChallenge(nonce4, nonce4Plus1);
            byte[] nonce5 = new byte[16];
            dataBuffer.get(nonce5);
            checkAndAddNonce(nonce5);
            byte[] cryptoConfigBytes = new byte[dataBuffer.remaining()];
            dataBuffer.get(cryptoConfigBytes);
            String cryptoConfigString = new String(cryptoConfigBytes);
            DSTPConfig cryptoConfig = new DSTPConfig(new StringReader(cryptoConfigString));
            CryptoProvider cryptoProvider = CryptoProviderFactory.createBouncyCastleProvider(cryptoConfig);
            System.out.println("[SHPClient] Processed packet 4");

            // send packet 5
            System.out.println("[SHPClient] Sending packet 5");
            SHPPacket msgFive = SHPPacketFactory.createTypeFivePacket(nonce5, cryptoProvider,
                    hexToBytes(cryptoConfig.getSymmetric_key()), hexToBytes(cryptoConfig.getMackey()));
            bufferedOutput.write(msgFive.serialize());
            bufferedOutput.flush();
            System.out.println("[SHPClient] Sent packet 5");

            System.out.println("[SHPClient] Handshake successful");
            return new SHPResult(cryptoConfig, host, udpPort, request, username);
        } catch (IOException e) {
            throw new RuntimeException("socket IO error");
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("crypto error");
        } catch (InterruptedException e) {
            throw new RuntimeException("thread interrupted while sleeping");
        }
    }

    private SHPResult phase2() {
        try (Socket socket = new Socket(host, tcpPort)) {
            // initialize tcp connection
            socket.setSoTimeout(5000);
            System.out.println("[SHPClient] Initializing TCP connection");
            System.out.println("[SHPClient] Connecting to " + host + " on port " + tcpPort);
            InputStream input = socket.getInputStream();
            OutputStream output = socket.getOutputStream();
            BufferedInputStream bufferedInput = new BufferedInputStream(input);
            BufferedOutputStream bufferedOutput = new BufferedOutputStream(output);

            // send packet 1
            System.out.println("[SHPClient] Sending packet 1");
            SHPPacket msgOne = SHPPacketFactory.createTypeOnePacket(username);
            bufferedOutput.write(msgOne.serialize());
            bufferedOutput.flush();
            System.out.println("[SHPClient] Sent packet 1");

            // receive packet 2
            System.out.println("[SHPClient] Waiting for packet 2");
            while (bufferedInput.available() == 0) {
                Thread.sleep(100);
            }
            System.out.println("[SHPClient] Receiving packet 2");
            byte[] receivedData = new byte[SHPPacket.headerLength()];
            int bytesRead = bufferedInput.read(receivedData);
            if (bytesRead != SHPPacket.headerLength()) {
                throw new RuntimeException("Failed to read SHP packet 2 header");
            }
            System.out.println("[SHPClient] Received packet 1");


            MessageType packetType = SHPPacket.extractMessageType(receivedData);
            if (packetType != MessageType.TWO) {
                throw new RuntimeException("Expected SHP packet type 2, but received: " + packetType);
            }

            // handle packet 2
            System.out.println("[SHPClient] Processing packet 2");
            byte[] nonceData = new byte[48];
            bytesRead = bufferedInput.read(nonceData);
            if (bytesRead != 48) {
                throw new RuntimeException("Failed to read nonce data");
            }
            ByteBuffer nonceBuffer = ByteBuffer.wrap(nonceData);
            byte[] nonce1 = new byte[16];
            nonceBuffer.get(nonce1);
            checkAndAddNonce(nonce1);
            byte[] nonce2 = new byte[16];
            nonceBuffer.get(nonce2);
            checkAndAddNonce(nonce2);
            byte[] nonce3 = new byte[16];
            nonceBuffer.get(nonce3);
            checkAndAddNonce(nonce3);
            System.out.println("[SHPClient] Processed packet 2");

            // create PBE key and nonce4 and DH Keypair
            byte[] passwordHash = generatePasswordHash(password, SALT);
            Key pbeKey = generatePBEKey(bytesToHex(passwordHash).toCharArray());
            byte[] nonce4 = generateNonce(16);
            checkAndAddNonce(nonce4);
            KeyPair DHKeypair = generateDHKeyPair();

            // send packet 32
            System.out.println("[SHPClient] Sending packet 3");
            SHPPacket msgThree = SHPPacketFactory.createTypeThreePacket2(request, username, nonce3, nonce4, udpPort, pbeKey, DHKeypair.getPublic().getEncoded());
            bufferedOutput.write(msgThree.serialize());
            bufferedOutput.flush();
            System.out.println("[SHPClient] Sent packet 3");

            // receive packet 42
            System.out.println("[SHPClient] Waiting for packet 4");
            while (bufferedInput.available() == 0) {
                Thread.sleep(100);
            }
            System.out.println("[SHPClient] Receiving packet 4");
            receivedData = new byte[SHPPacket.headerLength()];
            bytesRead = bufferedInput.read(receivedData);
            if (bytesRead != SHPPacket.headerLength()) {
                throw new RuntimeException("Failed to read SHP packet 4 header");
            }
            System.out.println("[SHPClient] Received packet 4");

            packetType = SHPPacket.extractMessageType(receivedData);
            if (packetType != MessageType.FOUR2) {
                throw new RuntimeException("Expected SHP packet type 4, but received: " + packetType);
            }

            // handle packet 42
            System.out.println("[SHPClient] Processing packet 4");
            // read encrypted data
            byte[] lengthBytes = new byte[4];
            bufferedInput.read(lengthBytes);
            int encryptedDataLength = ByteBuffer.wrap(lengthBytes).getInt();
            byte[] encryptedData = new byte[encryptedDataLength];
            bytesRead = bufferedInput.read(encryptedData);
            if (bytesRead != encryptedDataLength) {
                throw new RuntimeException("Failed to read encrypted data in packet 4. Expected: " + encryptedDataLength + "Bytes. Actual: " + bytesRead + "Bytes");
            }
            // ydh-server
            byte[] ydhSLengthBytes = new byte[4];
            bufferedInput.read(ydhSLengthBytes);
            int ydhSLength = ByteBuffer.wrap(ydhSLengthBytes).getInt();
            byte[] ydhS = new byte[ydhSLength];
            bytesRead = bufferedInput.read(ydhS);
            if (bytesRead != ydhSLength) {
                throw new RuntimeException("Failed to read ydh-server in packet 4. Expected: " + ydhSLength + "Bytes. Actual: " + bytesRead + "Bytes");
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
            checkAndAddMac(mac);

            // verify mac
            ByteBuffer toMac = ByteBuffer.allocate(encryptedData.length + ydhS.length + signatureLength);
            toMac.put(encryptedData);
            toMac.put(ydhS);
            toMac.put(signature);
            if (!verifyMac(toMac.array(), mac, pbeKey.getEncoded())) {
                throw new SecurityException("Integrity verification of packet 4 failed");
            }

            // verify signature
            ByteBuffer toSign = ByteBuffer.allocate(encryptedData.length + ydhS.length);
            toSign.put(encryptedData);
            toSign.put(ydhS);
            if (!verifyECDSASignature(toSign.array(), signature, ServerECCPubKey.getInstance().getPublic())) {
                throw new SecurityException("Signature verification of packet 4 failed");
            }

            // generate DH Sessionkey
            byte[] DHSessionKey = doDHKeyAgreement(DHKeypair, reconstructDHPublicKeyFromBytes(ydhS));

            // decrypt data
            byte[] decryptedData = ECIESDecrypt(encryptedData, ClientECCKeyPair.getInstance().getPrivate());
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
            verifyNonceChallenge(nonce4, nonce4Plus1);
            byte[] nonce5 = new byte[16];
            dataBuffer.get(nonce5);
            checkAndAddNonce(nonce5);
            byte[] cryptoConfigBytes = new byte[dataBuffer.remaining()];
            dataBuffer.get(cryptoConfigBytes);
            String cryptoConfigString = new String(cryptoConfigBytes);
            DSTPConfig cryptoConfig = new DSTPConfig(new StringReader(cryptoConfigString));

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
            CryptoProvider cryptoProvider = CryptoProviderFactory.createBouncyCastleProvider(cryptoConfig);
            System.out.println("[SHPClient] Processed packet 4");

            // send packet 5
            System.out.println("[SHPClient] Sending packet 5");
            SHPPacket msgFive = SHPPacketFactory.createTypeFivePacket(nonce5, cryptoProvider,
                    hexToBytes(cryptoConfig.getSymmetric_key()), hexToBytes(cryptoConfig.getMackey()));
            bufferedOutput.write(msgFive.serialize());
            bufferedOutput.flush();
            System.out.println("[SHPClient] Sent packet 5");

            System.out.println("[SHPClient] Handshake successful");
            return new SHPResult(cryptoConfig, host, udpPort, request, username);
        } catch (IOException e) {
            throw new RuntimeException("socket IO error");
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("crypto error");
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

    private void verifyNonceChallenge(byte[] challenge, byte[] challengeResponse) {
        if (!isExactlyOnelarger(challenge, challengeResponse)) {
            throw new RuntimeException("Nonce challenge failed");
        }
    }
}
