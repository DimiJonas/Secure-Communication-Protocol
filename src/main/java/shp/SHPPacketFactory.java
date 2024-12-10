package shp;

import crypto.CryptoProvider;
import dstp.config.DSTPConfig;
import org.bouncycastle.crypto.InvalidCipherTextException;
import shp.client.ClientECCKeyPair;
import shp.server.ServerECCKeyPair;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import static shp.MessageType.*;
import static util.ByteUtils.incrementByteNumber;
import static util.CryptoUtils.*;

public class SHPPacketFactory {

    public static SHPPacket createTypeOnePacket(String userid) {
        if (userid == null) {
            throw new IllegalArgumentException("User ID cannot be null");
        }
        if (userid.length() > 319) {
            throw new IllegalArgumentException("User ID is too long");
        }
        return new SHPPacket(userid.getBytes(), ONE);
    }

    public static SHPPacket createTypeTwoPacket() {
        try {
            byte[] nonce1 = generateNonce(16);
            byte[] nonce2 = generateNonce(16);
            byte[] nonce3 = generateNonce(16);

            ByteBuffer buffer = ByteBuffer.allocate(nonce1.length + nonce2.length + nonce3.length);
            buffer.put(nonce1);
            buffer.put(nonce2);
            buffer.put(nonce3);

            return new SHPPacket(buffer.array(), TWO);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to generate nonces for SHP type 2 packet", e);
        }
    }

    public static SHPPacket createTypeThreePacket(String request, String userID, byte[] nonce3, int udpPort, Key pbeKey) {
        try {
            // collect data parts
            byte[] requestBytes = request.getBytes();
            byte[] userIDBytes = userID.getBytes();
            incrementByteNumber(nonce3);
            byte[] nonce4 = generateNonce(16);

            // build data
            int dataLength = requestBytes.length + userIDBytes.length + nonce3.length + nonce4.length + 4; // 4 bytes for udpPort
            ByteBuffer dataBuffer = ByteBuffer.allocate(dataLength);
            dataBuffer.put(requestBytes);
            dataBuffer.put(userIDBytes);
            dataBuffer.put(nonce3);
            dataBuffer.put(nonce4);
            dataBuffer.putInt(udpPort);
            byte[] data = dataBuffer.array();

            // build security elements
            byte[] encryptedData = PBEEncrypt(data, pbeKey);
            byte[] signature = generateECDSASignature(encryptedData, ClientECCKeyPair.getInstance().getPrivate());
            byte[] mac = generateMac(encryptedData, pbeKey.getEncoded());

            return buildCryptoPacket(encryptedData, signature, mac, THREE);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Failed create SHP type 3 packet", e);
        }
    }

    public static SHPPacket createTypeFourPacket(String requestConfirmation, byte[] nonce4, PublicKey clientPubkey, Key pbeKey, byte[] cryptoConfig) {
        try {
            // collect data parts
            byte[] requestConfirmationBytes = requestConfirmation.getBytes();
            incrementByteNumber(nonce4);
            byte[] nonce5 = generateNonce(16);

            int dataLength = 4 + requestConfirmationBytes.length + nonce4.length + nonce5.length + cryptoConfig.length; // 4 bytes for request confirmation length
            ByteBuffer dataBuffer = ByteBuffer.allocate(dataLength);
            dataBuffer.putInt(requestConfirmation.length());
            dataBuffer.put(requestConfirmationBytes);
            dataBuffer.put(nonce4);
            dataBuffer.put(nonce5);
            dataBuffer.put(cryptoConfig);
            byte[] data = dataBuffer.array();

            // build security elements
            byte[] encryptedData = ECIESEncrypt(data, clientPubkey);
            byte[] signature = generateECDSASignature(encryptedData, ServerECCKeyPair.getInstance().getPrivate());
            byte[] mac = generateMac(encryptedData, pbeKey.getEncoded());

            return buildCryptoPacket(encryptedData, signature, mac, FOUR);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Failed to create SHP type 4 packet", e);
        }
    }

    public static SHPPacket createTypeFivePacket(byte[] nonce5, CryptoProvider cryptoProvider, byte[] symmetricKey, byte[] macKey) {
        try {
            String goString = "GO";
            byte[] goBytes = goString.getBytes();
            incrementByteNumber(nonce5);

            int dataLength = goBytes.length + nonce5.length;
            ByteBuffer dataBuffer = ByteBuffer.allocate(dataLength);
            dataBuffer.put(goBytes);
            dataBuffer.put(nonce5);
            byte[] data = dataBuffer.array();

            byte[] encryptedData = cryptoProvider.encrypt(data, symmetricKey);
            byte[] mac = cryptoProvider.generateIntegrityCheck(encryptedData, macKey);

            int payloadLength = 4 + encryptedData.length + 4 + mac.length;
            ByteBuffer payloadBuffer = ByteBuffer.allocate(payloadLength);
            payloadBuffer.putInt(encryptedData.length);
            payloadBuffer.put(encryptedData);
            payloadBuffer.putInt(mac.length);
            payloadBuffer.put(mac);

            return new SHPPacket(data, FIVE);
        } catch (GeneralSecurityException | InvalidCipherTextException e) {
            throw new RuntimeException("Failed to to create SHP type 5 packet", e);
        }
    }

    private static SHPPacket buildCryptoPacket(byte[] encryptedData, byte[] signature, byte[] mac, MessageType type) {
        // build payload
        // adding a length field before each element
        int payloadLength = 4 + encryptedData.length + 4 + signature.length + 4 + mac.length;
        ByteBuffer payloadBuffer = ByteBuffer.allocate(payloadLength);
        payloadBuffer.putInt(encryptedData.length);
        payloadBuffer.put(encryptedData);
        payloadBuffer.putInt(signature.length);
        payloadBuffer.put(signature);
        payloadBuffer.putInt(mac.length);
        payloadBuffer.put(mac);

        return new SHPPacket(payloadBuffer.array(), type);
    }
}
