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
import java.util.Arrays;

import static shp.MessageType.*;
import static util.ByteUtils.bytesToHex;
import static util.ByteUtils.incrementByteNumber;
import static util.CryptoUtils.*;

public class SHPPacketFactory {

    public static final String GO_STRING = "GO";

    public static SHPPacket createTypeOnePacket(String userid) {
        if (userid == null) {
            throw new IllegalArgumentException("User ID cannot be null");
        }
        if (userid.length() > 319) {
            throw new IllegalArgumentException("User ID is too long");
        }
        return new SHPPacket(userid.getBytes(), ONE);
    }

    public static SHPPacket createTypeTwoPacket(byte[] nonce1, byte[] nonce2, byte[] nonce3) {
        ByteBuffer buffer = ByteBuffer.allocate(nonce1.length + nonce2.length + nonce3.length);
        buffer.put(nonce1);
        buffer.put(nonce2);
        buffer.put(nonce3);

        return new SHPPacket(buffer.array(), TWO);
    }

    public static SHPPacket createTypeThreePacket(String request, String userID, byte[] nonce3, byte[] nonce4, int udpPort, Key pbeKey) {
        try {
            // collect data parts
            byte[] requestBytes = request.getBytes();
            byte[] userIDBytes = userID.getBytes();
            byte[] nonce3Plus1 = Arrays.copyOf(nonce3, nonce3.length);
            incrementByteNumber(nonce3Plus1);

            // build data
            int dataLength = requestBytes.length + userIDBytes.length + nonce3Plus1.length + nonce4.length + 4; // 4 bytes for udpPort
            ByteBuffer dataBuffer = ByteBuffer.allocate(dataLength);
            dataBuffer.put(requestBytes);
            dataBuffer.put(userIDBytes);
            dataBuffer.put(nonce3Plus1);
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

    public static SHPPacket createTypeThreePacket2(String request, String userID, byte[] nonce3, byte[] nonce4, int udpPort, Key pbeKey, byte[] ydhC) {
        try{
            byte[] nonce3Plus1 = Arrays.copyOf(nonce3, nonce3.length);
            incrementByteNumber(nonce3Plus1);

            // build data
            int dataLength = request.length() + userID.length() + nonce3Plus1.length + nonce4.length + 4; // 4 bytes for udpPort
            ByteBuffer dataBuffer = ByteBuffer.allocate(dataLength);
            dataBuffer.put(request.getBytes());
            dataBuffer.put(userID.getBytes());
            dataBuffer.put(nonce3Plus1);
            dataBuffer.put(nonce4);
            dataBuffer.putInt(udpPort);
            byte[] data = dataBuffer.array();

            // build security elements
            byte[] encryptedData = PBEEncrypt(data, pbeKey);
            ByteBuffer toSign = ByteBuffer.allocate(encryptedData.length + ydhC.length);
            toSign.put(encryptedData);
            toSign.put(ydhC);
            byte[] signature = generateECDSASignature(toSign.array(), ClientECCKeyPair.getInstance().getPrivate());
            ByteBuffer toMac = ByteBuffer.allocate(encryptedData.length + ydhC.length + signature.length);
            toMac.put(encryptedData);
            toMac.put(ydhC);
            toMac.put(signature);
            byte[] mac = generateMac(toMac.array(), pbeKey.getEncoded());

            // build payload
            // adding a length field before each element
            int payloadLength = 4 + encryptedData.length + 4 + ydhC.length + 4 + signature.length + 4 + mac.length;
            ByteBuffer payloadBuffer = ByteBuffer.allocate(payloadLength);
            payloadBuffer.putInt(encryptedData.length);
            payloadBuffer.put(encryptedData);
            payloadBuffer.putInt(ydhC.length);
            payloadBuffer.put(ydhC);
            payloadBuffer.putInt(signature.length);
            payloadBuffer.put(signature);
            payloadBuffer.putInt(mac.length);
            payloadBuffer.put(mac);

            return new SHPPacket(payloadBuffer.array(), THREE2);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Failed create SHP type 32 packet", e);
        }
    }

    public static SHPPacket createTypeFourPacket(String requestConfirmation, byte[] nonce4, byte[] nonce5, PublicKey clientPubkey, Key pbeKey, byte[] cryptoConfig) {
        try {
            // collect data parts
            byte[] nonce4Plus1 = Arrays.copyOf(nonce4, nonce4.length);
            incrementByteNumber(nonce4Plus1);

            int dataLength = 4 + requestConfirmation.length() + nonce4Plus1.length + nonce5.length + cryptoConfig.length; // 4 bytes for request confirmation length
            ByteBuffer dataBuffer = ByteBuffer.allocate(dataLength);
            dataBuffer.putInt(requestConfirmation.length());
            dataBuffer.put(requestConfirmation.getBytes());
            dataBuffer.put(nonce4Plus1);
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

    public static SHPPacket createTypeFourPacket2(String requestConfirmation, byte[] nonce4, byte[] nonce5, PublicKey clientPubkey, Key pbeKey, byte[] cryptoConfig, byte[] ydhS){
        try {
            byte[] nonce4Plus1 = Arrays.copyOf(nonce4, nonce4.length);
            incrementByteNumber(nonce4Plus1);

            int dataLength = 4 + requestConfirmation.length() + nonce4Plus1.length + nonce5.length + cryptoConfig.length; // 4 bytes for request confirmation length
            ByteBuffer dataBuffer = ByteBuffer.allocate(dataLength);
            dataBuffer.putInt(requestConfirmation.length());
            dataBuffer.put(requestConfirmation.getBytes());
            dataBuffer.put(nonce4Plus1);
            dataBuffer.put(nonce5);
            dataBuffer.put(cryptoConfig);
            byte[] data = dataBuffer.array();

            // build security elements
            byte[] encryptedData = ECIESEncrypt(data, clientPubkey);
            ByteBuffer toSign = ByteBuffer.allocate(encryptedData.length + ydhS.length);
            toSign.put(encryptedData);
            toSign.put(ydhS);
            byte[] signature = generateECDSASignature(toSign.array(), ServerECCKeyPair.getInstance().getPrivate());
            ByteBuffer toMac = ByteBuffer.allocate(encryptedData.length + ydhS.length + signature.length);
            toMac.put(encryptedData);
            toMac.put(ydhS);
            toMac.put(signature);
            byte[] mac = generateMac(toMac.array(), pbeKey.getEncoded());

            // build payload
            // adding a length field before each element
            int payloadLength = 4 + encryptedData.length + 4 + ydhS.length + 4 + signature.length + 4 + mac.length;
            ByteBuffer payloadBuffer = ByteBuffer.allocate(payloadLength);
            payloadBuffer.putInt(encryptedData.length);
            payloadBuffer.put(encryptedData);
            payloadBuffer.putInt(ydhS.length);
            payloadBuffer.put(ydhS);
            payloadBuffer.putInt(signature.length);
            payloadBuffer.put(signature);
            payloadBuffer.putInt(mac.length);
            payloadBuffer.put(mac);

            return new SHPPacket(payloadBuffer.array(), FOUR2);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Failed to create SHP type 42 packet", e);
        }
    }

    public static SHPPacket createTypeFivePacket(byte[] nonce5, CryptoProvider cryptoProvider, byte[] symmetricKey, byte[] macKey) {
        try {
            byte[] goBytes = GO_STRING.getBytes();
            byte[] nonce5Plus1 = Arrays.copyOf(nonce5, nonce5.length);
            incrementByteNumber(nonce5Plus1);

            int dataLength = goBytes.length + nonce5Plus1.length;
            ByteBuffer dataBuffer = ByteBuffer.allocate(dataLength);
            dataBuffer.put(goBytes);
            dataBuffer.put(nonce5Plus1);
            byte[] data = dataBuffer.array();

            byte[] encryptedData = cryptoProvider.encrypt(data, symmetricKey);
            byte[] mac = cryptoProvider.generateIntegrityCheck(encryptedData, macKey);

            int payloadLength = 4 + encryptedData.length + 4 + mac.length;
            ByteBuffer payloadBuffer = ByteBuffer.allocate(payloadLength);
            payloadBuffer.putInt(encryptedData.length);
            payloadBuffer.put(encryptedData);
            payloadBuffer.putInt(mac.length);
            payloadBuffer.put(mac);

            return new SHPPacket(payloadBuffer.array(), FIVE);
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
