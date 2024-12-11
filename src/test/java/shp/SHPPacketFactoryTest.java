package shp;

import crypto.CryptoProvider;
import crypto.CryptoProviderFactory;
import dstp.config.DSTPConfig;
import dstp.config.TestConfigBuilder;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import shp.client.ClientECCKeyPair;
import shp.server.ServerECCKeyPair;
import util.ByteUtils;
import util.CryptoUtils;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static shp.SHPPacketFactory.GO_STRING;
import static util.ByteUtils.hexToBytes;
import static util.CryptoUtils.*;

class SHPPacketFactoryTest {

    private Key mockPbeKey;
    private PublicKey mockClientPublicKey;
    private CryptoProvider mockCryptoProvider;

    @BeforeEach
    void setUp() {
        mockPbeKey = mock(Key.class);
        mockClientPublicKey = mock(PublicKey.class);
        mockCryptoProvider = mock(CryptoProvider.class);
    }

    @Test
    void testCreateTypeOnePacket_ValidUserid() {
        String userid = "testuser";
        SHPPacket packet = SHPPacketFactory.createTypeOnePacket(userid);

        assertNotNull(packet);
        assertEquals(MessageType.ONE, packet.getType());
        assertArrayEquals(userid.getBytes(), packet.getData());
    }

    @Test
    void testCreateTypeOnePacket_NullUserid() {
        assertThrows(IllegalArgumentException.class,
                () -> SHPPacketFactory.createTypeOnePacket(null));
    }

    @Test
    void testCreateTypeOnePacket_LongUserid() {
        String longUserid = "a".repeat(320);
        assertThrows(IllegalArgumentException.class,
                () -> SHPPacketFactory.createTypeOnePacket(longUserid));
    }

    @Test
    void testCreateTypeTwoPacket() {
        try (MockedStatic<ByteUtils> byteUtilsMockedStatic = Mockito.mockStatic(ByteUtils.class)) {
            SHPPacket packet = SHPPacketFactory.createTypeTwoPacket();

            assertNotNull(packet);
            assertEquals(MessageType.TWO, packet.getType());
            assertEquals(48, packet.getData().length); // 3 * 16-byte nonces
        } catch (Exception e) {
            fail("Unexpected exception: " + e.getMessage());
        }
    }

    @Test
    void testCreateTypeThreePacket() {
        try (MockedStatic<ClientECCKeyPair> clientEccMock = Mockito.mockStatic(ClientECCKeyPair.class)) {
            Key pbeKey = CryptoUtils.generatePBEKey(new char[16]);
            KeyPair clientKeyPair = CryptoUtils.generateECCKeyPair();

            // Setup mocks
            ClientECCKeyPair mockClientEccKeyPair = mock(ClientECCKeyPair.class);
            when(ClientECCKeyPair.getInstance()).thenReturn(mockClientEccKeyPair);
            when(mockClientEccKeyPair.getPrivate()).thenReturn(clientKeyPair.getPrivate());

            when(mockPbeKey.getEncoded()).thenReturn(new byte[16]);

            // Prepare test data
            String request = "test_request";
            String userID = "test_user";
            byte[] nonce3 = new byte[16];
            int udpPort = 8080;

            SHPPacket packet = SHPPacketFactory.createTypeThreePacket(request, userID, nonce3, udpPort, pbeKey);

            assertNotNull(packet);
            assertEquals(MessageType.THREE, packet.getType());
            assertNotNull(packet.getData());
        } catch (Exception e) {
            fail("Unexpected exception: " + e.getMessage());
        }
    }

    @Test
    void testCreateTypeFourPacket() {
        try (MockedStatic<ServerECCKeyPair> serverEccMock = Mockito.mockStatic(ServerECCKeyPair.class)) {
            KeyPair serverKeyPair = CryptoUtils.generateECCKeyPair();
            PublicKey clientPublicKey = serverKeyPair.getPublic();
            Key pbeKey = CryptoUtils.generatePBEKey(new char[16]);

            // Setup mocks
            when(mockClientPublicKey.getEncoded()).thenReturn(serverKeyPair.getPublic().getEncoded());
            ServerECCKeyPair mockServerEccKeyPair = mock(ServerECCKeyPair.class);
            when(ServerECCKeyPair.getInstance()).thenReturn(mockServerEccKeyPair);
            when(mockServerEccKeyPair.getPrivate()).thenReturn(serverKeyPair.getPrivate());

            when(mockPbeKey.getEncoded()).thenReturn(new byte[16]);

            // Prepare test data
            String requestConfirmation = "confirmed";
            byte[] nonce4 = new byte[16];
            byte[] cryptoConfig = new byte[32];

            SHPPacket packet = SHPPacketFactory.createTypeFourPacket(requestConfirmation, nonce4, clientPublicKey, pbeKey, cryptoConfig);

            assertNotNull(packet);
            assertEquals(MessageType.FOUR, packet.getType());
            assertNotNull(packet.getData());
        } catch (Exception e) {
            fail("Unexpected exception: " + e.getMessage());
        }
    }

    @Test
    void testCreateTypeFivePacket() throws Exception {
        // Prepare test data
        byte[] nonce5 = new byte[16];
        byte[] symmetricKey = new byte[32];
        byte[] macKey = new byte[16];
        byte[] encryptedData = "encryptedData".getBytes();
        byte[] mac = "mac".getBytes();

        // Setup mock crypto provider
        when(mockCryptoProvider.encrypt(any(), eq(symmetricKey))).thenReturn(encryptedData);
        when(mockCryptoProvider.generateIntegrityCheck(any(), eq(macKey))).thenReturn(mac);

        SHPPacket packet = SHPPacketFactory.createTypeFivePacket(nonce5, mockCryptoProvider, symmetricKey, macKey);

        assertNotNull(packet);
        assertEquals(MessageType.FIVE, packet.getType());
        assertNotNull(packet.getData());
        assertEquals(4 + encryptedData.length + 4 + mac.length, packet.getData().length);
    }

    @Test
    void testCreateTypeFivePacket_CryptoException() throws Exception {
        byte[] nonce5 = new byte[16];
        byte[] symmetricKey = new byte[32];
        byte[] macKey = new byte[16];

        // Simulate crypto exception
        when(mockCryptoProvider.encrypt(any(), eq(symmetricKey)))
                .thenThrow(new GeneralSecurityException("Encryption failed"));

        assertThrows(RuntimeException.class, () ->
                SHPPacketFactory.createTypeFivePacket(nonce5, mockCryptoProvider, symmetricKey, macKey)
        );
    }

    @Test
    void testPacketOne() {
        SHPPacket packet = SHPPacketFactory.createTypeOnePacket("testuser");
        assertEquals(MessageType.ONE, packet.getType());
        assertArrayEquals("testuser".getBytes(), packet.getData());
    }

    @Test
    void testPacketTwo() {
        SHPPacket packet = SHPPacketFactory.createTypeTwoPacket();
        assertEquals(MessageType.TWO, packet.getType());
        assertEquals(48, packet.getData().length);

        byte[] data = packet.getData();
        ByteBuffer nonceBuffer = ByteBuffer.wrap(data);
        byte[] nonce1 = new byte[16];
        nonceBuffer.get(nonce1);
        byte[] nonce2 = new byte[16];
        nonceBuffer.get(nonce2);
        byte[] nonce3 = new byte[16];
        nonceBuffer.get(nonce3);

        // ensure nonces are unique
        assertNotEquals(ByteBuffer.wrap(nonce1).getLong(), ByteBuffer.wrap(nonce2).getLong());
        assertNotEquals(ByteBuffer.wrap(nonce2).getLong(), ByteBuffer.wrap(nonce3).getLong());
        assertNotEquals(ByteBuffer.wrap(nonce3).getLong(), ByteBuffer.wrap(nonce1).getLong());

        packet = SHPPacketFactory.createTypeTwoPacket();
        data = packet.getData();
        nonceBuffer = ByteBuffer.wrap(data);
        byte[] nonce1a = new byte[16];
        nonceBuffer.get(nonce1a);
        byte[] nonce2a = new byte[16];
        nonceBuffer.get(nonce2a);
        byte[] nonce3a = new byte[16];
        nonceBuffer.get(nonce3a);

        // ensure new nonces are created each time
        assertNotEquals(ByteBuffer.wrap(nonce1).getLong(), ByteBuffer.wrap(nonce1a).getLong());
        assertNotEquals(ByteBuffer.wrap(nonce2).getLong(), ByteBuffer.wrap(nonce2a).getLong());
        assertNotEquals(ByteBuffer.wrap(nonce3).getLong(), ByteBuffer.wrap(nonce3a).getLong());
    }

    @Test
    void testPacketThree() throws GeneralSecurityException {
        try (MockedStatic<ClientECCKeyPair> clientEccMock = Mockito.mockStatic(ClientECCKeyPair.class)) {
            KeyPair clientKeyPair = CryptoUtils.generateECCKeyPair();
            // Setup mocks
            ClientECCKeyPair mockClientEccKeyPair = mock(ClientECCKeyPair.class);
            when(ClientECCKeyPair.getInstance()).thenReturn(mockClientEccKeyPair);
            when(mockClientEccKeyPair.getPrivate()).thenReturn(clientKeyPair.getPrivate());

            String request = "test_request";
            String username = "test_user";
            byte[] nonce3 = CryptoUtils.generateNonce(16);
            int udpPort = 12345;
            String password = "password";
            Key pbeKey = CryptoUtils.generatePBEKey(password.toCharArray());

            SHPPacket packet = SHPPacketFactory.createTypeThreePacket(request, username, Arrays.copyOf(nonce3, nonce3.length), udpPort, pbeKey);
            assertEquals(MessageType.THREE, packet.getType());

            byte[] data = packet.getData();
            ByteBuffer dataBuffer = ByteBuffer.wrap(data);

            // unwrap data
            // encrypted data
            int encryptedDataLength = dataBuffer.getInt();
            byte[] encryptedData = new byte[encryptedDataLength];
            dataBuffer.get(encryptedData);
            // signature
            int signatureLength = dataBuffer.getInt();
            byte[] signature = new byte[signatureLength];
            dataBuffer.get(signature);
            // mac
            int macLength = dataBuffer.getInt();
            byte[] mac = new byte[macLength];
            dataBuffer.get(mac);

            // verify mac
            assertTrue(CryptoUtils.verifyMac(encryptedData, mac, pbeKey.getEncoded()));

            // verify signature
            assertTrue(CryptoUtils.verifyECDSASignature(encryptedData, signature, clientKeyPair.getPublic()));

            // decrypt data
            byte[] decryptedData = PBEDecrypt(encryptedData, pbeKey);
            dataBuffer = ByteBuffer.wrap(decryptedData);

            // extract data
            byte[] requestBytes = new byte[request.length()];
            dataBuffer.get(requestBytes);
            String reconstructedRequest = new String(requestBytes);
            assertEquals(request, reconstructedRequest);
            byte[] userIDBytes = new byte[username.length()];
            dataBuffer.get(userIDBytes);
            String reconstructedUsername = new String(userIDBytes);
            assertEquals(username, reconstructedUsername);
            byte[] nonce3Plus1 = new byte[16];
            dataBuffer.get(nonce3Plus1);
            assertTrue(ByteUtils.isExactlyOnelarger(nonce3, nonce3Plus1));
            byte[] nonce4 = new byte[16];
            dataBuffer.get(nonce4);
            assertNotEquals(ByteBuffer.wrap(nonce3).getLong(), ByteBuffer.wrap(nonce4).getLong());
            int reconstructedUDPPort = dataBuffer.getInt();
            assertEquals(udpPort, reconstructedUDPPort);
        } catch (Exception e) {
            fail("Unexpected exception: " + e.getMessage());
        }
    }

    @Test
    void testPacketFour() {
        try (MockedStatic<ServerECCKeyPair> serverEccMock = Mockito.mockStatic(ServerECCKeyPair.class)) {
            KeyPair serverKeyPair = CryptoUtils.generateECCKeyPair();
            KeyPair clientKeyPair = CryptoUtils.generateECCKeyPair();

            // Setup mocks
            ServerECCKeyPair mockServerEccKeyPair = mock(ServerECCKeyPair.class);
            when(ServerECCKeyPair.getInstance()).thenReturn(mockServerEccKeyPair);
            when(mockServerEccKeyPair.getPrivate()).thenReturn(serverKeyPair.getPrivate());

            // Prepare test data
            String requestConfirmation = "confirmed";
            byte[] nonce4 = generateNonce(16);
            String cryptoConfigString = new TestConfigBuilder()
                    .generateSymmetricKey("AES/GCM/NoPadding", 256)
                    .generateIv(16)
                    .setIntegrity("hash")
                    .setH("SHA-256")
                    .build().serialize();
            byte[] cryptoConfig = cryptoConfigString.getBytes();
            String password = "password";
            Key pbeKey = CryptoUtils.generatePBEKey(password.toCharArray());

            SHPPacket packet = SHPPacketFactory.createTypeFourPacket(requestConfirmation, Arrays.copyOf(nonce4, nonce4.length), clientKeyPair.getPublic(), pbeKey, cryptoConfig);

            assertNotNull(packet);
            assertEquals(MessageType.FOUR, packet.getType());

            byte[] data = packet.getData();
            ByteBuffer dataBuffer = ByteBuffer.wrap(data);

            // encrypted data
            int encryptedDataLength = dataBuffer.getInt();
            byte[] encryptedData = new byte[encryptedDataLength];
            dataBuffer.get(encryptedData);
            // signature
            int signatureLength = dataBuffer.getInt();
            byte[] signature = new byte[signatureLength];
            dataBuffer.get(signature);
            // mac
            int macLength = dataBuffer.getInt();
            byte[] mac = new byte[macLength];
            dataBuffer.get(mac);

            // verify mac
            assertTrue(CryptoUtils.verifyMac(encryptedData, mac, pbeKey.getEncoded()));

            // verify signature
            assertTrue(CryptoUtils.verifyECDSASignature(encryptedData, signature, serverKeyPair.getPublic()));

            // decrypt data
            byte[] decryptedData = ECIESDecrypt(encryptedData, clientKeyPair.getPrivate());
            dataBuffer = ByteBuffer.wrap(decryptedData);

            // extract data
            int requestConfirmationLength = dataBuffer.getInt();
            byte[] requestConfirmationBytes = new byte[requestConfirmationLength];
            dataBuffer.get(requestConfirmationBytes);
            String reconstructedRequestConfirmation = new String(requestConfirmationBytes);
            assertEquals(requestConfirmation, reconstructedRequestConfirmation);
            byte[] nonce4Plus1 = new byte[16];
            dataBuffer.get(nonce4Plus1);
            assertTrue(ByteUtils.isExactlyOnelarger(nonce4, nonce4Plus1));
            byte[] nonce5 = new byte[16];
            dataBuffer.get(nonce5);
            assertNotEquals(0, ByteUtils.compareByteArrayNumbers(nonce5, nonce4));
            byte[] cryptoConfigBytes = new byte[dataBuffer.remaining()];
            dataBuffer.get(cryptoConfigBytes);
            String reconstructedCryptoConfigString = new String(cryptoConfigBytes);
            assertEquals(cryptoConfigString, reconstructedCryptoConfigString);

        } catch (Exception e) {
            fail("Unexpected exception: " + e.getMessage());
        }
    }

    @Test
    void testPacketFive() throws GeneralSecurityException, InvalidCipherTextException {
        DSTPConfig cryptoConfig = new TestConfigBuilder()
                .generateSymmetricKey("AES/GCM/NoPadding", 256)
                .generateIv(16)
                .setIntegrity("hash")
                .setH("SHA-256")
                .build();
        CryptoProvider cryptoProvider = CryptoProviderFactory.createBouncyCastleProvider(cryptoConfig);
        byte[] nonce5 = generateNonce(16);

        SHPPacket packet = SHPPacketFactory.createTypeFivePacket(Arrays.copyOf(nonce5, nonce5.length), cryptoProvider, hexToBytes(cryptoConfig.getSymmetric_key()), hexToBytes(cryptoConfig.getMackey()));

        assertNotNull(packet);
        assertEquals(MessageType.FIVE, packet.getType());

        byte[] data = packet.getData();
        ByteBuffer dataBuffer = ByteBuffer.wrap(data);

        // encrypted data
        int encryptedDataLength = dataBuffer.getInt();
        byte[] encryptedData = new byte[encryptedDataLength];
        dataBuffer.get(encryptedData);
        // mac
        int macLength = dataBuffer.getInt();
        byte[] mac = new byte[macLength];
        dataBuffer.get(mac);

        // verify mac
        assertTrue(cryptoProvider.verifyIntegrityCheck(encryptedData, mac, hexToBytes(cryptoConfig.getMackey())));

        // decrypt data
        byte[] decryptedData = cryptoProvider.decrypt(encryptedData, hexToBytes(cryptoConfig.getSymmetric_key()));
        dataBuffer = ByteBuffer.wrap(decryptedData);
        int goStringLength = decryptedData.length - 16; // only nonce5Plus1
        byte[] goStringBytes = new byte[goStringLength];
        dataBuffer.get(goStringBytes);
        String goString = new String(goStringBytes);
        assertEquals(GO_STRING, goString);
        byte[] nonce5Plus1 = new byte[16];
        dataBuffer.get(nonce5Plus1);
        assertTrue(ByteUtils.isExactlyOnelarger(nonce5, nonce5Plus1));
    }
}