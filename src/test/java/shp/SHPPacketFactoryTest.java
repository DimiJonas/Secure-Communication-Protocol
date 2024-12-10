package shp;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import crypto.CryptoProvider;
import shp.MessageType;
import shp.SHPPacket;
import shp.client.ClientECCKeyPair;
import shp.server.ServerECCKeyPair;
import util.ByteUtils;
import util.CryptoUtils;

import java.security.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

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
}