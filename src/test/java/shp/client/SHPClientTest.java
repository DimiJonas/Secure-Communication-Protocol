package shp.client;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;
import static util.ByteUtils.hexToBytes;
import static util.ByteUtils.incrementByteNumber;
import static util.CryptoUtils.generateNonce;

public class SHPClientTest {

    private SHPClient shpClient;

    @Mock
    private Socket mockSocket;

    @Mock
    private BufferedInputStream mockInput;

    @Mock
    private BufferedOutputStream mockOutput;

    @BeforeEach
    public void setUp() throws IOException {
        MockitoAnnotations.openMocks(this);

        // Mock socket input/output streams
        when(mockSocket.getInputStream()).thenReturn(mockInput);
        when(mockSocket.getOutputStream()).thenReturn(mockOutput);

        // Create SHPClient with mock parameters
        shpClient = new SHPClient(
                "localhost",
                8080,
                "testuser",
                "testpassword",
                "testrequest",
                9090
        );
    }

    @Test
    public void testConstructor_InitializationSuccessful() {
        assertNotNull(shpClient);
        assertEquals("localhost", getPrivateField(shpClient, "host"));
        assertEquals(8080, Optional.ofNullable(getPrivateField(shpClient, "tcpPort")).get());
        assertEquals("testuser", getPrivateField(shpClient, "username"));
    }

    @Test
    public void testCheckAndAddNonce_UniqueNoncesAccepted() {
        byte[] nonce1 = new byte[16];
        nonce1[0] = 1;
        byte[] nonce2 = new byte[16];
        nonce2[0] = 2;

        assertDoesNotThrow(() -> {
            invokePrivateMethod(shpClient, "checkAndAddNonce", nonce1);
            invokePrivateMethod(shpClient, "checkAndAddNonce", nonce2);
        });
    }

    @Test
    public void testCheckAndAddNonce_DuplicateNonceRejected() throws NoSuchAlgorithmException {
        byte[] nonce = generateNonce(16);

        // First nonce should be accepted
        assertDoesNotThrow(() ->
                invokePrivateMethod(shpClient, "checkAndAddNonce", nonce)
        );

        // Second identical nonce should throw an exception
        assertThrows(Exception.class, () ->
                invokePrivateMethod(shpClient, "checkAndAddNonce", nonce)
        );
    }

    @Test
    public void testCheckAndAddMac_UniqueMacsAccepted() {
        byte[] mac1 = hexToBytes("a1b2c3");
        byte[] mac2 = hexToBytes("d4e5f6");

        assertDoesNotThrow(() -> {
            invokePrivateMethod(shpClient, "checkAndAddMac", mac1);
            invokePrivateMethod(shpClient, "checkAndAddMac", mac2);
        });
    }

    @Test
    public void testCheckAndAddMac_DuplicateMacRejected() {
        byte[] mac = hexToBytes("a1b2c3");

        // First MAC should be accepted
        assertDoesNotThrow(() ->
                invokePrivateMethod(shpClient, "checkAndAddMac", mac)
        );

        // Second identical MAC should throw an exception
        assertThrows(Exception.class, () ->
                invokePrivateMethod(shpClient, "checkAndAddMac", mac)
        );
    }

    @Test
    public void testVerifyNonceChallenge_ValidChallenge() throws NoSuchAlgorithmException {
        byte[] challenge = generateNonce(16);
        byte[] challengeResponse = Arrays.copyOf(challenge, 16);
        incrementByteNumber(challengeResponse);

        assertDoesNotThrow(() ->
                invokePrivateMethod(shpClient, "verifyNonceChallenge", challenge, challengeResponse)
        );
    }

    @Test
    public void testVerifyNonceChallenge_InvalidChallenge() throws NoSuchAlgorithmException {
        byte[] challenge = generateNonce(16);
        byte[] challengeResponse = new byte[16];
        System.arraycopy(challenge, 0, challengeResponse, 0, 16);
        challengeResponse[0] += 2; // Not exactly one larger

        assertThrows(Exception.class, () ->
                invokePrivateMethod(shpClient, "verifyNonceChallenge", challenge, challengeResponse)
        );
    }

    @Test
    public void testExecuteHandshake_NetworkError() throws IOException {
        // Simulate network error by throwing IOException
        when(mockSocket.getInputStream()).thenThrow(new IOException("Network error"));

        assertThrows(RuntimeException.class, () -> {
            shpClient.executeHandshake();
        });
    }

    // Utility methods for testing private methods and fields
    private <T> T getPrivateField(Object obj, String fieldName) {
        try {
            var field = obj.getClass().getDeclaredField(fieldName);
            field.setAccessible(true);
            return (T) field.get(obj);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private void invokePrivateMethod(Object obj, String methodName, Object... args) throws Exception {
        var method = findMethod(obj.getClass(), methodName, args);
        method.setAccessible(true);
        method.invoke(obj, args);
    }

    // Helper method to find the correct method using reflection
    private java.lang.reflect.Method findMethod(Class<?> clazz, String methodName, Object... args) {
        for (java.lang.reflect.Method method : clazz.getDeclaredMethods()) {
            if (method.getName().equals(methodName)
                    && method.getParameterTypes().length == args.length) {
                boolean matchFound = true;
                for (int i = 0; i < args.length; i++) {
                    if (!method.getParameterTypes()[i].isAssignableFrom(args[i].getClass())) {
                        matchFound = false;
                        break;
                    }
                }
                if (matchFound) {
                    return method;
                }
            }
        }
        throw new RuntimeException("No method found: " + methodName);
    }
}