package shp;

import crypto.CryptoProviderFactory;
import dstp.config.DSTPConfig;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import shp.client.ClientECCKeyPair;
import shp.client.SHPClient;
import shp.client.ServerECCPubKey;
import shp.server.AuthRecord;
import shp.server.SHPServer;
import shp.server.ServerECCKeyPair;
import shp.server.UserDB;
import util.CryptoUtils;

import java.security.KeyPair;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static util.ByteUtils.bytesToHex;

public class SHPProtocolIntegrationTest {
    private static final int TEST_PORT = 9876;
    private static final String TEST_HOST = "localhost";
    private static final String TEST_USERNAME = "testuser123";
    private static final String TEST_PASSWORD = "testpassword";
    private static final String TEST_REQUEST = "test_service_request";
    private static final int TEST_UDP_PORT = 5678;
    private KeyPair clientECCKeyPair;
    private KeyPair serverECCKeyPair;
    private AuthRecord testRecord;

    @BeforeEach
    void setup() throws Exception {
        clientECCKeyPair = CryptoUtils.generateECCKeyPair();
        System.out.printf("setting up test with clientkeypair:%npublic: %s%nprivate: %s%n", bytesToHex(clientECCKeyPair.getPublic().getEncoded()), bytesToHex(clientECCKeyPair.getPrivate().getEncoded()));
        serverECCKeyPair = CryptoUtils.generateECCKeyPair();
        testRecord = UserDB.getInstance().addUser(TEST_USERNAME, TEST_PASSWORD, bytesToHex(clientECCKeyPair.getPublic().getEncoded()));
    }

    @AfterEach
    void cleanup() {
        UserDB.getInstance().deleteUser(TEST_USERNAME);
    }

    @Test
    void testFullSHPHandshakeProtocol() throws Exception {
        try (MockedStatic<ClientECCKeyPair> clientEccMock = Mockito.mockStatic(ClientECCKeyPair.class);
             MockedStatic<ServerECCKeyPair> serverEccMock = Mockito.mockStatic(ServerECCKeyPair.class);
             MockedStatic<UserDB> userDBMock = Mockito.mockStatic(UserDB.class);
             MockedStatic<ServerECCPubKey> serverEccPubkeyMock = Mockito.mockStatic(ServerECCPubKey.class)) {

            // Setup mocks
            ServerECCKeyPair mockServerEccKeyPair = mock(ServerECCKeyPair.class);
            when(ServerECCKeyPair.getInstance()).thenReturn(mockServerEccKeyPair);
            when(mockServerEccKeyPair.getPrivate()).thenReturn(serverECCKeyPair.getPrivate());
            when(mockServerEccKeyPair.getPublic()).thenReturn(serverECCKeyPair.getPublic());

            ClientECCKeyPair mockClientEccKeyPair = mock(ClientECCKeyPair.class);
            when(ClientECCKeyPair.getInstance()).thenReturn(mockClientEccKeyPair);
            when(mockClientEccKeyPair.getPrivate()).thenReturn(clientECCKeyPair.getPrivate());
            when(mockClientEccKeyPair.getPublic()).thenReturn(clientECCKeyPair.getPublic());

            UserDB mockUserDB = mock(UserDB.class);
            when(UserDB.getInstance()).thenReturn(mockUserDB);
            when(mockUserDB.getRecord(TEST_USERNAME)).thenReturn(testRecord);
            when(mockUserDB.verifyUser(TEST_USERNAME, TEST_PASSWORD)).thenReturn(true);

            ServerECCPubKey mockServerEccPubKey = mock(ServerECCPubKey.class);
            when(ServerECCPubKey.getInstance()).thenReturn(mockServerEccPubKey);
            when(mockServerEccPubKey.getPublic()).thenReturn(serverECCKeyPair.getPublic());

            // Use CountDownLatch to synchronize server and client
            CountDownLatch serverStartedLatch = new CountDownLatch(1);

            // Executor to run server and client concurrently
            ExecutorService executor = Executors.newFixedThreadPool(2);

            // Server-side execution
            Future<SHPResult> serverFuture = executor.submit(() -> {
                SHPServer server = new SHPServer(TEST_PORT);
                serverStartedLatch.countDown();
                return server.executeHandshake();
            });

            // Wait for server to start
            serverStartedLatch.await();

            // Client-side execution
            Future<SHPResult> clientFuture = executor.submit(() -> {
                SHPClient client = new SHPClient(
                        TEST_HOST,
                        TEST_PORT,
                        TEST_USERNAME,
                        TEST_PASSWORD,
                        TEST_REQUEST,
                        TEST_UDP_PORT
                );
                return client.executeHandshake();
            });

            // Get results
            SHPResult serverResult = serverFuture.get();
            SHPResult clientResult = clientFuture.get();

            // Verify results
            assertNotNull(serverResult);
            assertNotNull(clientResult);

            // Verify basic protocol parameters match
            assertEquals(TEST_HOST, clientResult.host());
            assertEquals(TEST_HOST, serverResult.host());
            assertEquals(TEST_UDP_PORT, clientResult.udpPort());
            assertEquals(TEST_UDP_PORT, serverResult.udpPort());
            assertEquals(TEST_USERNAME, clientResult.username());
            assertEquals(TEST_USERNAME, serverResult.username());
            assertEquals(TEST_REQUEST, clientResult.request());
            assertEquals(TEST_REQUEST, serverResult.request());

            // Verify crypto configuration
            DSTPConfig serverConfig = serverResult.config();
            DSTPConfig clientConfig = clientResult.config();

            assertNotNull(serverConfig);
            assertNotNull(clientConfig);

            assertEquals(serverConfig.serialize(), clientConfig.serialize());

            // Verify crypto provider can be created
            assertDoesNotThrow(() -> {
                CryptoProviderFactory.createBouncyCastleProvider(serverConfig);
                CryptoProviderFactory.createBouncyCastleProvider(clientConfig);
            });

            // Cleanup
            executor.shutdown();
        }
    }
}
