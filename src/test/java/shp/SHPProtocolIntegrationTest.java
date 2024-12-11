package shp;

import crypto.CryptoProviderFactory;
import dstp.config.DSTPConfig;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import shp.client.SHPClient;
import shp.server.SHPServer;
import shp.server.UserDB;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.*;

public class SHPProtocolIntegrationTest {
    private static final int TEST_PORT = 9876;
    private static final String TEST_HOST = "127.0.0.1";
    private static final String TEST_USERNAME = "testuser123";
    private static final String TEST_PASSWORD = "testpassword";
    private static final String TEST_REQUEST = "test_service_request";
    private static final int TEST_UDP_PORT = 5678;
    private static final String clientPubkey = "3059301306072a8648ce3d020106082a8648ce3d03010703420004435824c90c5331681daab2382e6e58a74fff61848d17b2454ac36ad22f7931ca32a236e1a0d9d9782175751c940af5cbb1c6f475487ebdb6ddfd623e4a3b10c5";

    @BeforeEach
    void setup() throws Exception {
        UserDB.getInstance().addUser(TEST_USERNAME, TEST_PASSWORD, clientPubkey);
    }

    @AfterEach
    void cleanup() {
        UserDB.getInstance().deleteUser(TEST_USERNAME);
    }

    @Test
    void testFullSHPHandshakeProtocol() throws Exception {
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
