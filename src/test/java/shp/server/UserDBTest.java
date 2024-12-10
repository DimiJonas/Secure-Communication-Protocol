package shp.server;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.*;

public class UserDBTest {
    private UserDB userDB;

    @BeforeEach
    public void setUp() {
        // Reset the singleton instance before each test
        try {
            java.lang.reflect.Field instanceField = UserDB.class.getDeclaredField("instance");
            instanceField.setAccessible(true);
            instanceField.set(null, null);
        } catch (Exception e) {
            fail("Could not reset UserDB singleton: " + e.getMessage());
        }

        // Re-initialize the instance
        userDB = UserDB.getInstance();
    }

    @Test
    public void testGetInstance_ShouldReturnSameInstance() {
        UserDB secondInstance = UserDB.getInstance();
        assertSame(userDB, secondInstance, "getInstance() should return the same instance");
    }

    @Test
    public void testGetRecord_ExistingUser_ShouldReturnRecord() {
        // This test assumes there's a pre-existing user in the database file
        String existingUserId = "testuser"; // Replace with an actual user ID from your test database
        AuthRecord record = userDB.getRecord(existingUserId);

        assertNotNull(record, "Record should not be null for existing user");
        assertEquals(existingUserId, record.userid(), "Retrieved record should match the requested user ID");
    }

    @Test
    public void testGetRecord_NonExistingUser_ShouldReturnNull() {
        String nonExistentUserId = "nonexistentuser";
        AuthRecord record = userDB.getRecord(nonExistentUserId);

        assertNull(record, "Record should be null for non-existing user");
    }

    @Test
    public void testVerifyUser_ValidCredentials_ShouldReturnTrue() {
        // This test assumes there's a pre-existing user with known credentials in the database file
        String validUserId = "testuser"; // Replace with an actual user ID from your test database
        String validPassword = "test"; // Replace with the correct password

        boolean verified = userDB.verifyUser(validUserId, validPassword);

        assertTrue(verified, "User with correct credentials should be verified");
    }

    @Test
    public void testVerifyUser_InvalidPassword_ShouldReturnFalse() {
        // This test assumes there's a pre-existing user in the database file
        String existingUserId = "testuser"; // Replace with an actual user ID from your test database
        String incorrectPassword = "wrongpassword";

        boolean verified = userDB.verifyUser(existingUserId, incorrectPassword);

        assertFalse(verified, "User with incorrect password should not be verified");
    }

    @Test
    public void testVerifyUser_NonExistingUser_ShouldReturnFalse() {
        String nonExistentUserId = "nonexistentuser";
        String anyPassword = "somepassword";

        boolean verified = userDB.verifyUser(nonExistentUserId, anyPassword);

        assertFalse(verified, "Non-existing user should not be verified");
    }

    @Test
    public void testAddUser_NewUser_ShouldSucceed() throws NoSuchAlgorithmException {
        String newUserId = "newuser" + System.currentTimeMillis(); // Unique user ID
        String newPassword = "newpassword";
        String newPubKey = "newpublickey";

        AuthRecord addedRecord = userDB.addUser(newUserId, newPassword, newPubKey);

        assertNotNull(addedRecord, "Adding a new user should return a non-null record");
        assertEquals(newUserId, addedRecord.userid(), "Added record should have the correct user ID");

        // Verify the user can be retrieved and verified
        AuthRecord retrievedRecord = userDB.getRecord(newUserId);
        assertNotNull(retrievedRecord, "Newly added user should be retrievable");

        boolean verified = userDB.verifyUser(newUserId, newPassword);
        assertTrue(verified, "Newly added user should be verifiable with the correct password");

        // Clean up by deleting the user
        userDB.deleteUser(newUserId);
    }

    @Test
    public void testAddUser_ExistingUser_ShouldReturnNull() throws NoSuchAlgorithmException {
        // This test assumes there's a pre-existing user in the database file
        String existingUserId = "testuser"; // Replace with an actual user ID from your test database
        String existingPassword = "somepassword"; // Replace with a suitable password
        String newPubKey = "anotherpublickey";

        AuthRecord addedRecord = userDB.addUser(existingUserId, existingPassword, newPubKey);

        assertNull(addedRecord, "Adding an existing user should return null");
    }
}