package shp.server;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import static util.HashUtils.generateSha256Hash;

public class UserDB {
    private static final String DB_PATH = "src/main/resources/pa2/server/userdatabase.txt";
    private static final String DB_DELIMITER = ":";

    private final Map<String, AuthRecord> db;
    private static UserDB instance;

    private UserDB() {
        db = new HashMap<>();
        try (BufferedReader reader = new BufferedReader(new FileReader(DB_PATH))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                // Skip empty lines and comments
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                String[] parts = line.split(DB_DELIMITER);
                if (parts.length != 4) {
                    System.out.printf("Invalid database entry: '%s'%n", line);
                    continue;
                }
                db.put(parts[0], new AuthRecord(parts[0], parts[1], parts[2], parts[3]));
            }
        } catch (IOException e) {
            System.out.printf("Could not read database file '%s'%n%s", DB_PATH, e);
        }
    }

    public static UserDB getInstance() {
        if (instance == null) {
            instance = new UserDB();
        }
        return instance;
    }

    public AuthRecord getRecord(String userid) {
        return db.get(userid);
    }

    public boolean verifyUser(String userid, String password) {
        AuthRecord record = db.get(userid);
        if (record == null) {
            System.out.printf("Could not verify user '%s': user not present in database%n%n", userid);
            return false;
        }

        return record.passwordhash().equalsIgnoreCase(generateSha256Hash(password + record.salt()));
    }

    public synchronized AuthRecord addUser(String userid, String password, String pubkey) {
        if (db.containsKey(userid)) {
            System.out.printf("Could not add user '%s': user already present in database%n%n", userid);
            return null;
        }

        Random random = new Random();
        String salt = String.valueOf(random.nextLong());
        String passwordhash = generateSha256Hash(password + salt);
        AuthRecord record = new AuthRecord(userid, passwordhash, salt, pubkey);
        db.put(userid, record);

        try (FileWriter fileWriter = new FileWriter(DB_PATH, true)) {
            fileWriter.write(record.serialize() + System.lineSeparator());
            System.out.printf("User '%s' added to database%n%n", userid);
            return record;
        } catch (IOException e) {
            System.err.printf("An error occurred while writing user %s to the database: %s", userid, e.getMessage());
            return null;
        }
    }
}
