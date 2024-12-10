package util;

import shp.server.AuthRecord;
import shp.server.UserDB;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

import static java.lang.System.exit;
import static util.CryptoUtils.generateECCKeyPair;
import static util.ByteUtils.bytesToHex;

public class AddUserApplication {
    public static void main(String[] args) {
        String userid;
        String password;
        String pubkey;
        String privkey = null;

        Random random = new Random();
        SecureRandom secureRandom = new SecureRandom();

        // read user input
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(System.in))) {
            // read userid
            System.out.println("Enter userid (leave empty to generate one): ");
            String userLine = reader.readLine().trim();
            if (userLine.isEmpty()) {
                userid = "user" + random.nextInt(1000);
            } else {
                userid = userLine;
            }

            // read password
            System.out.println("Enter password (leave empty to generate one): ");
            String pwLine = reader.readLine().trim();
            if (pwLine.isEmpty()) {
                byte[] passwordBytes = new byte[24];
                secureRandom.nextBytes(passwordBytes);
                password = bytesToHex(passwordBytes);
            } else {
                password = pwLine;
            }

            // read public key
            System.out.println("Enter public key (leave empty to generate one): ");
            String pubkeyLine = reader.readLine().trim();
            if (pubkeyLine.isEmpty()) {
                KeyPair ecKeyPair = generateECCKeyPair();
                pubkey = bytesToHex(ecKeyPair.getPublic().getEncoded());
                privkey = bytesToHex(ecKeyPair.getPrivate().getEncoded());
            } else {
                pubkey = pubkeyLine;
            }

            UserDB db = UserDB.getInstance();
            AuthRecord record = db.addUser(userid, password, pubkey);
            if (record == null) {
                System.out.println("User already exists: " + userid);
                exit(1);
            }
            System.out.println("User added successfully: " + record.serialize());
            System.out.println("Username: " + userid);
            System.out.println("Password: " + password);
            System.out.println("Salt: " + record.salt());
            System.out.printf("Public key:%n%s%n", pubkey);
            // print private key if keypair was generated
            if (privkey != null) {
                System.out.printf("Private key:%n%s%n", privkey);
            }
        } catch (IOException e) {
            System.err.println("Error reading last line: " + e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Error generating password hash: " + e.getMessage());
        } catch (GeneralSecurityException e) {
            System.err.println("Error generating public key: " + e.getMessage());
        }
    }
}
