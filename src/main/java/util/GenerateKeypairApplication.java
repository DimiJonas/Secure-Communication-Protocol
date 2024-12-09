package util;

import java.io.FileWriter;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;

import static util.SafeCurves.Curve25519;
import static util.SimpleCurves.secp256r1;
import static util.Utils.bytesToHex;

public class GenerateKeypairApplication {

        private static final String SERVER_KEYFILE_NAME = "ServerECCKeyPair.sec";
        private static final String SERVER_KEYFILE_PATH = "src/main/resources/pa2/server/" + SERVER_KEYFILE_NAME;
        private static final String CLIENT_KEYFILE_NAME = "ClientECCKeyPair.sec";
        private static final String CLIENT_RESOURCES_PATH = "src/main/resources/pa2/client/";
        private static final String CLIENT_KEYFILE_PATH = CLIENT_RESOURCES_PATH + CLIENT_KEYFILE_NAME;
        private static final String CLIENT_SERVER_PUBKEY_FILENAME = "ServerECCPubKey.txt";
        private static final String CLIENT_SERVER_PUBKEY_PATH = CLIENT_RESOURCES_PATH + CLIENT_SERVER_PUBKEY_FILENAME;
        private static final String USAGE = "Usage: GenerateKeypairApplication <client|server> <optional: curve algorithm>";

        public static void main(String[] args) throws GeneralSecurityException {
                if(args.length < 1){
                        System.err.println(USAGE);
                        System.exit(1);
                }

                String filepath = null;
                if (args[0].equals("client")) {
                        filepath = CLIENT_KEYFILE_PATH;
                } else if (args[0].equals("server")) {
                        filepath = SERVER_KEYFILE_PATH;
                } else {
                        System.err.println(USAGE);
                        System.exit(1);
                }

                String curve = secp256r1.getAlgorithm();
                if (args.length >= 2){
                        curve = args[1];
                }

                KeyPair keyPair = CryptoUtils.generateECCKeyPair(curve);
                String fileContent = "Curve: " + curve + "\n" +
                        "PrivateKey: " + bytesToHex(keyPair.getPrivate().getEncoded()) + "\n" +
                        "PublicKey: " + bytesToHex(keyPair.getPublic().getEncoded());
                // write keyfile
                try (FileWriter writer = new FileWriter(filepath, false)) {
                        writer.write(fileContent);
                        System.out.printf("Keyfile %s written successfully%n", filepath);
                } catch (IOException e) {
                        System.err.printf("An error occurred when writing file %s%n%s%n", filepath, e.getMessage());
                }

                // write server public key to client resources
                if (args[0].equals("server")){
                        fileContent = "Curve: " + curve + "\n" +
                                "PublicKey: " + bytesToHex(keyPair.getPublic().getEncoded());
                        try (FileWriter writer = new FileWriter(CLIENT_SERVER_PUBKEY_PATH, false)) {
                                writer.write(fileContent);
                                System.out.printf("Server Keyfile written successfully to client resources %s%n", CLIENT_SERVER_PUBKEY_PATH);
                        } catch (IOException e) {
                                System.err.printf("An error occurred when writing file %s%n%s%n", CLIENT_SERVER_PUBKEY_PATH, e.getMessage());
                        }
                }
        }
}
