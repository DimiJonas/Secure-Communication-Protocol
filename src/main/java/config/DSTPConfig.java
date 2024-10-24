package config;

import exception.InvalidConfigurationException;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Set;
import java.util.regex.Pattern;

public class DSTPConfig {

    public static final Set<String> validCiphers = Set.of(
        "AES/CTR/NoPadding",
        "RC6/CBC/PKCS5Padding",
        "AES/GCM/NoPadding",
        "BLOWFISH/ECB/PKCS5Padding",
        "DESede/CBC/NoPadding",
        "IDEA/CTR/NoPadding",
        "RC4",
        "CHACHA20-Poly1305",
        "ChaCha20");

    public static final Set<String> validHashfunctions = Set.of(
        "SHA224",
        "SHA256",
        "SHA512",
        "SHA3-256",
        "RIPEMD320"
    );

    public static final Set<String> validHMACs = Set.of(
        "RC6GMAC",
        "HMACSHA512",
        "HMACSHA384",
        "HMACSHA256",
        "AESGMAC",
        "HMACSHA3-512"
    );

    // ALG/MODE/PADDING
    private Cipher confidentiality;
    private static final Pattern confidentiality_regex = Pattern.compile("(?i)confidentiality");
    // key in hexadecimal value with the required key size
    private String symmetric_key;
    private static final Pattern symmetric_key_regex = Pattern.compile("(?i)^\\s*symmetric[_\\-\\s]*key\\s*$");
    // integer representing the number of BITS
    private int symmetric_key_size;
    private static final Pattern symmetric_key_size_regex = Pattern.compile("(?i)symmetric[_\\-\\s]*key[_\\-\\s]*size");
    // integer or NULL
    private int iv_size;
    private static final Pattern iv_size_regex = Pattern.compile("(?i)iv[_\\-\\s]*size");
    // hexadecimal value or NULL
    private String iv;
    // regex that only matches the string 'iv' and no other strings that contain 'iv' as a substring but the regex tolerates whitespace
    private static final Pattern iv_regex = Pattern.compile("(?i)[^a-z]*iv[^a-z]*");
    // HMAC or H
    private String integrity;
    private static final Pattern integrity_regex = Pattern.compile("(?i)integrity");
    // definition of secure ash Function or NULL
    private MessageDigest h;
    private static final Pattern h_regex = Pattern.compile("(?i)^\\s*h\\s*$");
    // definition of MAC (HMAC or CMAC algorithms)
    private Mac mac;
    private static final Pattern mac_regex = Pattern.compile("(?i)^\\s*mac\\s*$");
    // mackey value in hexadecimal with required keysize or NULL
    private String mackey;
    private static final Pattern mackey_regex = Pattern.compile("(?i)^\\s*mackey\\s*$");
    // integer representing the size of the MACKEY in BITS
    private int mackey_size;
    private static final Pattern mackey_size_regex = Pattern.compile("(?i)mackey[_\\-\\s]*size");

    public DSTPConfig(String configPath) throws IOException, InvalidConfigurationException {
        try (BufferedReader reader = new BufferedReader(new FileReader(configPath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                // Skip empty lines and comments
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                String[] parts = line.split("[:=]", 2);
                if (parts.length == 2) {
                    String key = parts[0].trim();
                    String value = parts[1].trim();
                    if(key.isBlank()){
                       continue;
                    }
                    if(confidentiality_regex.matcher(key).matches()){
                        setConfidentiality(value.trim());
                    } else if (symmetric_key_regex.matcher(key).matches()){
                        setSymmetric_key(value.trim());
                    } else if (symmetric_key_size_regex.matcher(key).matches()){
                        setSymmetric_key_size(value.trim());
                    } else if (iv_size_regex.matcher(key).matches()){
                        setIv_size(value.trim());
                    } else if (iv_regex.matcher(key).matches()){
                        setIv(value.trim());
                    } else if (integrity_regex.matcher(key).matches()){
                        setIntegrity(value.trim());
                    } else if (h_regex.matcher(key).matches()){
                        setH(value.trim());
                    } else if (mac_regex.matcher(key).matches()){
                        setMac(value.trim());
                    } else if (mackey_regex.matcher(key).matches()){
                        setMackey(value.trim());
                    } else if (mackey_size_regex.matcher(key).matches()){
                        setMackey_size(value.trim());
                    }
                } else {
                    System.out.printf("Could not read config line %s%n", line);
                }
            }
        }
        validate();
    }

    /**
     * validate the configuration input
     */
    private void validate() throws InvalidConfigurationException {

        // it should always be mandatory to have a symmetric encryption key in our case right?
        if (symmetric_key == null || symmetric_key.isBlank()){
            throw new InvalidConfigurationException("Symmetric key was not specified");
        } else {
            byte[] decodedKey = Base64.getDecoder().decode(symmetric_key);
            if (decodedKey.length != symmetric_key_size) {
                throw new InvalidConfigurationException("Symmetric key does not have the specified length");
            }
        }
        if (iv == null || iv.isBlank() || iv.equalsIgnoreCase("null")){
            // TODO: check if its okay that the iv is not specified
            // e.g. it uses a mode that does not need an iv like ECB or any stream cipher
        } else {
            byte[] decodedIv = Base64.getDecoder().decode(iv);
            if (decodedIv.length != iv_size) {
                throw new InvalidConfigurationException("IV does not have the specified length");
            }
        }
        if (mac == null){
            if(integrity.equalsIgnoreCase("HMAC")){
                throw new InvalidConfigurationException("configured to use HMAC but no MAC algorithm was not specified");
            }
            // TODO: check if okay that mac is not specified
            // e.g. it uses an AEAD mode or a secure hash function
        } else {
            if (mackey == null || mackey.isBlank()){
                throw new InvalidConfigurationException("MAC key was not specified");
            }
            byte[] decodedKey = Base64.getDecoder().decode(mackey);

            if (decodedKey.length != mackey_size) {
                throw new InvalidConfigurationException("MAC key does not have the specified length");
            }
        }
        if (h == null){
            if(integrity.equalsIgnoreCase("H")){
                throw new InvalidConfigurationException("configured to use H (secure hash function) but no hash algorithm was not specified");
            }
            // TODO: check if okay that h is not specified
            // e.g. it uses an AEAD mode or a mac
        }
    }

    public Cipher getConfidentiality() {
        return confidentiality;
    }

    public void setConfidentiality(String confidentiality) throws InvalidConfigurationException {
        if(!validCiphers.contains(confidentiality)){
            throw new InvalidConfigurationException(String.format("Invalid cipher specification\nOnly the following ciphers are allowed: %s", String.join(", ", validCiphers)));
        }
        try {
            this.confidentiality = Cipher.getInstance(confidentiality);;
        } catch (NoSuchAlgorithmException e) {
            System.out.printf("Could not get instance for the given cipher algorithm %s%n", confidentiality);
        } catch (NoSuchPaddingException e) {
            System.out.printf("Could not get instance for the given padding %s%n", confidentiality);
        }
    }

    public String getSymmetric_key() {
        return symmetric_key;
    }

    public void setSymmetric_key(String symmetric_key) {
        this.symmetric_key = symmetric_key;
    }

    public int getSymmetric_key_size() {
        return symmetric_key_size;
    }

    public void setSymmetric_key_size(String symmetric_key_size) {
        if(symmetric_key_size.isBlank()){
            this.symmetric_key_size = 0;
            return;
        }
        this.symmetric_key_size = Integer.parseInt(symmetric_key_size);
    }

    public int getIv_size() {
        return iv_size;
    }

    public void setIv_size(String iv_size) {
        if(iv_size.isBlank() || iv_size.equalsIgnoreCase("null")){
            this.iv_size = 0;
            return;
        }
        this.iv_size = Integer.parseInt(iv_size);
    }

    public String getIv() {
        return iv;
    }

    public void setIv(String iv) {
        this.iv = iv;
    }

    public String getIntegrity() {
        return integrity;
    }

    public void setIntegrity(String integrity) {
        this.integrity = integrity;
    }

    public MessageDigest getH() {
        return h;
    }

    public void setH(String h) throws InvalidConfigurationException {
        if(!h.isBlank() && !h.equalsIgnoreCase("null") && !validHashfunctions.contains(h)){
            throw new InvalidConfigurationException(String.format("Invalid hash function specification\nOnly the following hash functions are allowed: %s", String.join(", ", validHashfunctions)));
        }
        if(h.isBlank() || h.equalsIgnoreCase("null")){
            return;
        }
        try {
            this.h = MessageDigest.getInstance(h);
        } catch (NoSuchAlgorithmException e) {
            System.out.printf("Could not get instance for the given hash algorithm %s%n", h);;
        }
    }

    public Mac getMac() {
        return mac;
    }

    public void setMac(String mac) throws InvalidConfigurationException {
        if(!mac.isBlank() && !mac.equalsIgnoreCase("null") && !validHMACs.contains(mac)){
            throw new InvalidConfigurationException(String.format("Invalid MAC specification\nOnly the following MAC algorithms are allowed: %s", String.join(", ", validHMACs)));
        }
        if(mac.isBlank() || mac.equalsIgnoreCase("null")){
            return;
        }
        try {
            this.mac = Mac.getInstance(mac);
        } catch (NoSuchAlgorithmException e) {
            System.out.printf("Could not get instance for the given mac algorithm %s%n", h);;
        }
    }

    public String getMackey() {
        return mackey;
    }

    public void setMackey(String mackey) {
        this.mackey = mackey;
    }

    public int getMackey_size() {
        return mackey_size;
    }

    public void setMackey_size(String mackey_size) {
        if(mackey_size.isBlank() || mackey_size.equalsIgnoreCase("null")){
            this.mackey_size = 0;
            return;
        }
        this.mackey_size = Integer.parseInt(mackey_size);
    }
}
