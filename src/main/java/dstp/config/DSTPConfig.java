package dstp.config;

import java.io.*;
import java.nio.Buffer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static dstp.config.DSTPConfig.Integrity.NONE;
import static dstp.config.DSTPConfig.Integrity.parseIntegrity;

public class DSTPConfig {

    public enum Integrity {
        MAC,
        HASH,
        NONE;

        static Integrity parseIntegrity(String integrity){
            if (integrity.toLowerCase().contains("mac")) {
                return MAC;
            } else if (integrity.equalsIgnoreCase("H") || integrity.toLowerCase().contains("hash")) {
                return HASH;
            } else {
                return NONE;
            }
        }
    }

    // ALG/MODE/PADDING
    private String confidentiality = "";
    private static final Pattern confidentiality_regex = Pattern.compile("(?i)^\\s*confidentiality.*[:=\\s](?<value>.*)$");
    // key in hexadecimal value with the required key size
    private String symmetric_key = "";
    private static final Pattern symmetric_key_regex = Pattern.compile("(?i)^\\s*symmetric[_\\-\\s]*key[^a-z]*[:=\\s](?<value>[a-z0-9]*)$");
    // integer representing the number of BITS
    private int symmetric_key_size = 0;
    private static final Pattern symmetric_key_size_regex = Pattern.compile("(?i)^\\s*symmetric[_\\-\\s]*key[_\\-\\s]*size.*[:=\\s](?<value>[0-9\\s]*)$");
    // integer or NULL
    private int iv_size = 0;
    private static final Pattern iv_size_regex = Pattern.compile("(?i)^\\s*iv[_\\-\\s]*size.*[:=\\s](?<value>[0-9\\s]*)$");
    // hexadecimal value or NULL
    private String iv = "";
    private static final Pattern iv_regex = Pattern.compile("(?i)^[^a-z]*iv[^a-z]*[:=\\s](?<value>[a-z0-9]*)$");
    // HMAC or H
    private Integrity integrity = NONE;
    private static final Pattern integrity_regex = Pattern.compile("(?i)^\\s*integrity.*[:=\\s](?<value>.*)$");
    // definition of secure ash Function or NULL
    private String h = "";
    private static final Pattern h_regex = Pattern.compile("(?i)^[^a-z]*(h|hash)[^a-z]*[:=\\s](?<value>.*)$");
    // definition of MAC (HMAC or CMAC algorithms)
    private String mac = "";
    private static final Pattern mac_regex = Pattern.compile("(?i)^[^a-z]*mac[^a-z]*[:=\\s](?<value>.*)$");
    // mackey value in hexadecimal with required keysize or NULL
    private String mackey = "";
    private static final Pattern mackey_regex = Pattern.compile("(?i)^\\s*mac[_\\-\\s]*key[^a-z]*[:=\\s](?<value>[a-z0-9]*)$");
    // integer representing the size of the MACKEY in BITS
    private int mackey_size = 0;
    private static final Pattern mackey_size_regex = Pattern.compile("(?i)^\\s*mac[_\\-\\s]*key[_\\-\\s]*size[:=\\s](?<value>[0-9\\s]*)$");

    /**
     * empty constructor for Testing
     */
    public DSTPConfig(){

    }

    private void readConfig(Reader reader) {
        try (BufferedReader bufferedReader = new BufferedReader(reader)) {
            String line;
            while ((line = bufferedReader.readLine()) != null) {
                line = line.trim();
                // Skip empty lines and comments
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                if (line.matches(confidentiality_regex.pattern())) {
                    Matcher m = confidentiality_regex.matcher(line);
                    m.matches();
                    setConfidentiality(m.group("value").trim());
                } else if (symmetric_key_regex.matcher(line).matches()) {
                    Matcher m = symmetric_key_regex.matcher(line);
                    m.matches();
                    setSymmetric_key(m.group("value").trim());
                } else if (symmetric_key_size_regex.matcher(line).matches()) {
                    Matcher m = symmetric_key_size_regex.matcher(line);
                    m.matches();
                    setSymmetric_key_size(m.group("value").trim());
                } else if (iv_size_regex.matcher(line).matches()) {
                    Matcher m = iv_size_regex.matcher(line);
                    m.matches();
                    setIv_size(m.group("value").trim());
                } else if (iv_regex.matcher(line).matches()) {
                    Matcher m = iv_regex.matcher(line);
                    m.matches();
                    setIv(m.group("value").trim());
                } else if (integrity_regex.matcher(line).matches()) {
                    Matcher m = integrity_regex.matcher(line);
                    m.matches();
                    setIntegrity(m.group("value").trim());
                } else if (h_regex.matcher(line).matches()) {
                    Matcher m = h_regex.matcher(line);
                    m.matches();
                    setH(m.group("value").trim());
                } else if (mac_regex.matcher(line).matches()) {
                    Matcher m = mac_regex.matcher(line);
                    m.matches();
                    setMac(m.group("value").trim());
                } else if (mackey_regex.matcher(line).matches()) {
                    Matcher m = mackey_regex.matcher(line);
                    m.matches();
                    setMackey(m.group("value").trim());
                } else if (mackey_size_regex.matcher(line).matches()) {
                    Matcher m = mackey_size_regex.matcher(line);
                    m.matches();
                    setMackey_size(m.group("value").trim());
                } else {
                    System.out.printf("Could not read parse value from config line '%s'%n", line);
                }
            }
        } catch (IOException e) {
            throw new RuntimeException("Error reading DSTP config", e);
        }
    }

    public DSTPConfig(String configPath) {
        try (FileReader reader = new FileReader(configPath)) {
            readConfig(reader);
        } catch (IOException e) {
            System.out.printf("Could not read config file '%s'%n", configPath);
        }
    }

    public DSTPConfig(Reader reader) {
        readConfig(reader);
    }

    public String serialize(){
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("CONFIDENTIALITY: ").append(confidentiality).append("\n");
        stringBuilder.append("SYMMETRIC_KEY: ").append(symmetric_key).append("\n");
        stringBuilder.append("SYMMETRIC_KEY_SIZE: ").append(symmetric_key_size).append("\n");
        stringBuilder.append("IV: ").append(iv).append("\n");
        stringBuilder.append("IV_SIZE: ").append(iv_size).append("\n");
        stringBuilder.append("INTEGRITY: ").append(integrity).append("\n");
        stringBuilder.append("H: ").append(h).append("\n");
        stringBuilder.append("MAC: ").append(mac).append("\n");
        stringBuilder.append("MAC_KEY: ").append(mackey).append("\n");
        stringBuilder.append("MAC_KEY_SIZE: ").append(mackey_size).append("\n");

        return stringBuilder.toString();
    }

    public String getConfidentiality() {
        return confidentiality;
    }

    public void setConfidentiality(String confidentiality) {
        if (confidentiality != null && !confidentiality.isBlank() && !confidentiality.equalsIgnoreCase("null")) {
            this.confidentiality = confidentiality;
        }
    }

    public String getSymmetric_key() {
        return symmetric_key;
    }

    public void setSymmetric_key(String symmetric_key) {
        if (symmetric_key != null && !symmetric_key.isBlank() && !symmetric_key.equalsIgnoreCase("null")) {
            this.symmetric_key = symmetric_key;
        }
    }

    public int getSymmetric_key_size() {
        return symmetric_key_size;
    }

    public void setSymmetric_key_size(String symmetric_key_size) {
        if (symmetric_key_size != null && !symmetric_key_size.isBlank() && !symmetric_key_size.equalsIgnoreCase("null")) {
            this.symmetric_key_size = Integer.parseInt(symmetric_key_size);
        }
    }

    public int getIv_size() {
        return iv_size;
    }

    public void setIv_size(String iv_size) {
        if (iv_size != null && !iv_size.isBlank() && !iv_size.equalsIgnoreCase("null")) {
            this.iv_size = Integer.parseInt(iv_size);
        }
    }

    public String getIv() {
        return iv;
    }

    public void setIv(String iv) {
        if (iv != null && !iv.isBlank() && !iv.equalsIgnoreCase("null")) {
            this.iv = iv;
        }
    }

    public Integrity getIntegrity() {
        return integrity;
    }

    public void setIntegrity(String integrity) {
        if (integrity == null || integrity.isBlank()) {
            this.integrity = NONE;
        } else {
            this.integrity = parseIntegrity(integrity);
        }
    }

    public String getH() {
        return h;
    }

    public void setH(String h) {
        if (h != null && !h.isBlank() && !h.equalsIgnoreCase("null")) {
            this.h = h;
        }
    }

    public String getMac() {
        return mac;
    }

    public void setMac(String mac) {
        if (mac != null && !mac.isBlank() && !mac.equalsIgnoreCase("null")) {
            this.mac = mac;
        }
    }

    public String getMackey() {
        return mackey;
    }

    public void setMackey(String mackey) {
        if (mackey != null && !mackey.isBlank() && !mackey.equalsIgnoreCase("null")) {
            this.mackey = mackey;
        }
    }

    public int getMackey_size() {
        return mackey_size;
    }

    public void setMackey_size(String mackey_size) {
        if (mackey_size != null && !mackey_size.isBlank() && !mackey_size.equalsIgnoreCase("null")) {
            this.mackey_size = Integer.parseInt(mackey_size);
        }
    }
}
