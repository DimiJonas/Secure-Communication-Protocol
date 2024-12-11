package shp;

public enum MessageType {
    // c -> s
    // contains userID; max length 320 bytes
    ONE((byte) 1),

    // s -> c
    // contains 3 nonces, 16 bytes (128 bits) each -> 48 bytes in total
    TWO((byte) 2),

    // c -> s
    // contains:
    //      {request, userID, Nonce3+1, Nonce4 , udp_port}~PBE(H(password), Salt, Counter) +
    //      DigitalSig(movie, userID, Nonce3+1, Nonce4 , udp_port) +
    //      HMACkmac(movie, userID, Nonce3+1, Nonce4 , udp_port)
    // size varies
    // request according to application: movie or files to transfer
    // choose secure PBE scheme (or can we make this configurable?)
    // sign: ECDSA signature with client key
    // choose secure HMAC and use key derived from password
    THREE((byte) 3),

    // s -> c
    // contains:
    //      {request-confirmation, Nonce4+1, Nonce 5, crypto config}~Ekpubclient +
    //      DigitalSig(request-confirmation, userID, Nonce3+1, Nonce4 , crypto config) +
    //      HMACkmac(movie, Nonce4+1, crypto config)
    // size varies
    // Ekpubclient: A Secure envelope using the public key Kpub, using ECC-ECIES
    // Request-confirmation: confirmation of client request (message type 3)
    // sign: ECDSA Signature with ECC key (clientkey??)
    // choose secure HMAC and with the key as used in MsgType3
    // crypto config: datatype to send the Crypto configurations (ciphersuite.conf)
    FOUR((byte) 4),

    // c -> s
    // contains:
    //      {”GO”, Nonce5 + 1}~Eks +
    //      MACKmac (Eks (”GO”, Nonce5 + 1))
    // just for synchronization
    // the Keys for E() and MAC() are those received in crypto config
    //
    FIVE((byte) 5);

    private final byte value;

    MessageType(byte value) {
        this.value = value;
    }

    public byte getValue() {
        return value;
    }

    public static MessageType getTypeFromString(String number){
        return switch (number) {
            case "1" -> ONE;
            case "2" -> TWO;
            case "3" -> THREE;
            case "4" -> FOUR;
            case "5" -> FIVE;
            default -> null;
        };
    }
}
