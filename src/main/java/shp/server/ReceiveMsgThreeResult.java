package shp.server;

import java.security.Key;
import java.security.PublicKey;

public record ReceiveMsgThreeResult(String request, int udpPort, byte[] nonce4, PublicKey clientPubkey, Key pbeKey, byte[] ydhC) { }