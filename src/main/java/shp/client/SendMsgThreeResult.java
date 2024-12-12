package shp.client;

import java.security.Key;
import java.security.KeyPair;

public record SendMsgThreeResult(Key pbeKey, byte[] nonce4, KeyPair DHKeyPair) {
}
