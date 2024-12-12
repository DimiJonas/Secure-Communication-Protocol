package shp.client;

import dstp.config.DSTPConfig;

public record ReceiveMsgFourResult(DSTPConfig cryptoConfig, byte[] nonce5) {
}
