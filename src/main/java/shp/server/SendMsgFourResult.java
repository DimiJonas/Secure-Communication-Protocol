package shp.server;

import dstp.config.DSTPConfig;

public record SendMsgFourResult(DSTPConfig cryptoConfig, byte[] nonce5) {
}
