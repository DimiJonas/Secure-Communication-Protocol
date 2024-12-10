package shp;

import dstp.config.DSTPConfig;

public record SHPResult(DSTPConfig config, String host, int udpPort, String request, String username) {}
