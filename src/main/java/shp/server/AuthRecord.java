package shp.server;

public record AuthRecord(String userid, String passwordhash, String salt, String pubkey) {
    public String serialize(){
        return String.format("%s:%s:%s:%s", userid, passwordhash, salt, pubkey);
    }
}
