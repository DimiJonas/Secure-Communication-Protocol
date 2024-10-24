import java.net.*;

public class Sender {
    InetSocketAddress addr; //address to send data to + port
    DatagramSocket socket; //socket in use

    public Sender(InetSocketAddress addr) throws Exception {
        this.addr = addr;
        socket = new DatagramSocket();
    }

    public void send(DatagramPacket packet) throws Exception {
        byte[] encryptedPacket = encrypt(packet.getData());
        if (encryptedPacket != null) {
            DatagramPacket p = new DatagramPacket(encryptedPacket, encryptedPacket.length, addr);
            socket.send(p);
        }
    }

    private byte[] encrypt(byte[] packet) throws Exception {
        //SecretKey key =

        //Cipher cipher = Cipher.getInstance("Cipher here");
        //cipher.init(Cipher.ENCRYPT_MODE, key);

        //byte[] encryptedPacket = cipher.doFinal(packet);
        return packet; //encrypted packet
    }

}