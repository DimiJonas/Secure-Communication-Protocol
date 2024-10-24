import java.net.*;

public class Receiver {
    DatagramSocket socket; // the socket used for receiving
    String receiveMode;

    public Receiver(SocketAddress socket, String mode) throws Exception {
        this.socket = new DatagramSocket(socket);
        this.receiveMode = mode;
    }

    public DatagramPacket receive() throws Exception {
        byte[] buffer = new byte[4 * 1024];
        DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
        socket.receive(packet);
        byte[] decryptedPacket = decrypt(packet.getData());
        if (decryptedPacket != null) {
            DatagramPacket p = new DatagramPacket(decryptedPacket, decryptedPacket.length, new InetSocketAddress("localhost", packet.getPort()));
            return p;
        }
        return null;
    }

    private byte[] decrypt(byte[] packet) throws Exception {
        //SecretKey key =

        //Cipher cipher = Cipher.getInstance("Cipher here");
        //cipher.init(Cipher.DECRYPT_MODE, key);

        //byte[] decryptedPacket = cipher.doFinal(packet);
        return packet; //decrypted packet
    }
}