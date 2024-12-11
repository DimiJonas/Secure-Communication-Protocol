package applications.StreamingService.hjUDPproxy;/* hjUDPproxy, for use in 2024
 */

import dstp.socket.DSTPSocket;
import shp.SHPResult;
import shp.client.SHPClient;

import java.io.FileInputStream;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.MulticastSocket;
import java.net.InetSocketAddress;
import java.net.InetAddress;
import java.net.SocketAddress;
import java.util.Arrays;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;

class hjUDPproxy {
    public static void main(String[] args) throws Exception {
        if (args.length != 6) {
            System.out.println("Ex with shp: hjUDPproxy testuser test 127.0.0.1:45678 monsters.dat 10000 127.0.0.1:8888");
            System.out.println("Ex with shp: hjUDPproxy <username> <password> <tcp_port> <movie> <udp_port> <player_port>");
            System.exit(0);
        }

        // use SHP handshake with DSTP
        InetSocketAddress shpServerAddress = parseSocketAddress(args[2]);
        SHPResult shpResult = new SHPClient(shpServerAddress.getHostString(), shpServerAddress.getPort(), args[0], args[1], args[3], Integer.parseInt(args[4])).executeHandshake();

        SocketAddress inSocketAddress = parseSocketAddress(shpResult.host() + ":" + shpResult.udpPort());
        Set<SocketAddress> outSocketAddressSet = Arrays.stream(args[5].split(",")).map(s -> parseSocketAddress(s)).collect(Collectors.toSet());

        // Manage this according to your required setup, namely
        // if you want to use unicast or multicast channels

        // If listen a remote unicast server try the remote config
        // uncomment the following line
        DatagramSocket inSocket;
        inSocket = new DSTPSocket(inSocketAddress, shpResult.config());
//        DatagramSocket inSocket = new DatagramSocket(inSocketAddress);

        // If listen a remote multicast server using IP Multicasting
        // addressing (remember IP Multicast Range) and port 
        // uncomment the following two lines

        //	MulticastSocket ms = new MulticastSocket(9999);
        //        ms.joinGroup(InetAddress.getByName("239.9.9.9"));

        int countframes = 0;
        DatagramSocket outSocket = new DatagramSocket();
        byte[] buffer = new byte[4 * 1024];
        while (true) {

            DatagramPacket inPacket = new DatagramPacket(buffer, buffer.length);
            // If listen a remote unicast server
            // uncomment the following line

            inSocket.receive(inPacket);  // if remote is unicast
            // use a seperate buffer for sending
            byte[] outData = Arrays.copyOfRange(inPacket.getData(), inPacket.getOffset(), inPacket.getOffset() + inPacket.getLength());

            // If listen a remote multcast server
            // uncomment the following line

            //ms.receive(inPacket);          // if remote is multicast

            // Just for debug...
            //countframes++;
            //System.out.println(":"+countframes);           // debug	    
            //System.out.print(":");           // debug
            for (SocketAddress outSocketAddress : outSocketAddressSet) {
                outSocket.send(new DatagramPacket(outData, outData.length, outSocketAddress));
            }
        }
    }

    private static InetSocketAddress parseSocketAddress(String socketAddress) {
        String[] split = socketAddress.split(":");
        String host = split[0];
        int port = Integer.parseInt(split[1]);
        return new InetSocketAddress(host, port);
    }
}
