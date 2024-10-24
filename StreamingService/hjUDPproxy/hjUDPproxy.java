import java.net.DatagramPacket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

class hjUDPproxy {
    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            System.out.println("Use: hjUDPproxy <endpoint1> <endpoint2>");
            System.out.println("<endpoint1>: endpoint for receiving stream");
            System.out.println("<endpoint2>: endpoint of media player");

            System.out.println("Ex: hjUDPproxy 224.2.2.2:9000  127.0.0.1:8888");
            System.out.println("Ex: hjUDPproxy 127.0.0.1:10000 127.0.0.1:8888");
            System.exit(0);
        }

        String remote = args[0]; // receive media stream from this remote endpoint
        String destinations = args[1]; // resend media stream to this destination endpoint

        SocketAddress inSocketAddress = parseSocketAddress(remote);
        Set<SocketAddress> outSocketAddressSet = Arrays.stream(destinations.split(","))
                .map(s -> parseSocketAddress(s))
                .collect(Collectors.toSet());

        // Instantiate the DSTP Receiver to handle the incoming data stream
        Receiver receiver = new Receiver(inSocketAddress, "unicast");

        // Prepare the DSTP Senders for outgoing data to multiple destinations
        Set<Sender> senders = outSocketAddressSet.stream()
                .map(addr -> {
                    try {
                        return new Sender((InetSocketAddress) addr);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                })
                .collect(Collectors.toSet());

        int countframes = 0;
        while (true) {
            // Receive packet using DSTP Receiver (decrypts the packet)
            DatagramPacket inPacket = receiver.receive();
            if (inPacket == null) continue;

            // Debugging, optional
            countframes++;
            System.out.println("Frame received: " + countframes);

            // Send decrypted packet to all destination endpoints using DSTP Sender
            for (Sender sender : senders) {
                sender.send(inPacket);
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
