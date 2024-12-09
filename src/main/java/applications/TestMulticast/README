// SRSC 1718

Correr simplesmente ...

iptables rule for multicast
--------------------------------
allow multicast:
        sudo iptables -A INPUT -m addrtype --dst-type MULTICAST -j ACCEPT
delete multicast rule:
        sudo iptables -D INPUT -m addrtype --dst-type MULTICAST -j ACCEPT

UDP/IPmulticast Multicast Sender:
--------------------------------
java -Djava.net.preferIPv4Stack=true MulticastSender <multicast-address> <port> <time-interval-seconds>
java -Djava.net.preferIPv4Stack=true -cp target/classes applications.TestMulticast.MulticastSender 224.2.2.3 9000 2

UDP/IPmulticast Multicast Receiver:
-----------------------------------
java -Djava.net.preferIPv4Stack=true MulticastReceiver <multicast-address> <port>
java -Djava.net.preferIPv4Stack=true -cp target/classes applications.TestMulticast.MulticastReceiver 224.2.2.3 9000