package applications.StreamingService.hjStreamServer;/*
* hjStreamServer.java 
* Streaming server: emitter of video streams (movies)
* Can send in unicast or multicast IP for client listeners
* that can play in real time the transmitted movies
*/

import dstp.socket.DSTPSocket;
import shp.SHPResult;
import shp.server.SHPServer;

import java.io.*;
import java.net.*;

class hjStreamServer {

	static public void main( String []args ) throws Exception {
	        if (args.length != 0)
	        {
	         System.out.println("Ex with shp: hjStreamServer");

	         System.exit(-1);
	         }

		// use SHP handshake with DSTP
		SHPResult shpResult = new SHPServer(45678).executeHandshake();

		DatagramSocket s = new DSTPSocket(shpResult.config());
		String movie = shpResult.request();
		InetSocketAddress addr = new InetSocketAddress(shpResult.host(), shpResult.udpPort());
		int size;
		int count = 0;
 		long time;
		DataInputStream g = new DataInputStream( new FileInputStream(movie) );
		byte[] buff = new byte[65000];

		DatagramPacket p=new DatagramPacket(buff,buff.length,addr);
		long t0 = System.nanoTime(); // tempo de referencia
		long q0 = 0;

		while ( g.available() > 0 ) {
			size = g.readShort();
			time = g.readLong();
			if ( count == 0 ) q0 = time; // tempo de referencia no stream
			count += 1;
			g.readFully(buff, 0, size );
			p.setData(buff, 0, size );
			p.setSocketAddress( addr );
			long t = System.nanoTime();
			Thread.sleep( Math.max(0, ((time-q0)-(t-t0))/1000000) );
			s.send( p );
			//System.out.print( "." );
		}

		System.out.println("\nEND ! packets with frames sent: "+count);
	}

}
