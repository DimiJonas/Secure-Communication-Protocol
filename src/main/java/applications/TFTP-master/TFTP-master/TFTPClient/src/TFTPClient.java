

import java.net.InetAddress;
import java.net.UnknownHostException;
class UseException extends Exception {
	public UseException() {
		super();
	}

	public UseException(String s) {
		super(s);
	}
}

public class TFTPClient {
	public static void main(String argv[]) throws TftpException, UseException {
		String host = "";
		String fileName = "";
		String mode="octet"; //default mode
		String type="";
		String username ="";
		String password = "";
		int port = 45678;
		try {
			// Process command line
			if (argv.length == 0)
				throw new UseException("--Usage-- \nocter mode:  TFTPClient [host] [Type(R/W?)] [filename] \nother mode:  TFTPClient [host] [Type(R/W?)] [filename] [mode]" );
			//use default mode(octet)
			if(argv.length == 6){
				username = argv[0];
				password = argv[1];
				host = argv[2];
				port = Integer.parseInt(argv[3]);
				type = argv[4];
			    fileName = argv[5];}
			//use other modes
			else if(argv.length == 7){
				username = argv[0];
				password = argv[1];
				host = argv[2];
				port = Integer.parseInt(argv[3]);
				type = argv[4];
				fileName = argv[5];
				mode =argv[6];
			}
			else throw new UseException("wrong command. \n--Usage-- \nocter mode:  TFTPClient [host] [Type(R/W?)] [filename] \nother mode:  TFTPClient [host] [Type(R/W?)] [filename] [mode]");
			
			
			InetAddress server = InetAddress.getByName(host);
			
			//process read request
			if(type.matches("R")){
				TFTPclientRRQ r = new TFTPclientRRQ(server, fileName, mode, username, password, port);}
			//process write request
			else if(type.matches("W")){
				TFTPclientWRQ w = new TFTPclientWRQ(server, fileName, mode, username, password, port);
			}
			else{throw new UseException("wrong command. \n--Usage-- \nocter mode:  TFTPClient [host] [Type(R/W?)] [filename] \nother mode:  TFTPClient [host] [Type(R/W?)] [filename] [mode]");}
			
		} catch (UnknownHostException e) {
			System.out.println("Unknown host " + host);
		} catch (UseException e) {
			System.out.println(e.getMessage());
		}
	}
}