import sun.misc.BASE64Encoder;
import sun.security.provider.X509Factory;
import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;

import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.cert.X509Certificate;
import java.math.BigInteger;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Scanner;
import java.security.*;
import java.util.*;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.*;
import javax.crypto.Cipher;
import java.util.Base64;
import java.text.SimpleDateFormat;
import javax.crypto.spec.SecretKeySpec;
import java.util.Date;
import java.util.Calendar;
import java.util.Random;
import java.util.concurrent.LinkedBlockingQueue;

public class KDC {

	static private int port = 3000; //KDC Server port

	private ServerSocket ss;

	private LinkedBlockingQueue<Message> messages; // message array
	private ArrayList<ClientConnection> clientArray; // client array

	private static SecretKeySpec secretKey;
	private static byte[] key;


	private static String randomPassword;
	static byte [] message;


	public static void main(String[] args) throws Exception {

		File f = new File("KDC_Log.txt");
		if(!(f.exists() && !f.isDirectory())) {
			new File("keys").mkdirs();
			new File("cert").mkdirs();
			CreateAll("Alice");
			CreateAll("Web");
			CreateAll("Mail");
			CreateAll("Database");
			CreateAll("KDC");

			//alttaki KDC also prints the plaintext password to its log file.
			//Creates random password
			randomPassword = createRandomPassword();

			//Hash the random password with SHA-1
			String sha1_hashed_password = hashPassword(randomPassword);

			//alttaki "passwd" dosyasına yazılacak
			//KDC saves SHA1 hash of the password (in base64 format) in a file named “passwd”.
			String base64_sha1_hashed_password = Base64.getEncoder().encodeToString(sha1_hashed_password.getBytes());
			PrintStream passwordFile = new PrintStream("passwd");
			passwordFile.println(base64_sha1_hashed_password);

			//Create Timestamp value
			Date date = new Date();
			SimpleDateFormat formatter = new SimpleDateFormat("MM/dd/yyyy");
			formatter = new SimpleDateFormat("dd-M-yyyy H:mm:ss");
			String strDate = formatter.format(date);

			writeFile("KDC_Log.txt", strDate + " " + randomPassword);




		}

		KDC server = new KDC(port);

		while (true) {
			int i = 0;
		}
	}

	private class ClientConnection { // connections to client
		ObjectInputStream input;
		ObjectOutputStream output;
		Socket socket;

		ClientConnection(Socket socket) throws Exception {
			this.socket = socket;
			input = new ObjectInputStream(socket.getInputStream());
			output = new ObjectOutputStream(socket.getOutputStream());

			message = (byte[]) input.readObject();

			boolean passchecker = checkPassword(message);
			output.writeObject(passchecker);

			Thread read = new Thread() {
				public void run() {
					boolean connected = true;
					while (connected) {
						try { // sending messages to all clients to print, and writing into log file
							Message message = (Message) input.readObject();

							if (message.isConnected()) {
								message.setUserAmount(clientArray.size());
								messages.put(message);
								sendAllClients(message);
							} else {
								deleteClient(message);
								connected = false;
							}
						} catch (InterruptedException | IOException | ClassNotFoundException exception) {
						}
					}
				}
			};
			read.setDaemon(true);
			read.start();
		}

		public void print(Message message) {// printing into clients
			try {
				output.writeObject(message);
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

		private void deleteClient(Message message) {// disconnect
			try {
				input.close();
				output.close();
				socket.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
			clientArray.remove(message.getId());
		}
	}

	public KDC(int port) { // server constructors
		clientArray = new ArrayList<ClientConnection>();
		messages = new LinkedBlockingQueue<Message>();
		try {
			ss = new ServerSocket(port); // creating server with port
		} catch (IOException e) {
			System.out.println("Server error");
		}

		Thread join = new Thread() {
			public void run() {
				while (true) {
					try { // waiting for messages from clients
						Socket s = ss.accept();
						clientArray.add(new ClientConnection(s));
					} catch (Exception e) {
						e.printStackTrace();
					}
				}
			}
		};
		join.setDaemon(true);
		join.start();
	}

	public void sendAllClients(Message message) {// sending all messages to clients
		for (ClientConnection client : clientArray)
			client.print(message);
	}

	public static void CreateAll(String name)throws Exception{
		CertAndKeyGen certAndKeyGen = new CertAndKeyGen("RSA", "MD5WithRSA", null);
		certAndKeyGen.generate(2048);
		Date cert_date = new GregorianCalendar(2020, Calendar.JANUARY, 1).getTime();
		X509Certificate cert = certAndKeyGen.getSelfCertificate(new X500Name("CN=KDCprivate"), cert_date, (long) 60 * 60 * 24 * 365 * 10);
		PrintStream publicCertFile = new PrintStream("cert/"+name+".crt");
		BASE64Encoder encoder = new BASE64Encoder();
		publicCertFile.println(X509Factory.BEGIN_CERT);
		encoder.encodeBuffer(cert.getEncoded(), publicCertFile);
		publicCertFile.println(X509Factory.END_CERT);
		PrintStream publicKeyFile = new PrintStream("keys/"+name+"public.key");
		PublicKey publicKey = certAndKeyGen.getPublicKey();
		encoder.encodeBuffer(publicKey.getEncoded(), publicKeyFile);
		PrintStream privateKeyFile = new PrintStream("keys/"+name+"private.key");
		PrivateKey privateKey = certAndKeyGen.getPrivateKey();
		encoder.encodeBuffer(privateKey.getEncoded(), privateKeyFile);
	}

	public static void setKey(String myKey)
	{
		MessageDigest sha = null;
		try {
			key = myKey.getBytes("UTF-8");
			sha = MessageDigest.getInstance("SHA-1");
			key = sha.digest(key);
			key = Arrays.copyOf(key, 16);
			secretKey = new SecretKeySpec(key, "AES");
		}
		catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
	}

	public static String encryption(String strToEncrypt, String secret)
	{
		try
		{
			setKey(secret);
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, secretKey);
			return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
		}
		catch (Exception e)
		{
			System.out.println("Error while encrypting: " + e.toString());
		}
		return null;
	}

	public static String decryption(String strToDecrypt, String secret)
	{
		try
		{
			setKey(secret);
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
			cipher.init(Cipher.DECRYPT_MODE, secretKey);
			return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
		}
		catch (Exception e)
		{
			System.out.println("Error while decrypting: " + e.toString());
		}
		return null;
	}

	public static byte[] generateSessionKey() throws Exception
	{
		KeyGenerator kgen = KeyGenerator.getInstance("AES");
		kgen.init(128);
		SecretKey key = kgen.generateKey();
		byte[] symmKey = key.getEncoded();
		return symmKey;
	}
	// Encrypt RSA
	public static byte[] encrypt(Key privateKey, String message) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, privateKey);
		return cipher.doFinal(message.getBytes());
	}

	// Decrypt RSA
	public static byte[] decrypt(Key publicKey, byte [] encrypted) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, publicKey);

		return cipher.doFinal(encrypted);
	}
	public static PrivateKey getPrivateKey(String key) throws Exception {
		byte[] keyBytes = Base64.getDecoder().decode(key);
		PKCS8EncodedKeySpec keySpec = new  PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
		return privateKey;
	}
	public static PublicKey getPublicKey(String key) throws Exception {
		byte[] keyBytes = Base64.getDecoder().decode(key);
		X509EncodedKeySpec keySpec = new  X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PublicKey publickey = keyFactory.generatePublic(keySpec);
		return publickey;
	}
	public static String hashPassword(String password)
	{
		try {
			// getInstance() method is called with algorithm SHA-1
			MessageDigest md = MessageDigest.getInstance("SHA-1");

			// digest() method is called
			// to calculate message digest of the input string
			// returned as array of byte
			byte[] messageDigest = md.digest(password.getBytes());

			// Convert byte array into signum representation
			BigInteger no = new BigInteger(1, messageDigest);

			// Convert message digest into hex value
			String hashtext = no.toString(16);

			// Add preceding 0s to make it 32 bit
			while (hashtext.length() < 32) {
				hashtext = "0" + hashtext;
			}
			// return the HashText
			return hashtext;
		}
		// For specifying wrong message digest algorithms
		catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	public static String createRandomPassword() {
		String alpha_numeric = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
		SecureRandom random = new SecureRandom();
		int length= 20;

		StringBuilder sb = new StringBuilder(length);
		for(int i = 0; i < length; i++)
			sb.append(alpha_numeric.charAt(random.nextInt(alpha_numeric.length())));
		return sb.toString();
	}

	public static void writeFile(String fileName, String data) throws IOException {// writes into file
		FileWriter file = new FileWriter(fileName,true );
		BufferedWriter output = new BufferedWriter(file);
		output.write(data);
		output.newLine();
		output.close();
	}

	public static boolean checkPassword(byte[] message) throws Exception {

		Scanner scanner2=new Scanner(new File("keys/KDCprivate.key"));
		String line2="";
		while(scanner2.hasNextLine()) {
			line2 =line2+ scanner2.nextLine().toString();
		}
		scanner2.close();
		PrivateKey privKey = getPrivateKey(line2);
		byte[] outputfinal = decrypt(privKey, message);
		String s = new String(outputfinal, StandardCharsets.UTF_8);
		String[] bits1 = s.split(" ");
		String checkpass1 = bits1[bits1.length - 4];

		String server = bits1[bits1.length - 3];



		FileInputStream fis=new FileInputStream("KDC_Log.txt");
		Scanner sc=new Scanner(fis);
		//file to be scanned
		//returns true if there is another line to read
		String line = sc.nextLine();

		String[] array = line.split(" ");
		String pass = array[array.length - 1];


		//Creates timestamp
		Date date = new Date();
		SimpleDateFormat formatter = new SimpleDateFormat("MM/dd/yyyy");
		formatter = new SimpleDateFormat("dd-M-yyyy H:mm:ss");
		String strDate = formatter.format(date);

		String out= strDate+" Message Decrypted" + " : Alice , " + pass + ", " + server + ", " + strDate;
		writeFile("KDC_Log.txt", out);



		if(checkpass1.equals(pass)){
			System.out.println("Password Verified");
			writeFile("KDC_Log.txt", strDate + " KDC->Alice :" + " Password Verified");
			writeFile("Alice_Log.txt", strDate + " KDC->Alice :" + " Password Verified");
			return true;

		}
		else{
			System.out.println("Password Denied");
			writeFile("KDC_Log.txt", strDate + " KDC->Alice :" + " Password Denied");
			writeFile("Alice_Log.txt", strDate + " KDC->Alice :" + " Password Denied");
			return false;
		}
	}
}
