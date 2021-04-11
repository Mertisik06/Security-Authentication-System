import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.LinkedBlockingQueue;

public class Alice {

    private ServerConnection server; //connection to server
    private Socket socket;
    private LinkedBlockingQueue<Message> messages; //messages received
    //private int id;

    private static String password;
    private static byte[] x;

    private static boolean getpasscheck;

    private static SecretKeySpec secretKey;
    private static byte[] key;


    public static class Connection{

        public Connection(int i) {
        }
    }

    public void Connection(int port) throws IOException, ClassNotFoundException {

        InetAddress localHost = InetAddress.getLocalHost(); //local host
        socket = new Socket(localHost.getHostAddress(), port);
        messages = new LinkedBlockingQueue<Message>();
        server = new ServerConnection(socket);

        Thread messageProcess = new Thread() {//getting messages from server
            public void run() {
                while (true) {
                    try {
                        Message message = messages.take();
                        if (message.isConnected()==true) {
                            System.out.println("Connected to the server");


                        }
                    } catch (InterruptedException e) {
                    }
                }
            }
        };
        messageProcess.setDaemon(true);
        messageProcess.start();
    }

    //Port değişecek server'a göre 3000, 3001, 3002, 3003
    public Alice(int port) throws IOException, ClassNotFoundException {

        InetAddress localHost = InetAddress.getLocalHost(); //local host
        socket = new Socket(localHost.getHostAddress(), port);
        messages = new LinkedBlockingQueue<Message>();
        server = new ServerConnection(socket);

        Thread messageProcess = new Thread() {//getting messages from server
            public void run() {
                while (true) {
                    try {
                        Message message = messages.take();
                        if (message.isConnected()==true) {
                            System.out.println("Connected to the server");


                        }
                    } catch (InterruptedException e) {
                    }
                }
            }
        };
        messageProcess.setDaemon(true);
        messageProcess.start();
    }

    private class ServerConnection { // connection to server
        ObjectInputStream input;
        ObjectOutputStream output;
        Socket socket;

        ServerConnection(Socket socket) throws IOException, ClassNotFoundException {
            this.socket = socket;
            output = new ObjectOutputStream(socket.getOutputStream());//assigning inputs and outputs
            input = new ObjectInputStream(socket.getInputStream());


            output.writeObject(x);

            getpasscheck = (boolean) input.readObject();

            Thread read = new Thread() {
                public void run() {
                    boolean connection = true;
                    while (connection) {
                        try {
                            Message message = (Message) input.readObject();//sending messages to server
                            if (!message.isConnected()) {
                                input.close();
                                output.close();
                                socket.close();
                                disconnect();
                                connection = false;
                            }else{
                                messages.put(message);
                            }
                        } catch (IOException | ClassNotFoundException | InterruptedException e) {

                        }
                    }
                }
            };
            read.setDaemon(true);
            read.start();
        }

        private void write(Message message) {//writing to server
            try {
                output.writeObject(message);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    /*public void messageForward(Message message) {
        message.setId(id);
        server.write(message);
    }*/

    private void disconnect() {//disconnecting from server
        try {
            socket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }




    public static void First(String password , String server)throws Exception{
        //password burda okuncak
        //düz alice yazılcak başa
        Date date = new Date();
        SimpleDateFormat formatter = new SimpleDateFormat("MM/dd/yyyy");
        formatter = new SimpleDateFormat("dd-M-yyyy H:mm:ss");
        String strDate = formatter.format(date);
        String full = "Alice "+password+" "+server+" "+ strDate;
        Scanner scanner=new Scanner(new File("keys/KDCpublic.key"));
        Scanner scanner2=new Scanner(new File("keys/KDCprivate.key"));
        String line="";
        String line2="";
        while(scanner.hasNextLine()) {
            line =line+ scanner.nextLine().toString();
        }
        while(scanner2.hasNextLine()) {
            line2 =line2+ scanner2.nextLine().toString();
        }
        scanner.close();
        scanner2.close();
        PublicKey pubkey = getPublicKey(line);
        PrivateKey privKey = getPrivateKey(line2);
        byte[] message = full.getBytes();
        x = encrypt(pubkey,full);

        String out= strDate+" Alice->KDC" + " : Alice , "+ Base64.getEncoder().encodeToString(x);
        writeFile("KDC_Log.txt", out);

        full = "Alice , "+password+", "+server+", "+strDate;
        out = strDate+" Alice->KDC : " + full;
        writeFile("Alice_Log.txt", out);

        out= strDate+" Alice->KDC" + " : Alice , " + Base64.getEncoder().encodeToString(x);
        writeFile("Alice_Log.txt", out);
        //checkPassword(privKey,x);


    }

    //son hali
    public static void Second(String Server)throws Exception{
        byte[] aa=generateSessionKey();
        String s = Base64.getEncoder().encodeToString(aa);
        String ticketway= "keys/"+Server+"public.key";
        Scanner scanner=new Scanner(new File(ticketway));
        Scanner scanner2=new Scanner(new File("keys/Alicepublic.key"));
        String line="";
        String line2="";
        while(scanner.hasNextLine()) {
            line =line+ scanner.nextLine().toString();
        }
        while(scanner2.hasNextLine()) {
            line2 =line2+ scanner2.nextLine().toString();
        }
        scanner.close();
        scanner2.close();
        PublicKey pubkeyalice = getPublicKey(line2);
        PublicKey pubkeyserver = getPublicKey(line);

        Scanner scanner3=new Scanner(new File("keys/Aliceprivate.key"));
        String line3="";
        while(scanner3.hasNextLine()) {
            line3 =line3+ scanner3.nextLine().toString();
        }
        scanner3.close();
        PrivateKey privKey = getPrivateKey(line3);

        Date date = new Date();
        SimpleDateFormat formatter = new SimpleDateFormat("MM/dd/yyyy");
        formatter = new SimpleDateFormat("dd-M-yyyy H:mm:ss");
        String strDate = formatter.format(date);


        String full = "Alice "+Server+" "+strDate+" "+ s;

        String out = strDate + " KDC->Alice : " + s + ", " + Server + ", " + strDate;
        writeFile("KDC_Log.txt", out);

        byte[] Ticket = encrypt(pubkeyserver,full);
        String s3 = Base64.getEncoder().encodeToString(Ticket);

        String fullforalice = s+Server+strDate;
        byte[] Part1 = encrypt(pubkeyalice,fullforalice);
        String s4 = Base64.getEncoder().encodeToString(Part1);


        byte[] outputfinal=decrypt(privKey,Part1);
        String s5 = new String(outputfinal, StandardCharsets.UTF_8);

        out = strDate + " KDC->Alice : " + s4 + ", " + s3;
        writeFile("KDC_Log.txt", out);
        writeFile("Alice_Log.txt", out);


        out= strDate+" Message Decrypted : " + s + ", " + Server + ", " + strDate;
        writeFile("Alice_Log.txt", out);


        Three(Ticket,Server,strDate);
    }


    public static void Three(byte[] Ticket,String Server,String time)throws Exception{
        String filename=Server+"_Log.txt";
        Date date = new Date();
        SimpleDateFormat formatter = new SimpleDateFormat("MM/dd/yyyy");
        formatter = new SimpleDateFormat("dd-M-yyyy H:mm:ss");
        String strDate = formatter.format(date);

        String s3 = Base64.getEncoder().encodeToString(Ticket);

        String ticketway= "keys/"+Server+"private.key";
        Scanner scanner3=new Scanner(new File(ticketway));
        String line3="";
        while(scanner3.hasNextLine()) {
            line3 =line3+ scanner3.nextLine().toString();
        }
        scanner3.close();
        PrivateKey privKey = getPrivateKey(line3);

        String sticket = Base64.getEncoder().encodeToString(Ticket);

        Random rand = new Random();
        long x = (long)(rand.nextDouble()*100000000000000L);
        String nonce1 = String.valueOf("53") + String.format("%014d", x); // burda 16 uzunlukta nonce oluşturuyoruz .

        String out= time+" Alice->"+Server+" : Alice , "+nonce1;
        writeFile("Alice_Log.txt",out);

        byte[] outputfinal=decrypt(privKey,Ticket);
        String s5 = new String(outputfinal, StandardCharsets.UTF_8);


        int index = s5.lastIndexOf(' ');
        String lastString = s5.substring(index +1);


        String output1 = encryption(nonce1,lastString);

        out=time+" Alice->"+Server+" : Alice , "+sticket+" , "+output1;
        writeFile("Alice_Log.txt",out);
        writeFile(filename,out);
        out=time+" Ticket Decyrpted : Alice , "+Server+" , "+strDate+" , "+lastString;
        writeFile(filename,out);
        out=time+" Message Decyrpted : N1="+nonce1;
        writeFile(filename,out);

        String output2=decryption(output1,lastString);


        //Nonce+1
        String nonceplusone = String.valueOf("53") + String.format("%014d", x+1); // burda 16 uzunlukta nonce oluşturuyoruz .

        // Creating second nonce .
        Random rand1 = new Random();
        long x2 = (long)(rand1.nextDouble()*100000000000000L);
        String nonce2 = String.valueOf("53") + String.format("%014d", x2); // burda 16 uzunlukta nonce oluşturuyoruz .


        out=time+" "+Server+"->Alice : " +nonceplusone+" , "+nonce2;
        writeFile(filename,out);

        // 4. fonksiyon .
        String full = nonceplusone+" "+nonce2;
        String output3 = encryption(full,lastString);

        out=time+" "+Server+"->Alice : "+output3;
        writeFile("Alice_Log.txt",out);

        out=time+" "+Server+"->Alice : " +output3;
        writeFile(filename,out);


        String output4=decryption(output3,lastString);


        String[] bits = output4.split(" ");
        String checknonce = bits[bits.length - 2];


        out=time+" Message Decyrpted : "+nonce1+" is OK , N2="+nonce2;
        writeFile("Alice_Log.txt",out);

        // son fonksiyon
        if(nonceplusone.equals(checknonce)){
            String nonce2plusone = String.valueOf("53") + String.format("%014d", x2+1); // burda 16 uzunlukta nonce oluşturuyoruz .


            out=strDate+" Alice->"+Server+" : "+nonce2plusone;
            writeFile("Alice_Log.txt",out);

            String output5 = encryption(nonce2plusone,lastString);

            out=strDate+" Alice->"+Server+" :"+output5;
            writeFile(filename,out);

            out=strDate+" Alice->"+Server+" :"+output5;
            writeFile("Alice_Log.txt",out);

            String output6=decryption(output5,lastString);

            out=strDate+" Message Decrpyted : "+nonce2plusone;
            writeFile(filename,out);

            out=strDate+" "+Server+"->Alice"+" :"+"Authentication is completed!";
            writeFile("Alice_Log.txt",out);
            writeFile(filename,out);
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

    public static void writeFile(String fileName, String data) throws IOException {// writes into file
        FileWriter file = new FileWriter(fileName,true);
        BufferedWriter output = new BufferedWriter(file);
        output.write(data);
        output.newLine();
        output.close();
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







    public static void main(String[] args) throws Exception {

        int i= 1;

        do{
            Scanner sc = new Scanner(System.in);
            System.out.println("Enter Server Name:");
            String serverName = sc.nextLine();

            System.out.println("Enter Password:");
            password = sc.nextLine();

            First(password, serverName);

            Alice alice = new Alice(3000);


            if(getpasscheck){
                i++;
                Second(serverName);
                System.out.println("Password is true");
                if (serverName.equals("Mail")){
                    //MailServer server = new MailServer(3001);
                    Connection alice_mail = new Connection(3001);
                    System.out.println("Work done");


                }
                else if (serverName.equals("Web")){
                    Connection alice_web = new Connection(3002);
                    System.out.println("Work done");

                }
                else if (serverName.equals("Database")){
                    Connection alice_database = new Connection(3003);
                    System.out.println("Work done");
                }
            }
            else{
                System.out.println("Password is false! Please start begin");
            }


        }
        while(50>=i);
    }
}
