import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.concurrent.LinkedBlockingQueue;

public class MailServer {

    static private int port = 3001; //Mail Server port
    private ServerSocket ss;

    private LinkedBlockingQueue<Message> messages; // message array
    private ArrayList<ClientConnection> clientArray; // client array

    class ClientConnection { // connections to client
        ObjectInputStream input;
        ObjectOutputStream output;
        Socket socket;

        ClientConnection(Socket socket) throws IOException, ClassNotFoundException {
            this.socket = socket;
            input = new ObjectInputStream(socket.getInputStream());
            output = new ObjectOutputStream(socket.getOutputStream());


            Thread read = new Thread() {
                public void run() {
                    boolean connected = true;
                    while (connected) {
                        System.out.println("Work done");
                        connected=false;
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

    public MailServer(int port) { // server constructors
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
                    } catch (IOException | ClassNotFoundException e) {
                        e.printStackTrace();
                    }
                }
            }
        };
        join.setDaemon(true);
        join.start();
    }

    public static void writeFile(String fileName, String data) throws IOException {// writes into file
        FileWriter file = new FileWriter(fileName,true );
        BufferedWriter output = new BufferedWriter(file);
        output.write(data);
        output.close();
        System.out.println(data);
    }

    public void sendAllClients(Message message) {// sending all messages to clients
        for (ClientConnection client : clientArray)
            client.print(message);
    }

    public static void main(String[] args) {

        MailServer server = new MailServer(port);

        while (true) {
            int i = 0;
        }

    }
}
