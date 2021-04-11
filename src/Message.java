import java.io.Serializable;

public class Message implements Serializable {
    private String name;
    private String text;
    private int userAmount;
    private int id;
    //public Cryption crypter;
    private boolean connected = true;
    private byte[] key;

    public Message(String text, String name) { //message constructors
        this.text = text;
        this.name = name;
        //this.crypter = crypter;
     
    }

    public Message(String text, boolean connected) { //message constructor for disconnect
        this.connected = connected;
        this.text = text;

    }

    public void setKey(byte[] key) {//getters and setters
        this.key = key;
    }
    
    public byte[] getKey() {
        return key;
    }

    public String getText() {
        return text;
    }

    public void setText(String text) {
        this.text = text;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }


    public boolean isConnected() {
        return connected;
    }

    public void setConnected(boolean connected) {
        this.connected = connected;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public int getUserAmount() {
        return userAmount;
    }

    public void setUserAmount(int userAmount) {
        this.userAmount = userAmount;
    }
}
