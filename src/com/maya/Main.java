package com.maya;

import com.support.AckMessage;
import com.support.Chunk;
import com.support.StartMessage;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Scanner;
import java.util.zip.CRC32;

public class Main {
    private static Scanner sc = new Scanner(System.in);

    public static void main(String[] args) {
        if(args.length == 0){
            System.out.println("Error. Must run program with args");
        }
        else if(args[0].equals("makekeys")) {
            makeKeys();
        }
        else if(args[0].equals("client") & args.length == 4) {
            try{
                String publicKey = args[1];
                String host = args[2];
                int port = Integer.parseInt(args[3]);

                Socket socket = new Socket(host, port);

                //Instantiate streams
                InputStream is = socket.getInputStream();
                ObjectInputStream ois = new ObjectInputStream(is);
                OutputStream os = socket.getOutputStream();
                ObjectOutputStream oos = new ObjectOutputStream(os);

                //Generate Public key
                RSAPublicKey rsaKey = (RSAPublicKey) ois.readObject();

                //Generate AES session key
                SecureRandom r = new SecureRandom();
                byte[] aesKey = new byte[128];
                r.nextBytes(aesKey);

                //Encrypt session key
                SecretKey secretKey = new SecretKeySpec(aesKey, "AES");
                Cipher cipher = Cipher.getInstance("RSA");
                cipher.init(Cipher.WRAP_MODE, rsaKey);
                byte[] encryptedKey = cipher.wrap(secretKey);

                //Prompt user for file path & initial chunk size
                System.out.print("Enter file path: ");
                String filePath = sc.nextLine();
                File outputFile = new File(filePath);
                byte[] alldata = Files.readAllBytes(Paths.get(filePath));

                System.out.print("Enter chunk size [bytes] or to keep default, hit enter: ");
                int chunksize = 1024;
                String enteredChunkSize = sc.next();
                if (enteredChunkSize.length() != 0){
                    chunksize = Integer.parseInt(enteredChunkSize);
                }

                //Send server a start message
                if (outputFile.exists()){
                    StartMessage startMessage = new StartMessage(outputFile.getName(), encryptedKey, chunksize);
                    oos.writeObject(startMessage);
                }


                //Send all chunks
                int byteCount = 0;
                int numOfChunks = (int)outputFile.length() / chunksize;
                for (int i = 0; i < numOfChunks; i++){
                    byte[] sending = new byte[chunksize];

                    for (int j=0; j<chunksize;j++){
                        sending[j] = alldata[byteCount];
                    }
                    byteCount++;

                    //Receive AckMessage response
                    AckMessage am = (AckMessage) ois.readObject();
                    int seq = am.getSeq();
                    String ackResponse = (am.getSeq() == 0? "Success": "Failure");
                    System.out.println("Server response to Message: " + ackResponse);


                    //calculate CRC val
                    CRC32 crc32 = new CRC32();
                    crc32.update(sending);
                    int crcVal = (int)crc32.getValue();
                    int checksum = crcVal;

                    //send chunk to server
                    byte[] encrypt = cipher.doFinal(sending);
                    Chunk chunk = new Chunk(seq, encrypt, checksum);
                    oos.writeObject(chunk);

                    //update chunksize

                }
            } catch (Exception e){
                System.out.println("Error sending chunks in client. Error: " + e);
            }

        }
        else if(args[0].equals("server") & args.length == 3) {
            try{
                String publicKey = args[1];
                String host = args[2];
                int port = Integer.parseInt(args[3]);

                while (true){
                    ServerSocket serverSocket = new ServerSocket(port);
                    Socket socket = serverSocket.accept();

                    //Instantiate streams
                    InputStream is = socket.getInputStream();
                    ObjectInputStream ois = new ObjectInputStream(is);
                    OutputStream os = socket.getOutputStream();
                    ObjectOutputStream oos = new ObjectOutputStream(os);

                    //receive start message and send ack message
                    StartMessage sm = (StartMessage) ois.readObject();
                    AckMessage am = new AckMessage(0);
                    oos.writeObject(am);

                    //Generate Private key
                    RSAPrivateKey rsaKey = (RSAPrivateKey) ois.readObject();

                    //find secret key
                    Cipher cipher = Cipher.getInstance("RSA");
                    cipher.init(Cipher.UNWRAP_MODE, rsaKey);
                    Key secretKey = cipher.unwrap(sm.getEncryptedKey(), "AES", Cipher.SECRET_KEY);

                    //find data chunk info
                    int chunkSize = (int)sm.getChunkSize();
                    int fileSize = (int)sm.getSize();
                    int numOfChunks = (int)((double)fileSize / (double)chunkSize);
                    String message = "";

                    for (int i=0; i < numOfChunks; i++){
                        Chunk readChunk = (Chunk) ois.readObject();

                        //decrypt chunk
                        Cipher cipherChunk = Cipher.getInstance("AES");
                        cipherChunk.init(Cipher.DECRYPT_MODE, secretKey);
                        byte[] decrypt = cipherChunk.doFinal(readChunk.getData());

                        //check if message was tampered
                        int checkSumDecrypt = (int)checksum(decrypt);
                        int checkSumCRC = readChunk.getCrc();
                        String chunkData = new String(readChunk.getData());
                        String appendMessage = (checkSumDecrypt == checkSumCRC? chunkData: "");

                        //send ack message if message successfully transfered
                        if (appendMessage.equals("")){
                            System.out.println("ERROR. message did not successfully transfer from client");
                        } else{
                            message += appendMessage;
                            AckMessage amChunk = new AckMessage(readChunk.getSeq()+1);
                            oos.writeObject(amChunk);
                        }
                    }

                }
            } catch (Exception e){

            }
        }
        else {
            System.out.println("Error with executing project. Make sure commandline args are correct");
            System.out.println("Enter 'makekeys', 'client', or 'server' and the appropriate args following the command");
        }

    }

    public static short checksum(byte[] b){
        int sum = 0;
        for (int i = 0; i < b.length; i+=2){
            //get first 2 halfs of values
            int firstHalf = b[i] << 8;
            firstHalf &= 0xFF00;
            int secondHalf = b[i+1] & 0xFF;

            sum += firstHalf + secondHalf;

            if ((sum & 0xFFFF0000) != 0){
                sum &= 0xFFFF;
                sum++;
            }
        }
        return (short)(~(sum & 0xFFFF));
    }

    public static void makeKeys(){
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(4096); // you can use 2048 for faster key generation
            KeyPair keyPair = gen.genKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();
            try (ObjectOutputStream oos = new ObjectOutputStream(
                    new FileOutputStream(new File("public.bin")))) {
                oos.writeObject(publicKey);
            }
            try (ObjectOutputStream oos = new ObjectOutputStream(
                    new FileOutputStream(new File("private.bin")))) {
                oos.writeObject(privateKey);
            }
        } catch (NoSuchAlgorithmException | IOException e) {
            e.printStackTrace(System.err);
        }
    }
}
