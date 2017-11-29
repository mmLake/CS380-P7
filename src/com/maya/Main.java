package com.maya;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.*;
import java.util.Scanner;

public class Main {
    private Scanner sc = new Scanner(System.in);

    public static void main(String[] args) {

        if(args[0].equals("makekeys")) {
            makeKeys();
        }
        else if(args[0].equals("client")) {
            
        }
        else if(args[0].equals("server")) {
        }
        else {
            System.out.println("Error with executing project. Make sure commandline args are correct");
            System.out.println("Enter 'makekeys', 'client', or 'server' and the appropriate args following the command");
        }

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
