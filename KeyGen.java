import java.util.Scanner;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class KeyGen {

    public static void main(String[] args) {

        Scanner scan = new Scanner(System.in);
        
        KeyPairGenerator gen = null;
        SecureRandom rand;
        KeyPair pair;
        PrivateKey priv;
        PublicKey pub;
        File publicFile, privateFile;
        FileOutputStream pubStream = null, privStream = null;

        try {
            rand = SecureRandom.getInstance("SHA1PRNG");

            gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(1024, rand);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            System.exit(-1);
        }

        pair = gen.generateKeyPair();
        priv = pair.getPrivate();
        pub  = pair.getPublic();

        try {
            System.out.print("Enter public key filename: ");
            publicFile = new File(scan.nextLine().trim());

            System.out.print("Enter private key filename: ");
            privateFile = new File(scan.nextLine().trim());

            pubStream = new FileOutputStream(publicFile);
            privStream = new FileOutputStream(privateFile);

            pubStream.write(pub.getEncoded());
            privStream.write(priv.getEncoded());

        } catch (Exception e) {
            e.printStackTrace();
            return;
        } finally {
            if (pubStream != null) {
                try {
                    pubStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }

            if (privStream != null) {
                try {
                    privStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }

            }
        }
    }
}
