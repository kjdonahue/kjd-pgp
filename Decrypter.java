import java.util.Scanner;
import java.util.Base64;
import java.util.List;
import java.util.ArrayList;

import java.io.File;
import java.io.IOException;

import java.security.spec.PKCS8EncodedKeySpec;

public class Decrypter {

    public static void main(String[] args) throws IOException, ModeException {

        Scanner scan = new Scanner(System.in);
        String keyFilename;
        File keyFile;
        List<String> keyLines;
        Base64.Decoder baseReader;
        byte[] keyBytes;

        Crypto crypto;

        String message, key, plaintext, iv;

        java.nio.file.Path keyPath;

        System.out.print("Private key file: ");
        keyFilename = scan.nextLine().trim();

        System.out.print("Ciphertext: ");
        message = scan.nextLine().trim();

        System.out.print("Key ciphertext: ");
        key = scan.nextLine().trim();

        System.out.print("IV ciphertext: ");
        iv = scan.nextLine().trim();

        keyFile = new File(keyFilename);
        keyPath = keyFile.toPath();

        keyBytes = java.nio.file.Files.readAllBytes(keyPath);

        crypto = new Crypto(key, message, iv, new PKCS8EncodedKeySpec(keyBytes));

        System.out.println("Plaintext:");
        System.out.println(crypto.decryptMessage());
    }
}
