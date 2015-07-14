import java.util.Scanner;
import java.util.Base64;
import java.util.List;
import java.util.ArrayList;

import java.io.File;
import java.io.IOException;

import java.security.spec.X509EncodedKeySpec;

public class Encrypter {    

    public static void main(String[] args) throws IOException, ModeException {

        Scanner scan = new Scanner(System.in);
        String keyFilename, messageFilename;
        File keyFile, messageFile;
        List<String> messageLines, keyLines;
        Base64.Decoder baseReader;
        byte[] keyBytes;

        Crypto crypto;

        String message, key;
        String[] pair;

        java.nio.file.Path messagePath, keyPath;

        System.out.print("Public key file: ");
        keyFilename = scan.nextLine().trim();

        keyFile = new File(keyFilename);
        keyPath = keyFile.toPath();

        System.out.print("Message file: ");
        messageFilename = scan.nextLine().trim();

        messageFile = new File(messageFilename);
        messagePath = messageFile.toPath();

        messageLines = java.nio.file.Files.readAllLines(messagePath);
        keyBytes = java.nio.file.Files.readAllBytes(keyPath);

        StringBuilder tempMessage = new StringBuilder();
        for (String s : messageLines) {
            tempMessage.append(s);
        }
        message = tempMessage.toString();

        crypto = new Crypto(new X509EncodedKeySpec(keyBytes));

        pair = crypto.encryptMessage(message);

        System.out.println("Ciphertext:\n" + pair[0]);
        System.out.println();
        System.out.println("Key ciphertext:\n" + pair[1]);
        System.out.println();
        System.out.println("IV ciphertext:\n" + pair[2]);
    }
}
