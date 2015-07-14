import java.util.Base64;

import java.security.SecureRandom;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Key;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.spec.IvParameterSpec;    
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Cipher;

public class Crypto {
    
    private String cipherKey, cipherMessage, cipherIV;
    private PKCS8EncodedKeySpec privKey;
    private X509EncodedKeySpec pubKey;
    private final int mode;

    private static final int ENCRYPT_MODE = 0;
    private static final int DECRYPT_MODE = 1;

    /* Instantiate with the ciphertext of the random encryption key and of the
     * actual message, along with the .  This puts the crypto module into decryption mode.
     */
    public Crypto(String key, String message, String iv, PKCS8EncodedKeySpec privateKey) {
        
        cipherKey = key;
        cipherMessage = message;
        cipherIV = iv;
        privKey = privateKey;
        mode = DECRYPT_MODE;
    }

    /* Instantiate with our public key.  This puts the crypto
     * module into encryption mode.
     */
    public Crypto(X509EncodedKeySpec publicKey) {
        
        this.pubKey = publicKey;
        mode = ENCRYPT_MODE;
    }

    /* Decrypt the message with which the object was instantiated.
     * Returns: the plaintext of the message.
     */
    public String decryptMessage() throws ModeException {
        
        Base64.Decoder baseReader = Base64.getDecoder();
        byte[] encMessageBytes, encKeyBytes, keyBytes, messageBytes, iv, encIV;
        Cipher RSADecoder, symmetricDecoder;
        Key symmetricKey;

        if (this.mode == ENCRYPT_MODE)
            throw new ModeException("Crypto module is in encryption mode!");

        encMessageBytes = baseReader.decode(cipherMessage.getBytes());
        encKeyBytes = baseReader.decode(cipherKey.getBytes());
        encIV = baseReader.decode(cipherIV.getBytes());

        try {
            
            /* Decode the encryption key with our private key. */
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = kf.generatePrivate(privKey);
            
            RSADecoder = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256andMGF1Padding");
            RSADecoder.init(Cipher.DECRYPT_MODE, privateKey);

            keyBytes = RSADecoder.doFinal(encKeyBytes);
            iv = RSADecoder.doFinal(encIV);

            /* Now we have the bytes of the sender's random encryption key.
             * Reconstruct that key using those bytes.
             *
             * XXX TODO:
             * we need to send the IV as well, figure this out later! (7/15/15)
             */
            symmetricKey = new SecretKeySpec(keyBytes, "AES");

            symmetricDecoder = Cipher.getInstance("AES/CBC/PKCS5Padding");
            symmetricDecoder.init(Cipher.DECRYPT_MODE, symmetricKey, new IvParameterSpec(iv));

            /* Decode the bytes of the message. */
            messageBytes = symmetricDecoder.doFinal(encMessageBytes);

            /* Return our message. */
            return new String(messageBytes);
            
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /* Encrypt the passed message with a random key and encrypts the key with
     * the private key with which the object was instantiated.
     * Returns: an array in the form of [encrypted message, encrypted key]
     */
    public String[] encryptMessage(String plaintext) throws ModeException {
        SecureRandom rand;
        SecretKeySpec symmetricKey;
        Cipher RSAEncoder, symmetricEncoder;
        Base64.Encoder baseWriter = Base64.getEncoder();
        byte[] encMessage, encKey, keyBytes, iv, encIV;
        
        String[] triple = new String[3];

        if (this.mode == DECRYPT_MODE)
            throw new ModeException("Crypto module is in decryption mode!");

        try {

            /* Generate a random symmetric key, 256 bytes for security. */
            rand = SecureRandom.getInstance("SHA1PRNG");
            keyBytes = new byte[16];
            rand.nextBytes(keyBytes);

            iv = new byte[16];
            rand.nextBytes(iv);
            
            symmetricKey = new SecretKeySpec(keyBytes, "AES");

            /* Encrypt our message using this key. */
            symmetricEncoder = Cipher.getInstance("AES/CBC/PKCS5Padding");
            symmetricEncoder.init(Cipher.ENCRYPT_MODE, symmetricKey, new IvParameterSpec(iv));

            encMessage = symmetricEncoder.doFinal(plaintext.getBytes());

            /* Now encrypt the key bytes using the sender's public key. */
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PublicKey publicKey = kf.generatePublic(this.pubKey);
            RSAEncoder = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256andMGF1Padding");
            RSAEncoder.init(Cipher.ENCRYPT_MODE, publicKey);

            encKey = RSAEncoder.doFinal(keyBytes);

            encIV = RSAEncoder.doFinal(iv);

            triple[0] = new String(baseWriter.encode(encMessage));
            triple[1] = new String(baseWriter.encode(encKey));
            triple[2] = new String(baseWriter.encode(encIV));

            return triple;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
