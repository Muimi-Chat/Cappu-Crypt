package wqyeo.cappucrypt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import wqyeo.cappucrypt.enums.EncryptionType;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class AESUtils {
    private static final Logger log = LoggerFactory.getLogger(AESUtils.class);

    public static String generateAESKeyString(EncryptionType encryptionType) {
        int keySize = switch (encryptionType) {
            case AES_128 -> 128;
            case AES_192 -> 192;
            case AES_256 -> 256;
        };

        SecretKey secretKey = generateAESKey(keySize);

        byte[] keyBytes = secretKey.getEncoded();
        StringBuilder hexString = new StringBuilder();
        for (byte b : keyBytes) {
            hexString.append(String.format("%02X", b));
        }

        return hexString.toString();
    }

    private static SecretKey generateAESKey(int keySize) {
        KeyGenerator keyGen;
        try {
            keyGen = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            log.error("No such algorithm: AES", e);
            throw new RuntimeException(e);
        }

        keyGen.init(keySize);
        return keyGen.generateKey();
    }

    public static String encryptAES(String originalString, String keyString) throws Exception {
        byte[] keyBytes = hexStringToByteArray(keyString);

        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);

        byte[] encryptedBytes = cipher.doFinal(originalString.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decryptAES(String encryptedString, String keyString) throws Exception {
        byte[] keyBytes = hexStringToByteArray(keyString);

        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, keySpec);

        byte[] decodedBytes = Base64.getDecoder().decode(encryptedString);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        return new String(decryptedBytes);
    }

    public static byte[] hexStringToByteArray(String hexString) {
        int len = hexString.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4)
                    + Character.digit(hexString.charAt(i + 1), 16));
        }
        return data;
    }
}
