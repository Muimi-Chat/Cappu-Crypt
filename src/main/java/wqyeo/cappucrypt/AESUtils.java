package wqyeo.cappucrypt;

import jakarta.annotation.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import wqyeo.cappucrypt.enums.EncryptionType;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Base64;

public class AESUtils {
    private static final SecureRandom secureRandom = new SecureRandom();

    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_AUTH_TAG_LENGTH = 128;

    private static final Logger log = LoggerFactory.getLogger(AESUtils.class);

    public static String generateAESKeyString(EncryptionType encryptionType) {
        int keySize = switch (encryptionType) {
            case AES_128 -> 128;
            case AES_192 -> 192;
            case AES_256 -> 256;
        };

        SecretKey secretKey = generateAESKey(keySize);

        byte[] keyBytes = secretKey.getEncoded();
        return Base64.getEncoder().encodeToString(keyBytes);
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

    private static SecretKey toSecretKey(String keyString){
        return new SecretKeySpec(Base64.getDecoder().decode(keyString), "AES");
    }

    public static String encryptAES(String originalString, String keyString) throws Exception {
        return encryptAES(originalString, keyString, null);
    }

    public static String encryptAES(
            String originalString,
            String keyString,
            @Nullable String metadata
    ) throws Exception {
        byte[] iv = generateIV();
        final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_AUTH_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, toSecretKey(keyString), parameterSpec);

        if (metadata != null && !metadata.isEmpty() && !metadata.isBlank()) {
            byte[] metadataBytes = metadata.getBytes(StandardCharsets.UTF_8);
            cipher.updateAAD(metadataBytes);
        }

        byte[] cipherText = cipher.doFinal(originalString.getBytes(StandardCharsets.UTF_8));

        ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + cipherText.length);
        byteBuffer.put(iv);
        byteBuffer.put(cipherText);

        return Base64.getEncoder().encodeToString(byteBuffer.array());
    }

    private static byte[] generateIV() {
        byte[] iv = new byte[GCM_IV_LENGTH];
        secureRandom.nextBytes(iv);
        return iv;
    }

    public static String decryptAES(String encryptedString, String keyString) throws Exception {
        return decryptAES(encryptedString, keyString, null);
    }

    public static String decryptAES(
            String encryptedString,
            String keyString,
            @Nullable String metadata
    ) throws Exception {
        final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        byte[] cipherMessage = Base64.getDecoder().decode(encryptedString);

        AlgorithmParameterSpec gcmIv = new GCMParameterSpec(GCM_AUTH_TAG_LENGTH, cipherMessage, 0, GCM_IV_LENGTH);
        cipher.init(Cipher.DECRYPT_MODE, toSecretKey(keyString), gcmIv);

        if (metadata != null && !metadata.isEmpty() && !metadata.isBlank()) {
            byte[] metadataBytes = metadata.getBytes(StandardCharsets.UTF_8);
            cipher.updateAAD(metadataBytes);
        }

        byte[] plainText = cipher.doFinal(cipherMessage, GCM_IV_LENGTH, cipherMessage.length - GCM_IV_LENGTH);
        return new String(plainText, StandardCharsets.UTF_8);
    }
}
