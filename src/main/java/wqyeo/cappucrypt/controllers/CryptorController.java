package wqyeo.cappucrypt.controllers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import wqyeo.cappucrypt.AESUtils;
import wqyeo.cappucrypt.entities.EncryptionKey;
import wqyeo.cappucrypt.enums.EncryptionType;
import wqyeo.cappucrypt.records.DecryptionResult;
import wqyeo.cappucrypt.records.DeleteKeyResult;
import wqyeo.cappucrypt.records.EncryptionResult;
import wqyeo.cappucrypt.repositories.EncryptionKeyRepository;

import javax.crypto.BadPaddingException;
import java.util.*;

@Controller
@RequestMapping(path="/crypt")
public class CryptorController {
    private static final Logger log = LoggerFactory.getLogger(CryptorController.class);
    @Autowired
    private EncryptionKeyRepository encryptionKeyRepository;

    public static final EncryptionType DEFAULT_ENCRYPTION_TYPE = EncryptionType.AES_256;

    @PostMapping(path="/encrypt")
    public @ResponseBody ResponseEntity<EncryptionResult> encryptData(
            @RequestHeader(name="Authorization", required = false, defaultValue = "") String authHeader,
            @RequestParam(required = false, defaultValue = "") String id,
            @RequestParam(name="encryptionType", required = false, defaultValue = "") String encryptionTypeString,
            @RequestParam(required = false, defaultValue = "") String content,
            @RequestParam(required = false, defaultValue = "") String metadata
    ) {
        List<String> resultMessages = new ArrayList<>();
        List<String> resultNotes = new ArrayList<>();

        if (authHeader == null || !authHeader.equals(System.getenv("API_AUTH_KEY"))) {
            resultMessages.add("Invalid API key.");

            EncryptionResult response = new EncryptionResult("BAD_API_KEY",null, null, resultMessages, resultNotes);
            return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
        }

        if (content.isEmpty() || content.isBlank()) {
            resultMessages.add("Content was not provided.");

            EncryptionResult response = new EncryptionResult("EMPTY_CONTENT", null, null, resultMessages, resultNotes);
            return new ResponseEntity<>(response, HttpStatus.NOT_ACCEPTABLE);
        }

        EncryptionKey encryptionKey;
        Optional<EncryptionKey> keyInDatabase = Optional.empty();

        // If ID is provided, try to find encryption key in database first.
        if (id.isEmpty() || id.isBlank()) {
            id = UUID.randomUUID().toString();
            resultMessages.add("ID was not provided, creating new ID.");
            resultNotes.add("NEW_ID_CREATED");
        } else {
            keyInDatabase = encryptionKeyRepository.findById(id);
            if (keyInDatabase.isEmpty()) {
                resultMessages.add("ID not found in database. Creating new key.");
                resultNotes.add("NEW_KEY_CREATED");
            } else {
                resultMessages.add("ID found in database. Using existing key.");
                resultNotes.add("EXISTING_KEY_FETCHED");
            }
        }

        String encryptedKey;
        if (keyInDatabase.isEmpty()) {
            // Generate and store encryption key into database.
            encryptionKey = new EncryptionKey();
            encryptionKey.setId(id);

            // Determine encryption type, default if cant be determined from request
            Optional<EncryptionType> determinedEncryptionType = stringToEncryptionType(encryptionTypeString);
            EncryptionType encryptionType;
            if (determinedEncryptionType.isEmpty()) {
                encryptionType = DEFAULT_ENCRYPTION_TYPE;
                if (!encryptionTypeString.isEmpty() && !encryptionTypeString.isBlank()) {
                    resultMessages.add("Invalid or bad encryption type. Defaulting to: " + DEFAULT_ENCRYPTION_TYPE.name());
                    resultNotes.add("DEFAULTED_TO_" + DEFAULT_ENCRYPTION_TYPE.name());
                }
            } else {
                encryptionType = determinedEncryptionType.get();
            }

            // Encrypt the new key with master key...
            try {
                encryptedKey = AESUtils.encryptAES(AESUtils.generateAESKeyString(encryptionType), System.getenv("MASTER_KEY"));
            } catch (Exception e) {
                log.error("Error using maser key (ENCRYPT) :: ", e);
                resultMessages.add("Server encountered an error trying to encrypt...");
                EncryptionResult response = new EncryptionResult("ENCRYPTION_FAILED_FATAL", null, null, resultMessages, resultNotes);
                return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
            }

            encryptionKey.setEncryptionType(encryptionType);
            encryptionKey.setEncryptedKey(encryptedKey);
            encryptionKeyRepository.save(encryptionKey);
            resultMessages.add("Created new key for " + id + " with encryption method: " + encryptionKey.getEncryptionType().name());
        } else {
            encryptionKey = keyInDatabase.get();
            encryptedKey = encryptionKey.getEncryptedKey();

            // Warn if requested encryption type does not match.
            Optional<EncryptionType> determinedEncryptionType = stringToEncryptionType(encryptionTypeString);
            if (determinedEncryptionType.isPresent() && determinedEncryptionType.get() != encryptionKey.getEncryptionType()) {
                resultMessages.add("Requested Encryption Key Type mismatch in Database. Actual is : " + encryptionKey.getEncryptionType().name());
                resultNotes.add("ENCRYPTION_REQUEST_TYPE_MISMATCH");
            }
        }

        // Encrypt the content.
        String encryptedContent;
        try {
            // Decrypt with master key to get actual key, then encrypt...
            String actualKey = AESUtils.decryptAES(encryptedKey, System.getenv("MASTER_KEY"));
            encryptedContent = AESUtils.encryptAES(content, actualKey, metadata);
        } catch (Exception e) {
            log.error("Error encrypting key :: ", e);
            resultMessages.add("Server encountered an error trying to encrypt...");
            EncryptionResult response = new EncryptionResult("ENCRYPTION_FAILED_FATAL", null, null, resultMessages, resultNotes);
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }

        resultNotes.add("ENCRYPTED_WITH_" + encryptionKey.getEncryptionType().name());
        EncryptionResult response = new EncryptionResult("SUCCESS", id, encryptedContent, resultMessages, resultNotes);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @PostMapping(path="/decrypt")
    public @ResponseBody ResponseEntity<DecryptionResult> decryptData(
            @RequestHeader(name = "Authorization", required = false, defaultValue = "") String authHeader,
            @RequestParam(required = false, defaultValue = "") String id,
            @RequestParam(required = false, defaultValue = "") String content,
            @RequestParam(required = false, defaultValue = "") String metadata
    ) {
        List<String> resultNotes = new ArrayList<>();
        List<String> resultMessages = new ArrayList<>();

        if (authHeader == null || !authHeader.equals(System.getenv("API_AUTH_KEY"))) {
            resultMessages.add("Invalid API key.");

            DecryptionResult response = new DecryptionResult("BAD_API_KEY", null, resultMessages, resultNotes);
            return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
        }

        if (content.isEmpty() || content.isBlank()) {
            resultMessages.add("Content was not provided.");

            DecryptionResult response = new DecryptionResult("EMPTY_CONTENT", null, resultMessages, resultNotes);
            return new ResponseEntity<>(response, HttpStatus.NOT_ACCEPTABLE);
        }

        if (id.isEmpty() || id.isBlank()) {
            resultMessages.add("ID was not provided.");

            DecryptionResult response = new DecryptionResult("EMPTY_ID", null, resultMessages, resultNotes);
            return new ResponseEntity<>(response, HttpStatus.NOT_ACCEPTABLE);
        }

        EncryptionKey encryptionKey;
        Optional<EncryptionKey> keyInDatabase;

        // Check key's existence in database
        keyInDatabase = encryptionKeyRepository.findById(id);
        if (keyInDatabase.isEmpty()) {
            resultMessages.add("ID not found in database!");

            DecryptionResult response = new DecryptionResult("ID_NOT_FOUND", null, resultMessages, resultNotes);
            return new ResponseEntity<>(response, HttpStatus.NOT_ACCEPTABLE);
        }

        resultMessages.add("ID found in database. Using existing key.");
        encryptionKey = keyInDatabase.get();

        // Unlock key with master key...
        String key;
        try {
            key = AESUtils.decryptAES(encryptionKey.getEncryptedKey(), System.getenv("MASTER_KEY"));
        } catch (Exception e) {
            resultMessages.add("Server encountered an error trying to decrypt...");
            DecryptionResult response = new DecryptionResult("DECRYPTION_FAILED_FATAL", null, resultMessages, resultNotes);
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }

        // Try decrypt content...
        String decryptedContent;
        try {
            decryptedContent = AESUtils.decryptAES(content, key, metadata);
        } catch (BadPaddingException e) {
            resultMessages.add("Content could not be decrypted. Likely bad ID for content content.");
            DecryptionResult response = new DecryptionResult("DECRYPTION_FAILED", null, resultMessages, resultNotes);
            return new ResponseEntity<>(response, HttpStatus.UNPROCESSABLE_ENTITY);
        } catch (Exception e) {
            log.error("Error using maser key (DECRYPT) :: ", e);
            resultMessages.add("Server encountered an error trying to decrypt...");
            DecryptionResult response = new DecryptionResult("DECRYPTION_FAILED_FATAL", null, resultMessages, resultNotes);
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }

        resultMessages.add("Decrypted content with encryption type: " + encryptionKey.getEncryptionType().name());
        resultNotes.add("DECRYPTED_WITH_" + encryptionKey.getEncryptionType().name());

        DecryptionResult response = new DecryptionResult("SUCCESS", decryptedContent, resultMessages, resultNotes);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @PostMapping(path = "/delete")
    @Transactional
    public @ResponseBody ResponseEntity<DeleteKeyResult> decryptData(
            @RequestHeader(name = "Authorization", required = false, defaultValue = "") String authHeader,
            @RequestParam(required = false, defaultValue = "") String id
            ) {
        if (authHeader == null || !authHeader.equals(System.getenv("API_AUTH_KEY"))) {
            DeleteKeyResult response = new DeleteKeyResult("BAD_API_KEY", "Set API Key in Authorization header!");
            return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
        }

        if (id.isEmpty() || id.isBlank()) {
            DeleteKeyResult response = new DeleteKeyResult("EMPTY_ID", "Provided ID is blank or empty!");
            return new ResponseEntity<>(response, HttpStatus.NOT_ACCEPTABLE);
        }


        Integer deletionResult = encryptionKeyRepository.deleteById(id);
        if (deletionResult == 1) {
            DeleteKeyResult response = new DeleteKeyResult("SUCCESS", "Successfully deleted key with provided ID.");
            return new ResponseEntity<>(response, HttpStatus.OK);
        }

        DeleteKeyResult response = new DeleteKeyResult("ID_NOT_FOUND", "Provided ID not found in database!");
        return new ResponseEntity<>(response, HttpStatus.NOT_ACCEPTABLE);
    }

    private Optional<EncryptionType> stringToEncryptionType(String encryptionType) {
        return switch (encryptionType.toUpperCase()) {
            case "AES_128" -> Optional.of(EncryptionType.AES_128);
            case "AES_192" -> Optional.of(EncryptionType.AES_192);
            case "AES_256" -> Optional.of(EncryptionType.AES_256);
            default -> Optional.empty();
        };
    }
}
