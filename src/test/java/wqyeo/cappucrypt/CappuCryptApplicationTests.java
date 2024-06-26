package wqyeo.cappucrypt;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import wqyeo.cappucrypt.controllers.CryptorController;

import org.springframework.http.*;
import wqyeo.cappucrypt.enums.EncryptionType;
import wqyeo.cappucrypt.records.DecryptionResult;
import wqyeo.cappucrypt.records.EncryptionResult;

import java.util.Objects;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;

/**
 * NOTE: There's a bug where Transactional rollback is not working; Test this on a non-production database!
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Transactional
class CappuCryptApplicationTests {

    private static final Logger log = LoggerFactory.getLogger(CappuCryptApplicationTests.class);
    @Autowired
    private CryptorController controller;

    @Test
    void contextLoads() throws Exception {
        assertThat(controller).isNotNull();
    }

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    private static final String FIXED_ID = "TESTING_ID";
    private static final String FIXED_METADATA = "TESTING_123";

    @Test
    void testEncryptWithAES256() throws Exception {
        String url = "http://localhost:" + port + "/crypt/encrypt";

        // Set the authorization header
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.MULTIPART_FORM_DATA);
        headers.set("Authorization", System.getenv("API_AUTH_KEY"));

        // Create the HttpEntity object with the request body and headers
        MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
        body.add("encryptionType", "AES_256");
        body.add("content", "Hello, World! AES 256");

        HttpEntity<MultiValueMap<String, Object>> request = new HttpEntity<>(body, headers);

        // Perform the POST request
        ResponseEntity<EncryptionResult> response = restTemplate.postForEntity(url, request, EncryptionResult.class);

        // Assert the response status and body
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("SUCCESS", Objects.requireNonNull(response.getBody()).status());
        assertNotNull(response.getBody().id());
        assertNotNull(response.getBody().encryptedContent());
        System.out.println("Random AES 256 :: " + response.getBody().encryptedContent());
    }

    @Test
    void testEncryptWithAES192() throws Exception {
        String url = "http://localhost:" + port + "/crypt/encrypt";

        // Set the authorization header
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.MULTIPART_FORM_DATA);
        headers.set("Authorization", System.getenv("API_AUTH_KEY"));

        // Create the HttpEntity object with the request body and headers
        MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
        body.add("encryptionType", "AES_192");
        body.add("content", "Hello, World! AES 192");

        HttpEntity<MultiValueMap<String, Object>> request = new HttpEntity<>(body, headers);

        // Perform the POST request
        ResponseEntity<EncryptionResult> response = restTemplate.postForEntity(url, request, EncryptionResult.class);

        // Assert the response status and body
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("SUCCESS", Objects.requireNonNull(response.getBody()).status());
        assertNotNull(response.getBody().id());
        assertNotNull(response.getBody().encryptedContent());
        System.out.println("Random AES 192 :: " + response.getBody().encryptedContent());
    }

    @Test
    void testEncryptWithAES128() throws Exception {
        String url = "http://localhost:" + port + "/crypt/encrypt";

        // Set the authorization header
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.MULTIPART_FORM_DATA);
        headers.set("Authorization", System.getenv("API_AUTH_KEY"));

        // Create the HttpEntity object with the request body and headers
        MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
        body.add("encryptionType", "AES_128");
        body.add("content", "Hello, World! AES 128");

        HttpEntity<MultiValueMap<String, Object>> request = new HttpEntity<>(body, headers);

        // Perform the POST request
        ResponseEntity<EncryptionResult> response = restTemplate.postForEntity(url, request, EncryptionResult.class);

        // Assert the response status and body
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("SUCCESS", Objects.requireNonNull(response.getBody()).status());
        assertNotNull(response.getBody().id());
        assertNotNull(response.getBody().encryptedContent());
        System.out.println("Random AES 128 :: " + response.getBody().encryptedContent());
    }

    @Test
    void testEncryptWithFixedID() throws Exception {
        String url = "http://localhost:" + port + "/crypt/encrypt";

        // Set the authorization header
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.MULTIPART_FORM_DATA);
        headers.set("Authorization", System.getenv("API_AUTH_KEY"));

        // Create the HttpEntity object with the request body and headers
        MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
        body.add("content", "Hello, World AES 256 with Fixed ID!");
        body.add("id", FIXED_ID);

        HttpEntity<MultiValueMap<String, Object>> request = new HttpEntity<>(body, headers);

        // Perform the POST request
        ResponseEntity<EncryptionResult> response = restTemplate.postForEntity(url, request, EncryptionResult.class);

        // Assert the response status and body
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("SUCCESS", Objects.requireNonNull(response.getBody()).status());
        assertEquals(FIXED_ID,(response.getBody().id()));
        assertNotNull(response.getBody().encryptedContent());
        System.out.println("Fixed ID :: " + response.getBody().encryptedContent());
    }

    @Test
    void testEncryptWithFixedIDAndMetadata() throws Exception {
        String url = "http://localhost:" + port + "/crypt/encrypt";

        // Set the authorization header
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.MULTIPART_FORM_DATA);
        headers.set("Authorization", System.getenv("API_AUTH_KEY"));

        // Create the HttpEntity object with the request body and headers
        MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
        body.add("content", "Hello, World! AES 256 with Fixed ID and Metadata!");
        body.add("id", FIXED_ID);
        body.add("metadata", FIXED_METADATA);

        HttpEntity<MultiValueMap<String, Object>> request = new HttpEntity<>(body, headers);

        // Perform the POST request
        ResponseEntity<EncryptionResult> response = restTemplate.postForEntity(url, request, EncryptionResult.class);

        // Assert the response status and body
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("SUCCESS", Objects.requireNonNull(response.getBody()).status());
        assertEquals(FIXED_ID,(response.getBody().id()));
        assertNotNull(response.getBody().encryptedContent());
        System.out.println("Fixed ID and Fixed Metadata :: " + response.getBody().encryptedContent());
    }
    /**
     * Generates a random ASCII Printable string of the specified length.
     *
     * @param  length  the length of the string to generate
     * @return         a randomly generated string
     */
    private static String generateRandomString(int length) {
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            char ch = (char) ThreadLocalRandom.current().nextInt(' ', '~' + 1);
            sb.append(ch);
        }
        return sb.toString();
    }

    static Stream<Object[]> generateTestCasesInputs() {
        Random random = new Random();
        String[] possibleIds = new String[15];
        for (int i = 0; i < 15; i++) {
            possibleIds[i] = generateRandomString(random.nextInt(65) + 1);
        }

        return Stream.generate(() -> new Object[] {
            generateRandomString(random.nextInt(249) + 1),
            EncryptionType.values()[random.nextInt(3)],
            generateRandomString(random.nextInt(129)),
            possibleIds[random.nextInt(possibleIds.length)]
        }).limit(50);
    }

    @ParameterizedTest
    @MethodSource("generateTestCasesInputs")
    void testFullCryptographyFlow(String intendedMessage, EncryptionType encryptionType, String metadata, String id) throws Exception {
        System.out.println("Message :: " + intendedMessage );
        System.out.println("Encryption Type :: " + encryptionType );
        System.out.println("Metadata :: " + metadata );
        System.out.println("ID :: " + id );

        String url = "http://localhost:" + port + "/crypt/encrypt";

        // Set the authorization header
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.MULTIPART_FORM_DATA);
        headers.set("Authorization", System.getenv("API_AUTH_KEY"));

        // Create the HttpEntity object with the request body and headers
        MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
        body.add("encryptionType", encryptionType.name());
        body.add("id", id);
        body.add("content", intendedMessage);
        body.add("metadata", metadata);

        HttpEntity<MultiValueMap<String, Object>> request = new HttpEntity<>(body, headers);

        // Perform the POST request
        ResponseEntity<EncryptionResult> encryptionResponse = restTemplate.postForEntity(url, request, EncryptionResult.class);

        // Assert the response status and body
        assertEquals(HttpStatus.OK, encryptionResponse.getStatusCode());
        assertEquals("SUCCESS", Objects.requireNonNull(encryptionResponse.getBody()).status());
        assertEquals(id,(encryptionResponse.getBody().id()));
        assertNotNull(encryptionResponse.getBody().encryptedContent());
        System.out.println("Encrypted into :: " + encryptionResponse.getBody().encryptedContent());

        url = "http://localhost:" + port + "/crypt/decrypt";
        headers = new HttpHeaders();
        headers.setContentType(MediaType.MULTIPART_FORM_DATA);
        headers.set("Authorization", System.getenv("API_AUTH_KEY"));
        body = new LinkedMultiValueMap<>();
        body.add("id", id);
        body.add("content", encryptionResponse.getBody().encryptedContent());
        body.add("metadata", metadata);
        request = new HttpEntity<>(body, headers);
        ResponseEntity<DecryptionResult> decryptionResponse = restTemplate.postForEntity(url, request, DecryptionResult.class);

        assertEquals(HttpStatus.OK, decryptionResponse.getStatusCode());
        assertEquals("SUCCESS", Objects.requireNonNull(decryptionResponse.getBody()).status());
        assertEquals(intendedMessage,(decryptionResponse.getBody().decryptedContent()));
    }

}
