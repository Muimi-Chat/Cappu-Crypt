package wqyeo.cappucrypt.records;

import jakarta.annotation.Nullable;

import java.util.List;

public record DecryptionResult(
        String status,
        @Nullable String decryptedContent,
        List<String> messages,
        List<String> notes
) { }
