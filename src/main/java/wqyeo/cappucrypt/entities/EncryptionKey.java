package wqyeo.cappucrypt.entities;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Column;
import jakarta.persistence.EnumType;
import lombok.Getter;
import lombok.Setter;
import wqyeo.cappucrypt.enums.EncryptionType;

@Setter
@Getter
@Entity
public class EncryptionKey {
    @Id
    @Column(length = 64, nullable = false)
    private String id;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private EncryptionType encryptionType;

    @Column(length = 512, nullable = false)
    private String encryptedKey;
}