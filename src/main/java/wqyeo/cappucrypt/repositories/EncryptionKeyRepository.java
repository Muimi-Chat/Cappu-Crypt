package wqyeo.cappucrypt.repositories;

import org.springframework.data.repository.CrudRepository;
import wqyeo.cappucrypt.entities.EncryptionKey;

import java.util.Optional;
import java.util.List;

public interface EncryptionKeyRepository extends CrudRepository<EncryptionKey, Integer> {
    Optional<EncryptionKey> findById(String id);
}