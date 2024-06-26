package wqyeo.cappucrypt.repositories;

import org.springframework.data.repository.CrudRepository;
import wqyeo.cappucrypt.entities.EncryptionKey;

import java.util.Optional;

public interface EncryptionKeyRepository extends CrudRepository<EncryptionKey, Integer> {
    Optional<EncryptionKey> findById(String id);

    Integer deleteById(String id);
}