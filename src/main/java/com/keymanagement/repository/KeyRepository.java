package com.keymanagement.repository;

import com.keymanagement.entity.KeyEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

/**
 * JPA Repository for encryption keys.
 * Note: @Repository annotation is not needed for Spring Data JPA interfaces.
 */
public interface KeyRepository extends JpaRepository<KeyEntity, String> {

    /**
     * Find an active key by its ID.
     *
     * @param keyId The key identifier
     * @return Optional containing the key entity if found and active
     */
    Optional<KeyEntity> findByKeyIdAndActiveTrue(String keyId);

    /**
     * Count all active keys.
     *
     * @return The number of active keys
     */
    long countByActiveTrue();
}
