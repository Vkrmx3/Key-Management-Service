package com.keymanagement.repository;

import com.keymanagement.entity.KeyEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * JPA Repository for encryption keys with versioning support.
 */
@Repository
public interface KeyRepository extends JpaRepository<KeyEntity, String> {

    /**
     * Find an active key by its ID.
     *
     * @param keyId The key identifier
     * @return Optional containing the key entity if found and active
     */
    Optional<KeyEntity> findByKeyIdAndActiveTrue(String keyId);

    /**
     * Find the current version of a key by logical key ID.
     *
     * @param logicalKeyId The logical key identifier
     * @return Optional containing the current version
     */
    Optional<KeyEntity> findByLogicalKeyIdAndCurrentVersionTrueAndActiveTrue(String logicalKeyId);

    /**
     * Find a specific version of a key.
     *
     * @param logicalKeyId The logical key identifier
     * @param version The version number
     * @return Optional containing the specific version
     */
    Optional<KeyEntity> findByLogicalKeyIdAndVersionAndActiveTrue(String logicalKeyId, Integer version);

    /**
     * Find all versions of a key by logical key ID.
     *
     * @param logicalKeyId The logical key identifier
     * @return List of all versions
     */
    List<KeyEntity> findByLogicalKeyIdAndActiveTrueOrderByVersionDesc(String logicalKeyId);

    /**
     * Check if a logical key exists.
     *
     * @param logicalKeyId The logical key identifier
     * @return True if the logical key exists
     */
    boolean existsByLogicalKeyIdAndActiveTrue(String logicalKeyId);

    /**
     * Get the maximum version number for a logical key.
     *
     * @param logicalKeyId The logical key identifier
     * @return The maximum version number, or null if no versions exist
     */
    @Query("SELECT MAX(k.version) FROM KeyEntity k WHERE k.logicalKeyId = ?1 AND k.active = true")
    Integer findMaxVersionByLogicalKeyId(String logicalKeyId);

    /**
     * Count all active keys.
     *
     * @return The number of active keys
     */
    long countByActiveTrue();
}
