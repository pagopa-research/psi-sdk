package psi;

/**
 * This enumeration, representing an encryption phase, is used as part of the key while storing into the cache the
 * result of a mathematical computation. This is required to distinguish different outputs obtained on the same input
 * object while performing different operations.
 */
enum CacheOperationType {
    KEY_VALIDATION, PRIVATE_KEY_HASH_ENCRYPTION, PRIVATE_KEY_ENCRYPTION, REVERSE_VALUE, BLIND_SIGNATURE_ENCRYPTION
}
