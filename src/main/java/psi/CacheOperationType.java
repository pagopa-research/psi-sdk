package psi;

/**
 * Defines an encryption phase, which is appended to the key of the entry put into the cache to store the
 * result of a mathematical computation. This allows to distinguish the outputs obtained by running different
 * operations on the same input.
 */
enum CacheOperationType {
    KEY_VALIDATION, PRIVATE_KEY_HASH_ENCRYPTION, PRIVATE_KEY_ENCRYPTION, REVERSE_VALUE, BLIND_SIGNATURE_ENCRYPTION
}
