package psi.pluggable;

public interface EncryptionCacheProvider {
    enum CacheOperationType {
        PRIVATE_KEY_ENCRYPTION, BLIND_SIGNATURE_ENCRYPTION
    }

    public String getCachedEncryptedValue(long keyId, CacheOperationType cacheObjectType, String key);

    public String putEncryptedValue(long keyId, CacheOperationType cacheObjectType, String key);
}
