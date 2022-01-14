package psi.client;

import psi.cache.PsiCacheProvider;

import java.math.BigInteger;
import java.time.Instant;
import java.util.Set;

public abstract class PsiAbstractClient implements PsiClient {

    protected static final int DEFAULT_THREADS = 4;

    protected Integer threads;
    protected Set<BigInteger> serverEncryptedDataset;
    protected BigInteger clientPrivateKey;
    protected BigInteger serverPublicKey;
    protected BigInteger modulus;
    protected Long sessionId;
    protected Instant expiration;

    protected Boolean cacheEnabled;
    protected Long cacheKeyId;
    protected PsiCacheProvider encryptionCacheProvider;
}
