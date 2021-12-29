package psi.client;

import java.math.BigInteger;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Set;

public abstract class PsiAbstractClient implements PsiClient {

    protected static final int DEFAULT_THREADS = 4;

    protected int threads;
    protected Set<BigInteger> serverEncryptedDataset;
    protected BigInteger clientPrivateKey;
    protected BigInteger serverPublicKey;
    protected BigInteger modulus;
    protected long sessionId;
    protected Instant expiration;
}
