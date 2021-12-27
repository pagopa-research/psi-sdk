package psi.client;

import psi.client.PsiClient;

import java.math.BigInteger;
import java.util.Set;

public abstract class PsiAbstractClient implements PsiClient {

    protected static final int DEFAULT_THREADS = 4;

    protected Set<BigInteger> serverEncryptedDataset;
    protected BigInteger clientPrivateKey;
    protected BigInteger serverPublicKey;
    protected BigInteger modulus;
    protected long sessionId;
}
