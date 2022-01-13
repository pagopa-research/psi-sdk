package psi.server;

import psi.dto.SessionParameterDTO;
import psi.exception.CustomRuntimeException;
import psi.exception.PsiClientInitException;
import psi.cache.EncryptionCacheProvider;
import psi.exception.PsiServerInitException;
import psi.model.BsKeyDescription;
import psi.model.KeyDescription;
import psi.model.ServerSession;
import psi.server.algorithm.BsPsiServer;
import psi.model.BsServerSession;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;

public interface PsiServer {

    Set<String> encryptDataset(Set<String> inputSet);

    Map<Long, String> encryptDatasetMap(Map<Long, String> encryptedDatasetMap);

    int getThreads();

    void setThreads(int threads);

    ServerSession getServerSession();

    EncryptionCacheProvider getEncryptionCacheProvider();
}
