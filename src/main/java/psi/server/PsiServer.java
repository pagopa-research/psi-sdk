package psi.server;

import psi.PsiServerKeyDescription;
import psi.PsiServerSession;
import psi.cache.PsiCacheProvider;
import psi.model.PsiPhaseStatistics;
import psi.model.PsiRuntimeConfiguration;

import java.util.List;
import java.util.Map;
import java.util.Set;

public interface PsiServer {

    Set<String> encryptDataset(Set<String> inputSet);

    Map<Long, String> encryptDatasetMap(Map<Long, String> encryptedDatasetMap);

    int getThreads();

    PsiServerSession getServerSession();

    PsiCacheProvider getPsiCacheProvider();

    PsiServerKeyDescription getServerKeyDescription();

    List<PsiPhaseStatistics> getStatisticList();

    void setConfiguration(PsiRuntimeConfiguration configuration);

}
