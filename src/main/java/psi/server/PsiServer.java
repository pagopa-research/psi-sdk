package psi.server;

import psi.cache.PsiCacheProvider;
import psi.client.PsiClientKeyDescription;
import psi.utils.StatisticsFactory;

import java.util.List;
import java.util.Map;
import java.util.Set;

public interface PsiServer {

    Set<String> encryptDataset(Set<String> inputSet);

    Map<Long, String> encryptDatasetMap(Map<Long, String> encryptedDatasetMap);

    int getThreads();

    void setThreads(int threads);

    PsiServerSession getServerSession();

    PsiCacheProvider getPsiCacheProvider();

    PsiServerKeyDescription getServerKeyDescription();

    public List<StatisticsFactory> getStatisticList();

}
