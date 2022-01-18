package psi.server;

import psi.cache.PsiCacheProvider;
import psi.utils.StatisticsFactory;
import psi.server.model.PsiServerSession;

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

    public List<StatisticsFactory> getStatisticList();

}
