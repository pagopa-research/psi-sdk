package psi.client;

import psi.client.model.PsiClientKeyDescription;
import psi.utils.StatisticsFactory;

import java.util.List;
import java.util.Map;
import java.util.Set;

public interface PsiClient {

    Map<Long, String> loadAndEncryptClientDataset(Set<String> clearClientDataset);

    void loadDoubleEncryptedClientDataset(Map<Long, String> doubleEncryptedClientDatasetMap);

    void loadServerDataset(Set<String> serverEncryptedDataset);

    Set<String> computePsi();

    PsiClientKeyDescription getClientKeyDescription();

    public List<StatisticsFactory> getStatisticList();
}
