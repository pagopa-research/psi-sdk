package psi.client;

import psi.model.PsiRuntimeConfiguration;
import psi.utils.PsiPhaseStatistics;

import java.util.List;
import java.util.Map;
import java.util.Set;

public interface PsiClient {

    Map<Long, String> loadAndEncryptClientDataset(Set<String> clearClientDataset);

    void loadDoubleEncryptedClientDataset(Map<Long, String> doubleEncryptedClientDatasetMap);

    void loadAndProcessServerDataset(Set<String> serverEncryptedDataset);

    Set<String> computePsi();

    PsiClientKeyDescription getClientKeyDescription();

    List<PsiPhaseStatistics> getStatisticList();

    void setConfiguration(PsiRuntimeConfiguration configuration);
}
