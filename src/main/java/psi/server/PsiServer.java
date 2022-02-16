package psi.server;

import psi.PsiServerKeyDescription;
import psi.PsiServerSession;
import psi.cache.PsiCacheProvider;
import psi.model.PsiPhaseStatistics;
import psi.model.PsiRuntimeConfiguration;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * This interface exposes the server APIs required to calculate psi regardless of the algorithm used.
 * Note: all the input and output collections are devised to work on Strings in order to facilitate the exchanges
 * between the parties while hiding the complexity od the implementations. Thus, if the domain of the psi is different
 * from String, it has to be previously converted.
 */
public interface PsiServer {

    /**
     * Encrypts and returns the input element set. It is used to encrypt the clear server dataset.
     * @param inputSet set of elements to be encrypted by the server
     * @return a Set containing the encrypted input dataset
     */
    Set<String> encryptDataset(Set<String> inputSet);

    /**
     * Encrypts and returns the set of values contained into the input map. It is used to encrypt the client dataset,
     * previously encrypted by the client itself. The keys are used as identifier to link encrypted values with the
     * original ones.
     * @param encryptedDatasetMap a map which values must be encrypted by the server
     * @return a Map with the same key of the input map, associated to the corresponding encrypted values
     */
    Map<Long, String> encryptDatasetMap(Map<Long, String> encryptedDatasetMap);

    int getThreads();

    PsiServerSession getServerSession();

    PsiCacheProvider getPsiCacheProvider();

    PsiServerKeyDescription getServerKeyDescription();

    /**
     * Retrieves the statistics collected during the execution of the PsiServer.
     * @return a list containing a different PsiPhaseStatistics for each encryption phase
     */
    List<PsiPhaseStatistics> getStatisticList();

    /**
     * Configures the number of threads and the max lifetime of each thread used by the PsiServer.
     * @param configuration containing the runtime configuration parameters
     */
    void setConfiguration(PsiRuntimeConfiguration configuration);

}
