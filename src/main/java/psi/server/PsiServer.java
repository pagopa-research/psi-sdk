package psi.server;

import psi.PsiServerKeyDescription;
import psi.cache.PsiCacheProvider;
import psi.model.PsiPhaseStatistics;
import psi.model.PsiServerSession;
import psi.model.PsiThreadConfiguration;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Interface that provides the methods that perform the server-side computation of the PSI for all the supported algorithms.
 * Instances of this class should be created by calling the methods in the <code>PsiServerFactory</code> class.
 * All the input and output collections are devised to work on Strings in order to facilitate the data exchange
 * between the parties and/or from external data sources.
 * Thus, the conversion of the datasets to String is required and outside the scope of this sdk.
 */
public interface PsiServer {

    /**
     * Encrypts and returns the input element set. This should be called to encrypt the clear server dataset.
     *
     * @param inputSet set of elements to be encrypted by the server
     * @return a Set containing the encrypted input dataset
     */
    Set<String> encryptDataset(Set<String> inputSet);

    /**
     * Encrypts and returns the set of values contained into the input map. It is used to encrypt the client dataset,
     * previously encrypted by the client itself. The keys of the map are identifiers that link together
     * different evolutions of the same entries.
     *
     * @param encryptedDatasetMap a map which values must be encrypted by the server
     * @return a Map where for each entry the key is the same as the input entry, and the value
     * is a server-side encryption of the value from the input entry
     */
    Map<Long, String> encryptDatasetMap(Map<Long, String> encryptedDatasetMap);

    int getThreads();

    PsiServerSession getServerSession();

    PsiCacheProvider getPsiCacheProvider();

    PsiServerKeyDescription getServerKeyDescription();


    /**
     * Retrieves the statistics associated to the different phases of the PSI calculation performed by this object.
     * @return a list containing a different PsiPhaseStatistics for each encryption phase
     */
    List<PsiPhaseStatistics> getStatisticList();

    /**
     * Configures the number of threads and the max lifetime of each thread used by the PsiServer.
     *
     * @param configuration containing the runtime configuration parameters
     */
    void setConfiguration(PsiThreadConfiguration configuration);

}
