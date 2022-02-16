package psi.client;

import psi.PsiClientKeyDescription;
import psi.model.PsiPhaseStatistics;
import psi.model.PsiRuntimeConfiguration;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * This interface exposes the client APIs required to calculate psi regardless of the algorithm used.
 * Note: all the input and output collections are devised to work on Strings in order to facilitate the exchanges
 * between the parties while hiding the complexity od the implementations. Thus, if the domain of the psi is different
 * from String, it has to be previously converted.
 */
public interface PsiClient {

    /**
     * Loads, encrypts and returns the input element set. It is used to encrypt the clear client dataset. During the encryption,
     * each processed element is associated to a unique key to be used during the next phases to link the different
     * stages of each value.
     * @param clearClientDataset set of elements to be encrypted by the client
     * @return a Map containing the encrypted input dataset as values, each one associated to a unique key computed at runtime
     */
    Map<Long, String> loadAndEncryptClientDataset(Set<String> clearClientDataset);

    /**
     * Loads the input map into the PsiClient instance. It is used to store locally the encrypted client dataset, double
     * encrypted by the server. The stored value are used by the client to compute the psi.
     * @param doubleEncryptedClientDatasetMap a map containing the elements to be stored
     */
    void loadDoubleEncryptedClientDataset(Map<Long, String> doubleEncryptedClientDatasetMap);

    /**
     * Loads the input set into the PsiClient instance. Depending on the algorithm implementing the PsiClient, this
     * method should perform additional computations before storing it. It is used to store locally the server encrypted
     * dataset, used by the client to compute the psi.
     * @param serverEncryptedDataset a set containing the elements to be stored
     */
    void loadAndProcessServerDataset(Set<String> serverEncryptedDataset);

    /**
     * Computes the psi on the server and client datasets returning the resulting intersection.
     * @return the result of the private set intersection containing the elements present both in the server and client datasets.
     */
    Set<String> computePsi();

    PsiClientKeyDescription getClientKeyDescription();

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
