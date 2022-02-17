package psi.client;

import psi.PsiClientKeyDescription;
import psi.model.PsiPhaseStatistics;
import psi.model.PsiRuntimeConfiguration;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Interface that provides the methods that perform the client-side computation of the PSI for all the supported algorithms.
 * Instances of this class should be created by calling the methods in the <code>PsiClientFactory</code> class.
 * All the input and output collections are devised to work on Strings in order to facilitate the data exchange
 * between the parties and/or from external data sources.
 * Thus, the conversion of the datasets to String is required and outside the scope of this SDK.
 */
public interface PsiClient {

    /**
     * Loads and encrypts the client dataset passed as input and returns a map of encrypted elements.
     * It performs the client-side encryption of the client dataset.
     * The conversion from Set to Map is needed to assign a unique id to each entry, which links together different
     * stages of the same entry (e.g., allowing to find the clear value associated to a given server-side encrypted entry)
     * This method can be called multiple times with different portions of the client dataset, even concurrently.
     * This method should be called before the <code>loadAndEncryptClientDataset</code> method (at least for the respective entries)
     * and before calling the <code>computePsi</code> method, else the result of the PSI will be an empty set.
     *
     * @param clearClientDataset set of elements to be encrypted by the client
     * @return a Map containing for each item of the input set an entry which, as key, has an identifier of the entry
     * computed at runtime, and as value, has the client-side encryption of the item.
     * */
    Map<Long, String> loadAndEncryptClientDataset(Set<String> clearClientDataset);

    /**
     * Loads the input map, which should be the server-side encryption of the client dataset.
     * The input of this method should be passed by the server. It is referred as double encrypted client dataset because it
     * is the result of the server-side encryption of the client-side, which was also previously encrypted at the client-side
     * prior to being sent to the server to preserve the privacy of the client. Therefore, both the server and the
     * client applied encryption operations on the entries of the input map.
     * This method can be called multiple times with different portions of the client dataset, even concurrently.
     * This method should be called after the <code>loadAndEncryptClientDataset</code> method (at least for the respective entries)
     * but before calling the <code>computePsi</code> method, else the result of the PSI will be an empty set.
     *
     * @param doubleEncryptedClientDatasetMap a map containing the elements to be stored
     */
    void loadDoubleEncryptedClientDataset(Map<Long, String> doubleEncryptedClientDatasetMap);

    /**
     * Loads the input set, which should be associated to entries of the server-side encryption of the server dataset.
     * This method can be called multiple times to load different portions of the server dataset, even concurrently.
     * Depending on the specific PSI algorithm, this method might perform additional computations in addition to
     * simply loading the input set.
     *
     * This method should be called before calling the <code>computePsi</code> method,
     * else the result of the PSI will be an empty set.
     *
     * @param serverEncryptedDataset a set containing the elements to be loaded, which are associated to a portion
     */
    void loadAndProcessServerDataset(Set<String> serverEncryptedDataset);

    /**
     * Computes the actual PSI calculation by comparing the entries of the double encrypted client dataset with the
     * processed entries loaded from the server dataset.
     * @return the result of the private set intersection containing the elements present both in the server and client datasets.
     */
    Set<String> computePsi();

    PsiClientKeyDescription getClientKeyDescription();

    /**
     * Retrieves the statistics associated to the different phases of the PSI calculation performed by this object.
     * @return a list containing a different PsiPhaseStatistics for each encryption phase
     */
    List<PsiPhaseStatistics> getStatisticList();

    /**
     * Configures the number of threads and the max lifetime of each thread used by the PsiClient.
     * @param configuration containing the runtime configuration parameters
     */
    void setConfiguration(PsiRuntimeConfiguration configuration);
}
