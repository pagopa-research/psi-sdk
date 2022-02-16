package psi;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Support class that checks whether the computed psi is a correct intersection.
 */
class PsiValidationHelper {

    private static final Logger log = LoggerFactory.getLogger(PsiValidationHelper.class);

    public static Set<String> computeNaiveIntersection(Set<String> serverDataset, Map<Long, String> clientDatasetMap) {
        Set<String> clientDataset = new HashSet<>(clientDatasetMap.values());
        return computeNaiveIntersection(serverDataset, clientDataset);
    }

    private static Set<String> computeNaiveIntersection(Set<String> serverDataset, Set<String> clientDataset) {
        Set<String> smallerSet = new HashSet<>();
        Set<String> largerSet;
        if (serverDataset.size() < clientDataset.size()) {
            smallerSet.addAll(serverDataset);
            largerSet = clientDataset;
        } else {
            smallerSet.addAll(clientDataset);
            largerSet = serverDataset;
        }
        smallerSet.retainAll(largerSet);
        return smallerSet;
    }

    static boolean validateResult(Set<String> serverDataset, Set<String> clientDataset, Set<String> psiSet) {

        if (psiSet == null || serverDataset == null || clientDataset == null) {
            log.error("Result is null...Have you run the PSI algorithm");
            return false;
        }

        Set<String> validationSet = computeNaiveIntersection(serverDataset, clientDataset);

        int sizeValidationSet = validationSet.size();
        int sizeResultSet = psiSet.size();

        boolean ret = true;
        if (sizeResultSet != sizeValidationSet) {
            log.error("Sets with different cardinality:\n\texpected = {}\n\tactual = {}",sizeValidationSet,sizeResultSet);
            ret = false;
        }

        if (sizeResultSet > 0) {
            boolean hasCommon = validationSet.removeAll(psiSet);
            if (!hasCommon) {
                log.error("Sets with same cardinality but no items in common");
                ret = false;
            }

            if (validationSet.size() != 0) {
                log.error("Sets with same cardinality but some items in common");
                ret = false;
            }
        }
        return ret;
    }

}
