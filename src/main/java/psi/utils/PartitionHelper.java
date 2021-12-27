package psi.utils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class PartitionHelper {

    public static <T, K> List<Map<T,K>> partitionMap(Map<T,K> map, int numPartitions){
        if (map == null) {
            throw new NullPointerException("The map must not be null");
        }

        if(numPartitions <= 0)
            throw new IllegalArgumentException("'numPartitions' must be greater than 0");

        List<T> list = new ArrayList<>(map.keySet());
        List<Map<T,K>> partitions = new ArrayList<>(numPartitions);
        int size = list.size();

        int partitionSize = (int) Math.ceil((double)size/numPartitions);
        for(int i = 0; i < numPartitions; i++){
            int from = Math.min(i * partitionSize, size);
            int to = Math.min((i + 1) * partitionSize, size);
            Map<T,K> tmpMap = new HashMap<>();
            for(T elem : list.subList(from, to))
                tmpMap.put(elem, map.get(elem));
            partitions.add(tmpMap);
        }
        return partitions;
    }
}
