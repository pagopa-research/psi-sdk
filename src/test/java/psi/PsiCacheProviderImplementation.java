package psi;

import psi.cache.PsiCacheProvider;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

public class PsiCacheProviderImplementation implements PsiCacheProvider {

    private Map<String, String> cache = new ConcurrentHashMap<>();

    public Optional<String> get(String key){
        String output = cache.get(key);
        if (output == null)
            return Optional.empty();
        else
            return Optional.of(output);
    }
    public void put(String key, String value){
        cache.putIfAbsent(key, value);
    }

    public long size (){
        return cache.size();
    }
}