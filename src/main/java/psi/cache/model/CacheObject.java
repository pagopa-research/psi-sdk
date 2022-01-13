package psi.cache.model;

public interface CacheObject {

    public String getBase64Representation();

    public void initializeFromBase64Representation(String base64);

}
