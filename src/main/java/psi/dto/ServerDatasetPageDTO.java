package psi.dto;

import java.util.List;

public class ServerDatasetPageDTO {

    private Integer page;

    private Integer size;

    private Integer entries;

    private Boolean last;

    private Integer totalPages;

    private Integer totalEntries;

    private List<String> content;

    public Integer getPage() {
        return page;
    }

    public void setPage(Integer page) {
        this.page = page;
    }

    public Integer getSize() {
        return size;
    }

    public void setSize(Integer size) {
        this.size = size;
    }

    public Integer getEntries() {
        return entries;
    }

    public void setEntries(Integer entries) {
        this.entries = entries;
    }

    public Boolean isLast() {
        return last;
    }

    public void setLast(Boolean last) {
        this.last = last;
    }

    public Integer getTotalPages() {
        return totalPages;
    }

    public void setTotalPages(Integer totalPages) {
        this.totalPages = totalPages;
    }

    public Integer getTotalEntries() {
        return totalEntries;
    }

    public void setTotalEntries(Integer totalEntries) {
        this.totalEntries = totalEntries;
    }

    public List<String> getContent() {
        return content;
    }

    public void setContent(List<String> content) {
        this.content = content;
    }

    @Override
    public String toString() {
        return "ServerDatasetPageDTO{" +
                "page=" + page +
                ", size=" + size +
                ", entries=" + entries +
                ", last=" + last +
                ", totalPages=" + totalPages +
                ", totalEntries=" + totalEntries +
                ", content=" + content +
                '}';
    }
}
