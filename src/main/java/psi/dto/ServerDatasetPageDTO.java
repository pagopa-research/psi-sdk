package psi.dto;

import java.util.List;

public class ServerDatasetPageDTO {

    private int page;

    private int size;

    private int entries;

    private boolean last;

    private int totalPages;

    private int totalEntries;

    private List<String> content;

    public int getPage() {
        return page;
    }

    public void setPage(int page) {
        this.page = page;
    }

    public int getSize() {
        return size;
    }

    public void setSize(int size) {
        this.size = size;
    }

    public int getEntries() {
        return entries;
    }

    public void setEntries(int entries) {
        this.entries = entries;
    }

    public boolean isLast() {
        return last;
    }

    public void setLast(boolean last) {
        this.last = last;
    }

    public int getTotalPages() {
        return totalPages;
    }

    public void setTotalPages(int totalPages) {
        this.totalPages = totalPages;
    }

    public int getTotalEntries() {
        return totalEntries;
    }

    public void setTotalEntries(int totalEntries) {
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
