package ee.taltech.securefiles.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.time.LocalDateTime;

@Entity
@Table(
        name = "files",
        uniqueConstraints = {
                @UniqueConstraint(columnNames = {"owner_id", "original_name"})
        }
)
public class FileRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotNull
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "owner_id", nullable = false)
    private User owner;

    @NotBlank
    @Column(name = "original_name", nullable = false)
    private String originalName;

    @NotBlank
    @Column(name = "storage_filename", nullable = false)
    private String storageFilename;

    @Column(nullable = false)
    private long size;

    @Column(name = "uploaded_at", nullable = false, updatable = false, insertable = false)
    private LocalDateTime uploadedAt;

    @NotBlank
    @Column(nullable = false, length = 128)
    private String integrityHmac; // hex or base64 encoded

    public String getIntegrityHmac() { return integrityHmac; }
    public void setIntegrityHmac(String integrityHmac) { this.integrityHmac = integrityHmac; }

    public FileRecord() {
    }

    // ------------------------------ getters ------------------------------

    public Long getId() {
        return id;
    }

    public User getOwner() {
        return owner;
    }

    public String getOriginalName() {
        return originalName;
    }

    public String getStorageFilename() {
        return storageFilename;
    }

    public long getSize() {
        return size;
    }

    public LocalDateTime getUploadedAt() {
        return uploadedAt;
    }

    // ------------------------------ setters for mutable fields ------------------------------

    public void setOwner(User owner) {
        this.owner = owner;
    }

    public void setOriginalName(String originalName) {
        this.originalName = originalName;
    }

    public void setStorageFilename(String storageFilename) {
        this.storageFilename = storageFilename;
    }

    public void setSize(long size) {
        this.size = size;
    }
}
