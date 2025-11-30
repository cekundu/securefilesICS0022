package ee.taltech.securefiles.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name="users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank
    @Column(unique = true, nullable = false)
    private String username;

    @NotBlank
    @Column(nullable = false)
    private String passwordHash;

    @NotBlank
    @Column(name="pbkdf2_salt", nullable = false)
    private String pbkdf2Salt;

    @NotNull
    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt = LocalDateTime.now();

    @OneToMany(mappedBy = "owner", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<FileRecord> files = new ArrayList<>();

    @Column(nullable = false)
    private boolean isAdmin = false;


    // Must be public for User in AuthService
    public User() {
    }

    // ------------------------------ getters ------------------------------

    public Long getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public String getPbkdf2Salt() {
        return pbkdf2Salt;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }


    public List<FileRecord> getFiles() {
        return files;
    }

    // ------------------------------ setters ------------------------------

    public void setUsername(String username) {
        this.username = username;
    }

    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
    }

    public void setPbkdf2Salt(String pbkdf2Salt) {
        this.pbkdf2Salt = pbkdf2Salt;
    }

    public boolean isAdmin() { return isAdmin; }
    public void setAdmin(boolean admin) { isAdmin = admin; }


}
