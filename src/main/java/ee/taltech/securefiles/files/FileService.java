package ee.taltech.securefiles.files;

import ee.taltech.securefiles.auth.Session;
import ee.taltech.securefiles.db.FileRecordRepository;
import ee.taltech.securefiles.db.UserRepository;
import ee.taltech.securefiles.log.LoggerService;
import ee.taltech.securefiles.model.FileRecord;
import ee.taltech.securefiles.model.User;
import ee.taltech.securefiles.crypto.CryptoService;
import ee.taltech.securefiles.validate.InputValidator;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.util.*;
@Service
public class FileService {

    private final Path rootDir;
    private final CryptoService cryptoService;
    private final FileRecordRepository fileRecordRepository;
    private final UserRepository userRepository;
    private final InputValidator validator;
    private final LoggerService logger;

    public FileService(
            @Value("${securefiles.data-root:data}") String rootDir,
            CryptoService cryptoService,
            FileRecordRepository fileRecordRepository,
            UserRepository userRepository,
            InputValidator validator,
            LoggerService logger
    ) {
        this.rootDir = Paths.get(rootDir).toAbsolutePath().normalize();
        this.cryptoService = cryptoService;
        this.fileRecordRepository = fileRecordRepository;
        this.userRepository = userRepository;
        this.validator = validator;
        this.logger = logger;
    }

    // PUBLIC QUERIES
    public List<FileRecord> listFilesByUserId(Long userId) {
        return fileRecordRepository.findAllByOwnerId(userId);
    }

    public List<FileRecord> listUserFiles(Session session) {
        return fileRecordRepository.findAllByOwnerId(session.userId());
    }

    // ENCRYPTION

    /**
     * Encrypt and store a file for the current user.
     * originalName = user-chosen alias
     */
    public void encryptAndStore(Session session, Path sourcePath, String originalName) throws IOException {
        requireUserRole(session);  // rejects admin sessions; rejects null

        // VALIDATE SOURCE PATH SAFELY
        if (!Files.isRegularFile(sourcePath)) {
            throw new IllegalArgumentException("Source path is not a regular file.");
        }

        validator.validateAlias(originalName);

        Path userDir = ensureUserDir(session);

        // Generate an unguessable random filename for storage.
        String storageFilename = UUID.randomUUID().toString() + ".enc";
        Path destPath = userDir.resolve(storageFilename).normalize();

        // Strong boundary check
        ensureUnderDirectory(destPath, userDir);

        long plaintextSize = Files.size(sourcePath);
        validator.validateFileSize(plaintextSize);

        // ENC + AUTH
        byte[] plaintext = Files.readAllBytes(sourcePath);
        byte[] ciphertext = cryptoService.encrypt(plaintext, session.encryptionKey());

        String integrityHmac = computeHmac(ciphertext, session.encryptionKey());

        // WRITE ENC DATA TO DISK
        Files.write(destPath, ciphertext,
                StandardOpenOption.CREATE_NEW,
                StandardOpenOption.WRITE);

        applyStrictPermissions(destPath);

        // PERSIST DB RECORD
        User owner = userRepository.findById(session.userId())
                .orElseThrow(() -> new IllegalStateException("Session user missing."));

        FileRecord record = new FileRecord();
        record.setOwner(owner);
        record.setOriginalName(originalName);
        record.setStorageFilename(storageFilename);
        record.setSize(ciphertext.length);
        record.setIntegrityHmac(integrityHmac);

        logger.log("encrypt", session.userId(), "alias=" + originalName + " storage=" + originalName + " size_bytes=" + record.getSize());


        fileRecordRepository.save(record);
    }

    // ------------------------------ decryption ------------------------------

    public void decryptTo(Session session, String originalName, Path outputPath) throws IOException {
        validator.validateAlias(originalName);
        validator.validateOutputPath(outputPath);

        // Prevent attackers from forcing dumps into the user storage directory.
        ensureNotInsideRoot(outputPath);

        FileRecord record = findOwnedRecordOrThrow(session, originalName);

        Path userDir = getUserDir(session);
        Path sourcePath = userDir.resolve(record.getStorageFilename()).normalize();
        ensureUnderDirectory(sourcePath, userDir);

        if (!Files.isRegularFile(sourcePath)) {
            throw new IllegalStateException("Encrypted file missing.");
        }

        byte[] ciphertext = Files.readAllBytes(sourcePath);

        // Integrity check via stored HMAC
        String stored = record.getIntegrityHmac();
        if (stored == null || stored.isBlank()) {
            // this case should never happen unless DB corruption occurs;
            // disallow decryption if missing.
            throw new SecurityException("Missing integrity data; cannot decrypt.");
        }

        String recalculated = computeHmac(ciphertext, session.encryptionKey());

        if (!MessageDigest.isEqual(
                Base64.getDecoder().decode(stored),
                Base64.getDecoder().decode(recalculated)
        )) {
            throw new SecurityException("Integrity check failed.");
        }

        // Decrypt only after integrity success
        byte[] plaintext = cryptoService.decrypt(ciphertext, session.encryptionKey());

        Path parentDir = outputPath.toAbsolutePath().normalize().getParent();
        if (parentDir != null) {
            Files.createDirectories(parentDir);
        }

        logger.log("decrypt", session.userId(), "alias=" + originalName + " storage=" + originalName + " size_bytes=" + record.getSize());

        Files.write(outputPath, plaintext,
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING,
                StandardOpenOption.WRITE);
        applyStrictPermissions(outputPath);
    }

    // ------------------------------ DELETE ------------------------------

    /**
     * Securely delete a file owned by current session.
     */
    public void secureDelete(Session session, String originalName) throws IOException {
        validator.validateAlias(originalName);

        FileRecord record = findOwnedRecordOrThrow(session, originalName);

        Path userDir = getUserDir(session);
        Path filePath = userDir.resolve(record.getStorageFilename()).normalize();
        ensureUnderDirectory(filePath, userDir);

        wipeAndDelete(filePath, record.getSize());

        logger.log("delete", session.userId(), "alias=" + originalName + " storage=" + originalName + " size_bytes=" + record.getSize());

        fileRecordRepository.delete(record);
    }

    /**
     * Used by adminDeleteUser: bypasses session + alias logic.
     * COMMENT: strong boundary checks preserved.
     */
    public void secureDeleteRaw(Long userId, FileRecord record) throws IOException {
        Path userDir = rootDir.resolve(String.valueOf(userId)).normalize();
        Path path = userDir.resolve(record.getStorageFilename()).normalize();
        ensureUnderDirectory(path, userDir);

        wipeAndDelete(path, record.getSize());

        fileRecordRepository.delete(record);
    }

    // ------------------------------ INTERNAL DELETE HELPER ------------------------------
    private void wipeAndDelete(Path path, long size) throws IOException {
        if (Files.exists(path) && Files.isRegularFile(path)) {

            // Overwrite if size > 0
            if (size > 0) {
                byte[] zeros = new byte[(int) Math.min(size, 1024 * 1024)];

                try (var channel = java.nio.channels.FileChannel.open(
                        path, StandardOpenOption.WRITE)) {

                    long remaining = size;
                    while (remaining > 0) {
                        int toWrite = (int) Math.min(zeros.length, remaining);
                        channel.write(java.nio.ByteBuffer.wrap(zeros, 0, toWrite));
                        remaining -= toWrite;
                    }
                    channel.force(true);
                }
            }
            Files.delete(path);
        }
    }

    // ------------------------------ INTEGRITY CHECK (used by CLI before decrypt) ------------------------------

    public void checkIntegrity(Session session, String alias) throws IOException {
        FileRecord record = findOwnedRecordOrThrow(session, alias);

        Path userDir = getUserDir(session);
        Path sourcePath = userDir.resolve(record.getStorageFilename()).normalize();
        ensureUnderDirectory(sourcePath, userDir);

        byte[] ciphertext = Files.readAllBytes(sourcePath);

        // GCM integrity check, redundant with HMAC.
        try {
            cryptoService.decrypt(ciphertext, session.encryptionKey());
        } catch (Exception e) {
            throw new IllegalArgumentException("Integrity check failed.");
        }
    }

    // ------------------------------ LOW-LEVEL HELPERS ------------------------------

    private String computeHmac(byte[] ciphertext, SecretKey key) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec spec = new SecretKeySpec(key.getEncoded(), "HmacSHA256");
            mac.init(spec);
            return Base64.getEncoder().encodeToString(mac.doFinal(ciphertext));
        } catch (Exception e) {
            // COMMENT: ok — generic failure only
            throw new IllegalStateException("Integrity HMAC computation failed");
        }
    }

    private Path ensureUserDir(Session session) throws IOException {
        Path userDir = getUserDir(session);
        if (!Files.exists(userDir)) {
            try {
                Set<PosixFilePermission> perms =
                        PosixFilePermissions.fromString("rwx------");
                Files.createDirectories(userDir, PosixFilePermissions.asFileAttribute(perms));
            } catch (UnsupportedOperationException e) {
                Files.createDirectories(userDir);
            }
        }
        return userDir;
    }

    public void deleteUserDirectory(Long userId) {
        Path userDir = rootDir.resolve(String.valueOf(userId)).normalize();
        try {
            if (Files.exists(userDir)) {
                Files.walk(userDir)
                        .sorted(Comparator.reverseOrder())
                        .forEach(p -> {
                            try { Files.deleteIfExists(p); }
                            catch (IOException ignored) {}
                        });
            }
        } catch (IOException ignored) {}

        logger.log("delete_user_directory", userId, "");
    }

    public FileRecord findRecordForUser(Session session, String alias) {
        return fileRecordRepository
                .findByOwnerIdAndOriginalName(session.userId(), alias)
                .orElseThrow(() -> new IllegalArgumentException("Alias not found."));
    }

    private Path getUserDir(Session session) {
        return rootDir.resolve(String.valueOf(session.userId())).normalize();
    }

    /**
     * Hard boundary enforcement: prevents symlink tricks and traversal.
     */
    private void ensureUnderDirectory(Path target, Path parent) {
        try {
            Path realParent = parent.toRealPath();
            Path realTarget = target.toRealPath(LinkOption.NOFOLLOW_LINKS);

            if (!realTarget.startsWith(realParent)) {
                throw new SecurityException("Path escapes user directory.");
            }

        } catch (NoSuchFileException e) {
            // COMMENT: destination might not exist yet → fallback to normalized check
            Path normParent = parent.normalize().toAbsolutePath();
            Path normTarget = target.normalize().toAbsolutePath();

            if (!normTarget.startsWith(normParent)) {
                throw new SecurityException("Path escapes user directory.");
            }

        } catch (IOException e) {
            throw new IllegalStateException("Failed path boundary check.");
        }
    }

    private void applyStrictPermissions(Path path) {
        try {
            Set<PosixFilePermission> perms =
                    PosixFilePermissions.fromString("rw-------");
            Files.setPosixFilePermissions(path, perms);
        } catch (UnsupportedOperationException ignored) {
            // expected on Windows
        } catch (IOException e) {
            throw new IllegalStateException("Failed to set secure permissions.");
        }
    }

    private void ensureNotInsideRoot(Path out) {
        Path normOut = out.toAbsolutePath().normalize();
        Path normRoot = rootDir.toAbsolutePath().normalize();

        if (normOut.startsWith(normRoot)) {
            throw new SecurityException("Output path cannot be inside securefiles storage.");
        }
    }

    public boolean recordExists(Session session, String alias) {
        return fileRecordRepository
                .findByOwnerIdAndOriginalName(session.userId(), alias)
                .isPresent();
    }

    private FileRecord findOwnedRecordOrThrow(Session session, String originalName) {
        return fileRecordRepository
                .findByOwnerIdAndOriginalName(session.userId(), originalName)
                .orElseThrow(() ->
                        new IllegalArgumentException("File not found: " + originalName));
    }

    /**
     * Rejects admins and null sessions. Important.
     */
    private void requireUserRole(Session session) {
        if (session == null) {
            throw new SecurityException("Not authenticated.");
        }

        boolean isAdmin = userRepository.findById(session.userId())
                .map(User::isAdmin)
                .orElse(false);

        if (isAdmin) {
            throw new SecurityException("Admins cannot perform file operations.");
        }
    }
}