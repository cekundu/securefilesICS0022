package ee.taltech.securefiles.auth;

import ee.taltech.securefiles.db.UserRepository;
import ee.taltech.securefiles.log.LoggerService;
import ee.taltech.securefiles.model.User;
import ee.taltech.securefiles.validate.InputValidator;
import jakarta.transaction.Transactional;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.List;
import java.util.Locale;

@Service
public class AuthService {

    private static final String PBKDF2_ALGO = "PBKDF2WithHmacSHA256";
    private static final int PBKDF2_ITERATIONS = 210_000;
    private static final int PBKDF2_KEY_LENGTH_BITS = 256;
    private static final int SALT_LENGTH_BYTES = 16;

    private final UserRepository userRepository;
    private final SecureRandom secureRandom = new SecureRandom();
    private final InputValidator validator;
    private final LoggerService logger;

    public AuthService(UserRepository userRepository, InputValidator validator, LoggerService logger) {
        this.userRepository = userRepository;
        this.validator = validator;
        this.logger = logger;
    }

    // ------------------------------ regular user registration / login ------------------------------

    @Transactional
    public void registerUser(String username, char[] password) {

        String normalized = username.toLowerCase(Locale.ROOT);

        validator.validateUsername(normalized);

        if (userRepository.findByUsername(normalized).isPresent()) {
            throw new IllegalArgumentException("Username is already taken.");
        }

        validator.validatePassword(password);

        String saltBase64 = generateSaltBase64();
        String hashBase64 = hashPassword(password, saltBase64);

        User user = new User();
        user.setUsername(normalized);
        user.setPbkdf2Salt(saltBase64);
        user.setPasswordHash(hashBase64);
        user.setAdmin(false); // normal users are never admin

        logger.log("user_create", user.getId(), "username=" + normalized + " admin=false" );
        userRepository.save(user);
    }

    @Transactional
    public Session login(String username, char[] password) {
        String normalized = username.toLowerCase(Locale.ROOT);

        var userOpt = userRepository.findByUsername(normalized);
        if (userOpt.isEmpty()) {
            logger.log("login_attempt", null, "failed username=" + normalized);
            throw new IllegalArgumentException("Invalid username or password.");
        }

        User user = userOpt.get();

        if (!verifyPassword(password, user)) {
            logger.log("login_attempt", user.getId(), "failed username=" + normalized);
            throw new IllegalArgumentException("Invalid username or password.");
        }

        SecretKey encryptionKey = deriveEncryptionKey(password, user.getPbkdf2Salt());

        logger.log("login_attempt", user.getId(), "success username=" + normalized);

        if (user.isAdmin()) {
            logger.log("admin_login_success", user.getId(), "");
        }

        return new Session(user.getId(), user.getUsername(), encryptionKey);
    }

    // ------------------------------ admin helpers ------------------------------

    public List<User> listAllUsers() {
        return userRepository.findAll();
    }

    @Transactional
    public void adminChangeOwnPassword(String adminUsername, char[] oldPassword, char[] newPassword) {
        String normalized = adminUsername.toLowerCase(Locale.ROOT);

        User user = userRepository.findByUsername(normalized)
                .orElseThrow(() -> new IllegalArgumentException("Admin not found."));

        if (!user.isAdmin()) {
            throw new SecurityException("Not an admin.");
        }

        if (!verifyPassword(oldPassword, user)) {
            throw new IllegalArgumentException("Old password is incorrect.");
        }

        validator.validatePassword(newPassword);

        String newSalt = generateSaltBase64();
        String newHash = hashPassword(newPassword, newSalt);

        user.setPbkdf2Salt(newSalt);
        user.setPasswordHash(newHash);

        userRepository.save(user);
        logger.log("admin_password_change", user.getId(), "");
    }

    // ------------------------------ existing helpers ------------------------------

    private String generateSaltBase64() {
        byte[] salt = new byte[SALT_LENGTH_BYTES];
        secureRandom.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    private String hashPassword(char[] password, String saltBase64) {
        byte[] salt = Base64.getDecoder().decode(saltBase64);
        byte[] keyBytes = pbkdf2(password, salt);
        return Base64.getEncoder().encodeToString(keyBytes);
    }

    private boolean verifyPassword(char[] password, User user) {
        String recomputedHash = hashPassword(password, user.getPbkdf2Salt());
        byte[] a = Base64.getDecoder().decode(recomputedHash);
        byte[] b = Base64.getDecoder().decode(user.getPasswordHash());
        return constantTimeEquals(a, b);
    }

    private SecretKey deriveEncryptionKey(char[] password, String saltBase64) {
        byte[] salt = Base64.getDecoder().decode(saltBase64);
        byte[] keyBytes = pbkdf2(password, salt);
        return new SecretKeySpec(keyBytes, "AES");
    }

    private byte[] pbkdf2(char[] password, byte[] salt) {
        try {
            PBEKeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, PBKDF2_KEY_LENGTH_BITS);
            SecretKeyFactory skf = SecretKeyFactory.getInstance(PBKDF2_ALGO);
            return skf.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            // treat as generic internal error
            throw new IllegalStateException("Internal key derivation error");
        }
    }


    public void preCheckUsername(String username) {
        String normalized = username.toLowerCase(Locale.ROOT);

        validator.validateUsername(normalized);

        if (userRepository.findByUsername(normalized).isPresent()) {
            throw new IllegalArgumentException("Username already exists.");
        }
    }

    public boolean userExists(String username) {
        String normalized = username.toLowerCase(Locale.ROOT);
        return userRepository.findByUsername(normalized).isPresent();
    }

    public void preCheckPassword(char[] password) {
        validator.validatePassword(password);
    }

    private boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return false;
        }
        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= (a[i] ^ b[i]);
        }
        return result == 0;
    }

    public void verifyLoginForPasswordChange(String username, char[] oldPassword) {
        String normalized = username.toLowerCase(Locale.ROOT);

        var userOpt = userRepository.findByUsername(normalized);
        if (userOpt.isEmpty()) {
            throw new IllegalArgumentException("No such user.");
        }
        User user = userOpt.get();

        if (!verifyPassword(oldPassword, user)) {
            throw new IllegalArgumentException("Old password incorrect.");
        }
    }



    // ------------------------------ admin ------------------------------

    public boolean isAdmin(String username) {
        String normalized = username.toLowerCase(Locale.ROOT);
        return userRepository.findByUsername(normalized)
                .map(User::isAdmin)
                .orElse(false);
    }

    @Transactional
    public void healthCheck() {
        userRepository.count();
    }

    public User getUser(String username) {
        return userRepository.findByUsername(username.toLowerCase(Locale.ROOT))
                .orElseThrow(() -> new IllegalArgumentException("User not found."));
    }

    @Transactional
    public void deleteUser(String username) {
        var user = getUser(username);
        userRepository.delete(user);

        logger.log("delete_user", user.getId(), "username=" + username);
    }
}
