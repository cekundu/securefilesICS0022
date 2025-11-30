package ee.taltech.securefiles.validate;

import org.springframework.stereotype.Component;

import java.nio.file.Path;

@Component
public class InputValidator {

    public void validateUsername(String username) {
        if (username == null || username.isBlank()) {
            throw new IllegalArgumentException("Username must not be empty.");
        }
        if (!username.matches("[A-Za-z0-9][A-Za-z0-9_-]{1,31}")) {
            throw new IllegalArgumentException("Invalid username format.");
        }
    }

    public void validateAlias(String alias) {
        if (alias == null || alias.isBlank()) {
            throw new IllegalArgumentException("Alias must not be empty.");
        }
        if (!alias.matches("[A-Za-z0-9._-]{1,64}")) {
            throw new IllegalArgumentException("Alias contains forbidden characters.");
        }
        if (alias.startsWith(".") || alias.endsWith(".")) {
            throw new IllegalArgumentException("Alias cannot start or end with a dot.");
        }
        if (alias.startsWith("-")) {
            throw new IllegalArgumentException("Alias cannot start with '-'.");
        }
        if (alias.contains("..")) {
            throw new IllegalArgumentException("Alias cannot contain '..'.");
        }
    }

    private static final long MAX_FILE_SIZE = 50L * 1024 * 1024;

    public void validateFileSize(long size) {
        if (size <= 0) {
            throw new IllegalArgumentException("File is empty.");
        }
        if (size > MAX_FILE_SIZE) {
            throw new IllegalArgumentException("File too large (max 50 MB).");
        }
    }

    public void validateOutputPath(Path path) {
        if (path == null) {
            throw new IllegalArgumentException("Output path cannot be null.");
        }

        Path norm = path.toAbsolutePath().normalize();
        String name = norm.getFileName() != null ? norm.getFileName().toString() : "";

        if (name.isBlank()) {
            throw new IllegalArgumentException("Output filename invalid.");
        }

        // forbid control chars
        if (name.chars().anyMatch(ch -> ch < 32)) {
            throw new IllegalArgumentException("Output filename contains forbidden characters.");
        }

        if (name.startsWith(".") || name.endsWith(".")) {
            throw new IllegalArgumentException("Output filename cannot start or end with a dot.");
        }

        if (norm.getParent() == null) {
            throw new IllegalArgumentException("Output path must include a parent directory.");
        }

        // safe traversal check
        for (Path part : norm) {
            if (part.toString().equals("..")) {
                throw new IllegalArgumentException("Output path cannot escape directories.");
            }
        }
    }

    public void validatePassword(char[] password) {
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("Password cannot be empty.");
        }

        int len = password.length;

        boolean hasUpper = false;
        boolean hasLower = false;
        boolean hasDigit = false;
        boolean hasSpecial = false;

        for (char c : password) {
            if (Character.isUpperCase(c)) hasUpper = true;
            else if (Character.isLowerCase(c)) hasLower = true;
            else if (Character.isDigit(c)) hasDigit = true;
            else hasSpecial = true; // any non-alnum counts
        }

        StringBuilder errors = new StringBuilder();

        if (len < 8) errors.append(" - At least 8 characters\n");
        if (len > 128) errors.append(" - Password too long (max 128)\n");
        if (!hasUpper) errors.append(" - Must contain at least one uppercase letter\n");
        if (!hasLower) errors.append(" - Must contain at least one lowercase letter\n");
        if (!hasDigit) errors.append(" - Must contain at least one digit\n");
        if (!hasSpecial) errors.append(" - Must contain at least one special character\n");

        if (errors.length() > 0) {
            throw new IllegalArgumentException("Password does not meet the requirements:\n" + errors);
        }
    }
}
