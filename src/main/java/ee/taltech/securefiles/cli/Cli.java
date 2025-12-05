package ee.taltech.securefiles.cli;

import ee.taltech.securefiles.auth.AuthService;
import ee.taltech.securefiles.auth.Session;
import ee.taltech.securefiles.files.FileService;
import ee.taltech.securefiles.log.LoggerService;
import ee.taltech.securefiles.model.FileRecord;
import ee.taltech.securefiles.validate.InputValidator;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.io.Console;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Locale;
import java.util.Scanner;

@Component
public class Cli implements CommandLineRunner {

    private final AuthService authService;
    private final FileService fileService;
    private final InputValidator validator;
    private final LoggerService logger;
    private Scanner scannerSingleton;

    public Cli(AuthService authService, FileService fileService, InputValidator validator, LoggerService logger) {
        this.authService = authService;
        this.fileService = fileService;
        this.validator = validator;
        this.logger = logger;
    }

    @Override
    public void run(String... args) {
        scannerSingleton = new Scanner(System.in);

        // Ensure DB is up before anything else
        waitForDatabase();

        while (true) {
            System.out.println("\n=======--- secure file manager ---=======");
            System.out.println("1. Login");
            System.out.println("2. Create User");
            System.out.println("3. Admin login");
            System.out.println("0. Exit");
            System.out.println("===========-------------------===========");
            System.out.print("> ");

            String choice;
            try {
                choice = scannerSingleton.nextLine().trim();
            } catch (Exception e) {
                // stdin closed or broken
                return;
            }

            try {
                switch (choice) {
                    case "1" -> {
                        Session session = login();
                        if (session != null) fileMenu(session);
                    }
                    case "2" -> registerUser();
                    case "3" -> adminLogin();
                    case "0" -> {
                        System.out.println("Bye. °‧ 𓆝 𓆟 𓆞 ·｡");
                        return;
                    }
                    default -> System.out.println("Invalid option.");
                }
            } catch (Exception e) {
                // Do not leak stack traces or DB details
                System.out.println("Database error.");
                waitForDatabase();     // block until DB recovery, return cleanly to main menu
            }
        }
    }

    // --------------------------- user registration ---------------------------

    private void registerUser() {
        System.out.println("\n===========- create new user -===========");
        System.out.println("press 'enter' at an empty input to cancel");
        System.out.println("===========-------------------===========");

        String username;

        System.out.println("Username requirements:");
        System.out.println(" - 2 to 32 characters");
        System.out.println(" - English letters and numbers");
        System.out.println(" - Usernames are normalized to lowercase");
        System.out.println(" - No empty input (press Enter to cancel)");
        System.out.println();

        // USERNAME LOOP
        while (true) {
            System.out.print("Username: ");
            username = scannerSingleton.nextLine().trim().toLowerCase(Locale.ROOT);

            if (username.isEmpty()) {
                System.out.println("Canceled.");
                return;
            }

            try {
                authService.preCheckUsername(username);
                break;
            } catch (Exception e) {
                // This message is high-level (format / already taken), OK to show
                System.out.println("Error: " + e.getMessage());
            }
        }

        System.out.println("Password requirements:");
        System.out.println(" - At least 8 characters");
        System.out.println(" - At least one uppercase letter");
        System.out.println(" - At least one lowercase letter");
        System.out.println(" - At least one digit");
        System.out.println(" - At least one special character");
        System.out.println(" - No empty input (press Enter to cancel)");
        System.out.println();

        // PASSWORD LOOP
        char[] password = null;
        char[] confirm = null;

        while (true) {
            password = readPassword("Password: ");
            if (password.length == 0) {
                System.out.println("Canceled.");
                return;
            }

            try {
                authService.preCheckPassword(password);
            } catch (Exception e) {
                // High-level password policy text is fine to display
                System.out.println("Error: " + e.getMessage());
                Arrays.fill(password, '\0');
                continue;
            }

            confirm = readPassword("Confirm password: ");
            if (confirm.length == 0) {
                System.out.println("Canceled.");
                Arrays.fill(password, '\0');
                return;
            }

            if (!Arrays.equals(password, confirm)) {
                System.out.println("Error: Passwords do not match.");
                Arrays.fill(password, '\0');
                Arrays.fill(confirm, '\0');
                continue;
            }

            // valid and confirmed
            break;
        }

        // FINAL CREATION
        try {
            authService.registerUser(username, password);
            System.out.println("User created successfully.");
        } catch (Exception e) {
            // Should be generic or high-level (e.g. "username taken")
            System.out.println("Error: " + e.getMessage());
        } finally {
            if (password != null) Arrays.fill(password, '\0');
            if (confirm != null) Arrays.fill(confirm, '\0');
        }
    }

    // ------------------------------ login -----------------------------------

    private Session login() {
        System.out.println("\n===========------ login ------===========");
        System.out.println("press 'enter' at an empty input to cancel");
        System.out.println("===========-------------------===========");

        System.out.print("Username: ");
        String username = scannerSingleton.nextLine().trim().toLowerCase(Locale.ROOT);

        if (username.isEmpty()) {
            System.out.println("Canceled.");
            return null;
        }

        // IMPORTANT: never reveal whether username exists.
        char[] password = readPassword("Password: ");

        try {
            // AuthService.login already does the full check and logs the attempt.
            Session session = authService.login(username, password);
            return session;
        } catch (Exception e) {
            // generic message
            System.out.println("Invalid username or password.");
            return null;
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    // ------------------------ file operations menu ---------------------------

    private void fileMenu(Session session) {
        System.out.println("\nLogged in as: " + session.username());

        while (true) {
            System.out.println("\n==========-- file operations --==========");
            System.out.println("1. Encrypt file");
            System.out.println("2. Decrypt file");
            System.out.println("3. Delete file");
            System.out.println("4. List files");
            System.out.println("0. Logout");
            System.out.println("press 'enter' at an empty input to cancel");
            System.out.println("===========-------------------===========");
            System.out.print("> ");

            String choice = scannerSingleton.nextLine().trim();

            try {
                switch (choice) {
                    case "1" -> encryptMenu(session);
                    case "2" -> decryptMenu(session);
                    case "3" -> deleteMenu(session);
                    case "4" -> listFiles(session);
                    case "0" -> {
                        System.out.println("Logged out.");
                        return;
                    }
                    default -> System.out.println("Invalid option.");
                }
            } catch (Exception e) {
                // Anything that bubbles out here is treated as DB-level failure.
                System.out.println("Database error.");
                waitForDatabase();
                return;
            }
        }
    }

    // ---------------------- file operations helpers --------------------------

    private void encryptMenu(Session session) throws Exception {
        System.out.println("\n==========-- encrypt new file --==========");
        System.out.println("press 'enter' at an empty input to cancel");
        System.out.println("===========--------------------===========");

        Path source;

        // SOURCE PATH INPUT LOOP
        while (true) {
            System.out.print("Source file path: ");
            String raw = scannerSingleton.nextLine().trim();

            if (raw.isEmpty()) {
                System.out.println("Canceled.");
                return;
            }

            source = Path.of(raw);
            if (!Files.exists(source) || !Files.isRegularFile(source)) {
                System.out.println("Error: File does not exist or is not a regular file.");
                continue;
            }

            System.out.println("You entered: " + source);
            System.out.print("Press Enter to confirm, or type anything to re-enter: ");
            String confirm = scannerSingleton.nextLine().trim();

            if (!confirm.isEmpty()) {
                continue; // ask again
            }

            // path confirmed -> validate size
            try {
                long size = Files.size(source);
                validator.validateFileSize(size);
            } catch (Exception e) {
                // High-level message: "File too large" etc.
                System.out.println("Error: " + e.getMessage());
                continue; // force user to choose another file
            }
            break; // final source accepted
        }

        // ALIAS LOOP
        String alias;
        while (true) {
            System.out.print("Alias (name to store under): ");
            alias = scannerSingleton.nextLine().trim();

            if (alias.isEmpty()) {
                System.out.println("Canceled.");
                return;
            }
            try {
                validator.validateAlias(alias);
            } catch (Exception e) {
                System.out.println("Error: " + e.getMessage());
                continue;
            }

            final String aliasInput = alias;

            boolean exists = fileService.listUserFiles(session)
                    .stream()
                    .anyMatch(f -> f.getOriginalName().equals(aliasInput));
            if (!exists) {
                break;
            }

            System.out.println("Alias already exists.");
            System.out.println("Press Enter to auto-generate, or type a different alias:");
            String attempt = scannerSingleton.nextLine().trim();

            if (attempt.isEmpty()) {
                alias = resolveAliasCollision(session, aliasInput);
                System.out.println("Using auto-generated alias: " + alias);
                break;
            }

            try {
                validator.validateAlias(attempt);
                alias = attempt;

                final String aliasFinal = alias;
                boolean existsAgain = fileService.listUserFiles(session)
                        .stream()
                        .anyMatch(f -> f.getOriginalName().equals(aliasFinal));

                if (!existsAgain) break;
                System.out.println("That alias is also taken. Try again.");
            } catch (Exception e) {
                System.out.println("Error: " + e.getMessage());
            }
        }

        // PERFORM ENCRYPTION
        fileService.encryptAndStore(session, source, alias);
        System.out.println("File encrypted and stored as: " + alias);
    }

    private void decryptMenu(Session session) throws Exception {
        System.out.println("\n==========---- decrypt a file ----==========");
        System.out.println("press 'enter' at an empty input to cancel");
        System.out.println("===========----------------------===========");

        // If no files - go back to file menu immediately
        if (fileService.listUserFiles(session).isEmpty()) {
            System.out.println("You have no files to decrypt.");
            return;
        }

        String alias;
        // ALIAS LOOP
        while (true) {
            System.out.print("Alias (press Enter to cancel): ");
            alias = scannerSingleton.nextLine().trim();

            if (alias.isEmpty()) {
                System.out.println("Canceled.");
                return;
            }

            try {
                validator.validateAlias(alias);
                fileService.findRecordForUser(session, alias);   // must exist
                break;
            } catch (Exception e) {
                // no exposure whether it was invalid format/not found
                System.out.println("Invalid alias.");
            }
        }

        // INTEGRITY CHECK BEFORE ASKING OUTPUT PATH
        try {
            fileService.checkIntegrity(session, alias);
        } catch (Exception e) {
            // no internal detail
            System.out.println("Error: " + e.getMessage());
            System.out.println("This file cannot be decrypted.");
            System.out.print("Type 'delete' to remove it, or press Enter to keep it: ");

            String choice = scannerSingleton.nextLine().trim().toLowerCase(Locale.ROOT);

            if (choice.equals("delete")) {
                try {
                    fileService.secureDelete(session, alias);
                    System.out.println("File deleted.");
                } catch (Exception ex) {
                    // error generic enough
                    System.out.println("Error deleting file.");
                }
            } else {
                System.out.println("File kept.");
            }

            return;
        }

        Path target;
        // OUTPUT PATH LOOP
        while (true) {
            System.out.print("Output file path: ");
            String out = scannerSingleton.nextLine().trim();

            if (out.isEmpty()) {
                System.out.println("Canceled.");
                return;
            }
            try {
                target = Path.of(out);
                validator.validateOutputPath(target);
            } catch (Exception e) {
                System.out.println("Error: " + e.getMessage());
                continue;
            }

            System.out.println("You entered: " + target);
            System.out.print("Press Enter to confirm, or type anything to re-enter: ");
            String confirm = scannerSingleton.nextLine().trim();

            if (confirm.isEmpty()) {
                break;
            }

            // redefine out = confirm
            out = confirm;

            try {
                target = Path.of(out);
                validator.validateOutputPath(target);
                // if this passes, loop will break next iteration
            } catch (Exception e) {
                System.out.println("Error: " + e.getMessage());
            }
        }
        fileService.decryptTo(session, alias, target);
        System.out.println("File decrypted to: " + target);
    }


    private void deleteMenu(Session session) throws Exception {
        System.out.println("\n==========---- delete a file ----==========");
        System.out.println("press 'enter' at an empty input to cancel");
        System.out.println("==========-----------------------==========");

        var files = fileService.listUserFiles(session);

        if (files.isEmpty()) {
            System.out.println("You have no files to delete.");
            return;
        }

        String alias;

        while (true) {
            System.out.print("Alias: ");
            alias = scannerSingleton.nextLine().trim();

            if (alias.isEmpty()) {
                System.out.println("Canceled.");
                return;
            }

            try {
                validator.validateAlias(alias);

                if (!fileService.recordExists(session, alias)) {
                    throw new IllegalArgumentException();
                }

                break;
            } catch (Exception e) {
                System.out.println("Invalid alias.");
            }
        }

        System.out.println("You are about to delete: " + alias);
        System.out.print("Press Enter to confirm, or type anything to cancel: ");
        String confirm = scannerSingleton.nextLine().trim();

        if (!confirm.isEmpty()) {
            System.out.println("Canceled.");
            return;
        }

        fileService.secureDelete(session, alias);
        System.out.println("File deleted: " + alias);
    }

    private void listFiles(Session session) {
        System.out.println("\n==========----- list files -----==========");

        var files = fileService.listUserFiles(session);

        if (files.isEmpty()) {
            System.out.println("You have no stored files.");
            return;
        }

        System.out.println("Your files (sizes shown are encrypted sizes on disk):");
        int i = 1;
        for (var f : files) {
            System.out.println(" " + i++ + ". " + f.getOriginalName() + " (" + f.getSize() + " bytes)");
        }
    }

    // ------------------------------ utilities ------------------------------

    private char[] readPassword(String prompt) {
        Console console = System.console();
        if (console != null) {
            char[] pw = console.readPassword(prompt);
            return pw != null ? pw : new char[0];
        }
        // Fallback for IDEs (IntelliJ etc.) where System.console() is null.
        System.out.print(prompt);
        System.out.flush();

        String line = scannerSingleton.nextLine();
        return line.toCharArray();
    }

    /**
     * Resolve alias collision for a given user.
     * IMPORTANT: use the real Session instead of inventing a fake one.
     */
    private String resolveAliasCollision(Session session, String alias) {
        var existing = fileService.listUserFiles(session)
                .stream()
                .map(FileRecord::getOriginalName)
                .toList();

        if (!existing.contains(alias)) {
            return alias; // no collision
        }

        int counter = 1;
        while (true) {
            String candidate = alias + "-" + counter;
            if (!existing.contains(candidate)) {
                return candidate;
            }
            counter++;
        }
    }

    // ------------------------------ admin login ------------------------------

    private void adminLogin() {
        System.out.println("\n===========----- admin login -----===========");
        System.out.println("press 'enter' at an empty input to cancel");
        System.out.println("===========-----------------------===========");

        System.out.print("Admin username: ");
        String username = scannerSingleton.nextLine().trim().toLowerCase(Locale.ROOT);

        if (username.isEmpty()) {
            System.out.println("Canceled.");
            return;
        }

        char[] password = readPassword("Password: ");

        try {
            // no pre-checks that leak whether the user exists.
            Session session = authService.login(username, password);

            if (!authService.isAdmin(session.username())) {
                // no reveal that user exists but is not admin.
                System.out.println("Invalid username or password.");
                return;
            }
            adminMenu(session);
        } catch (Exception e) {
            System.out.println("Invalid username or password.");
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    // ------------------------------ admin operations menu ------------------------------

    private void adminMenu(Session adminSession) {
        System.out.println("\nLogged in as ADMIN: " + adminSession.username());

        while (true) {
            System.out.println("\n===========-- admin operations --===========");
            System.out.println("press 'enter' at an empty input to cancel");
            System.out.println("1. List users");
            System.out.println("2. Change own admin password");
            System.out.println("3. Delete user with all records");
            System.out.println("0. Logout");
            System.out.println("===========----------------------===========");
            System.out.print("> ");
            System.out.flush();

            String choice;
            try {
                choice = scannerSingleton.nextLine().trim();
            } catch (Exception e) {
                // stdin closed
                return;
            }

            try {
                switch (choice) {
                    case "1" -> adminListUsers();
                    case "2" -> adminChangeOwnPassword(adminSession.username());
                    case "3" -> adminDeleteUser();
                    case "0" -> {
                        System.out.println("Admin logged out.");
                        return;
                    }
                    default -> System.out.println("Invalid option.");
                }
            } catch (Exception e) {
                // generic error
                System.out.println("Error.");
            }
        }
    }

    // ------------------------------ admin operations helpers ------------------------------

    private void adminListUsers() {
        System.out.println("\n==========------ list users ------==========");
        System.out.println("press 'enter' at an empty input to cancel");
        System.out.println("==========------------------------==========");
        var users = authService.listAllUsers();
        if (users.isEmpty()) {
            System.out.println("No users in the system.");
            return;
        }

        System.out.println("ID | username - admin role");
        users.forEach(u ->
                System.out.println(
                        u.getId() + " | " + u.getUsername() + " - " + (u.isAdmin() ? "yes" : "no")
                )
        );
    }

    private void adminChangeOwnPassword(String adminUsername) {
        System.out.println("\n==========- change admin password -==========");
        System.out.println("press 'enter' at an empty input to cancel");
        System.out.println("==========-------------------------===========");

        char[] oldPassword;

        // OLD PASSWORD LOOP
        while (true) {
            oldPassword = readPassword("Old password: ");
            if (oldPassword.length == 0) {
                System.out.println("Canceled.");
                return;
            }

            try {
                authService.verifyLoginForPasswordChange(adminUsername, oldPassword);
                break; // correct old password - continue
            } catch (Exception e) {
                System.out.println("Error: " + e.getMessage());
                Arrays.fill(oldPassword, '\0');
                // loop continues and asks again
            }
        }

        // REQUIREMENTS
        System.out.println("New password requirements:");
        System.out.println(" - At least 8 characters");
        System.out.println(" - At least one uppercase letter");
        System.out.println(" - At least one lowercase letter");
        System.out.println(" - At least one digit");
        System.out.println(" - At least one special character");
        System.out.println(" - No empty input (press Enter to cancel)");
        System.out.println();

        char[] newPassword = null;
        char[] confirm = null;

        // NEW PASSWORD LOOP
        while (true) {
            newPassword = readPassword("New password: ");
            if (newPassword.length == 0) {
                System.out.println("Canceled.");
                Arrays.fill(oldPassword, '\0');
                return;
            }

            String errorMsg = null;
            try {
                authService.preCheckPassword(newPassword);
            } catch (Exception e) {
                errorMsg = e.getMessage();
            }

            if (errorMsg != null) {
                System.out.println("Error: " + errorMsg);
                Arrays.fill(newPassword, '\0');
                continue;
            }

            confirm = readPassword("Confirm new password: ");
            if (confirm.length == 0) {
                System.out.println("Canceled.");
                Arrays.fill(newPassword, '\0');
                Arrays.fill(oldPassword, '\0');
                return;
            }

            if (!Arrays.equals(newPassword, confirm)) {
                System.out.println("Error: Passwords do not match. Try again.");
                Arrays.fill(newPassword, '\0');
                Arrays.fill(confirm, '\0');
                continue;
            }
            break;
        }

        // APPLY CHANGE
        try {
            authService.adminChangeOwnPassword(adminUsername, oldPassword, newPassword);
            System.out.println("Admin password changed successfully.");
        } finally {
            Arrays.fill(oldPassword, '\0');
            Arrays.fill(newPassword, '\0');
            Arrays.fill(confirm, '\0');
        }
    }

    private void adminDeleteUser() {
        System.out.println("\n==========-- delete user --==========");
        System.out.println("press 'enter' at an empty input to cancel");
        System.out.println("==========-----------------==========");

        // USERNAME LOOP
        String username;
        while (true) {
            System.out.print("Target username: ");
            username = scannerSingleton.nextLine().trim().toLowerCase(Locale.ROOT);

            if (username.isEmpty()) {
                System.out.println("Canceled.");
                return;
            }

            if (!authService.userExists(username)) {
                System.out.println("No such user.");
                continue;
            }

            if (authService.isAdmin(username)) {
                System.out.println("Error: Cannot delete an admin account.");
                return;
            }

            break; // valid username
        }

        // FETCH USER and FILES
        var user = authService.getUser(username);
        var files = fileService.listFilesByUserId(user.getId());

        System.out.println("\nUser summary:");
        System.out.println("  Username: " + user.getUsername());
        System.out.println("  ID      : " + user.getId());
        System.out.println("  Files   : " + files.size());

        System.out.println();
        System.out.println("Deleting this user will permanently remove:");
        System.out.println(" - All encrypted files");
        System.out.println(" - All DB records");
        System.out.println();

        // REQUIRED CONFIRMATION
        System.out.print("Type 'delete' to remove this user, or press Enter to cancel: ");
        String confirm = scannerSingleton.nextLine().trim();

        if (!confirm.equalsIgnoreCase("delete")) {
            System.out.println("Canceled.");
            return;
        }

        // DELETE ALL FILES
        for (var f : files) {
            try {
                fileService.secureDeleteRaw(user.getId(), f);
            } catch (Exception e) {
                System.out.println("Warning: Could not delete file: " + f.getOriginalName());
            }
        }

        // DELETE DIR AND USER
        fileService.deleteUserDirectory(user.getId());
        authService.deleteUser(username);

        System.out.println("User '" + username + "' and all their files were deleted.");
    }

    // ------------------------------ DB availability ------------------------------

    private void waitForDatabase() {
        while (true) {
            try {
                authService.healthCheck();   // lightweight query
                return; // DB is healthy, continue
            } catch (Exception e) {
                logger.log("db_unreachable", null, "error=" + e.getClass().getSimpleName());
                System.out.println("Database unavailable. Retrying...");
                try {
                    Thread.sleep(2000);
                } catch (InterruptedException ignored) {
                }
            }
        }
    }
}
