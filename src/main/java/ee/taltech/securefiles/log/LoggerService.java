package ee.taltech.securefiles.log;

import org.springframework.stereotype.Component;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;

@Component
public class LoggerService {

    private final Path logFile = Path.of("logs/audit.log");
    private final Set<PosixFilePermission> dirPerms =
            PosixFilePermissions.fromString("rwx------");
    private final Set<PosixFilePermission> filePerms =
            PosixFilePermissions.fromString("rw-------");

    public LoggerService() {
        secureSetup();
    }

    private void secureSetup() {
        try {
            Path dir = logFile.getParent();

            if (!Files.exists(dir)) {
                Files.createDirectories(dir);
            }

            // directory permission
            try {
                Files.setPosixFilePermissions(dir, dirPerms);
            } catch (Exception ignored) {
            }

            if (!Files.exists(logFile)) {
                Files.createFile(logFile);
            }

            // enforce file permission
            try {
                Files.setPosixFilePermissions(logFile, filePerms);
            } catch (Exception ignored) {
                // non-POSIX FS
            }

        } catch (Exception e) {
            System.err.println("FATAL: cannot initialize audit logging: " + e.getMessage());
        }
    }

    public synchronized void log(String event, Long userId, String details) {
        String ts = java.time.Instant.now().toString();
        String line = String.format(
                "{\"ts\":\"%s\",\"event\":\"%s\",\"userId\":%s,\"details\":\"%s\"}%n",
                ts, event, userId, escape(details)
        );

        try {
            Files.writeString(
                    logFile,
                    line,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.APPEND
            );

            // reapply perms in case of FS behavior / external tampering
            try {
                Files.setPosixFilePermissions(logFile, filePerms);
            } catch (Exception ignored) {}

        } catch (Exception e) {
            System.err.println("FATAL: cannot write audit log: " + e.getMessage());
        }
    }

    private String escape(String s) {
        return s.replace("\"", "\\\"");
    }
}
