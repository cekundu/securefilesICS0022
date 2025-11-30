# SecureFiles — Encrypted Multi-User File Storage (CLI)

SecureFiles is a Spring Boot–based command-line application that provides:

- Per-user AES-GCM encryption  
- HMAC integrity protection  
- Strict per-user directories  
- Admin account with limited functions  
- Logging of all security-relevant events  
- PostgreSQL persistence (via Docker or local installation)

The system stores *only encrypted binaries* on disk and enforces alias uniqueness per user.  
No plaintext ever touches the database.

## Features

### For users
- Register with PBKDF2-HMAC-SHA256 password hashing  
- Login with constant-time password verification  
- Encrypt arbitrary files (≤ 50 MB)  
- Decrypt only their own files  
- Integrity verification via HMAC and AES-GCM authentication tag  
- Secure deletion (overwrite + delete)

### For admin
- Admin login  
- List all users  
- Change own admin password  
- Delete users (cascade: encrypted files + directory + DB entries)

### Security
- AES-256-GCM encryption  
- Per-user symmetric key derived from password  
- HMAC-SHA256 over ciphertext stored in DB  
- POSIX file permissions enforced (700 user dirs, 600 files)  
- Prevents directory traversal and symbolic link escape  
- No sensitive logs (only metadata)

## Components
- Java 21+, Spring Boot 3.5  
- PostgreSQL 16  
- Liquibase for schema migrations  
- Docker (optional)  
- CLI frontend only (no web UI)

## Documentation
- See **INSTALL.md** for installation and deployment
- `securefiles.sh` is the recommended launcher for normal usage
