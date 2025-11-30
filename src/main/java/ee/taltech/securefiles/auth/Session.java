package ee.taltech.securefiles.auth;

import javax.crypto.SecretKey;

public record Session(Long userId, String username, SecretKey encryptionKey) {

}

