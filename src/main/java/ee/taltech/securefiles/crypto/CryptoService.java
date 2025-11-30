package ee.taltech.securefiles.crypto;

import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Minimal AES-GCM encryption/decryption service.
 * Format of encrypted blob:
 *    [12-byte IV][ciphertext...][16-byte GCM tag]
 */
@Service
public class CryptoService {

    private static final String CIPHER = "AES/GCM/NoPadding";
    private static final int GCM_TAG_BITS = 128;
    private static final int IV_LENGTH = 12;  // recommended for GCM
    private static final int MAX_BLOB_SIZE = 55 * 1024 * 1024;  // 55 MB - calc for max ciphertext

    private final SecureRandom secureRandom = new SecureRandom();

    /**
     * Encrypt plaintext with AES-GCM using the provided SecretKey.
     * Output format = IV || ciphertext+tag
     */
    public byte[] encrypt(byte[] plaintext, SecretKey key) {
        try {
            byte[] iv = new byte[IV_LENGTH];
            secureRandom.nextBytes(iv);

            Cipher cipher = Cipher.getInstance(CIPHER);
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_BITS, iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, spec);

            byte[] ciphertext = cipher.doFinal(plaintext);

            // combine IV + ciphertext
            byte[] output = new byte[IV_LENGTH + ciphertext.length];
            System.arraycopy(iv, 0, output, 0, IV_LENGTH);
            System.arraycopy(ciphertext, 0, output, IV_LENGTH, ciphertext.length);
            return output;

        } catch (Exception e) {
            throw new IllegalArgumentException("Encryption failed");
        }
    }

    /**
     * Decrypt blob in format [IV][ciphertext+tag]
     */
    public byte[] decrypt(byte[] blob, SecretKey key) {
        if (blob.length > MAX_BLOB_SIZE) {
            throw new IllegalArgumentException("Ciphertext too large");
        }
        try {
            if (blob.length < IV_LENGTH + 16) {  // minimum: IV + tag
                throw new IllegalArgumentException("Input too short");
            }

            byte[] iv = Arrays.copyOfRange(blob, 0, IV_LENGTH);
            byte[] ciphertext = Arrays.copyOfRange(blob, IV_LENGTH, blob.length);

            Cipher cipher = Cipher.getInstance(CIPHER);
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_BITS, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, spec);

            return cipher.doFinal(ciphertext);

        } catch (Exception e) {
            throw new IllegalArgumentException("Decryption failed");
        }
    }
}
