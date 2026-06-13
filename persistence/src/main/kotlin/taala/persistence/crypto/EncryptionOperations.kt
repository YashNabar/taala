package taala.persistence.crypto

import java.security.Key
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

object EncryptionOperations {
    /**
     * Derives an AES Key Encryption Key (KEK) from a user-provided password
     * using PBKDF2 with HMAC-SHA256.
     *
     * The derived key is used to wrap and unwrap cryptographic keys before
     * they are persisted. A unique salt should be generated for each wrapped
     * key and stored alongside the protected key material.
     *
     * @param password password used as the basis for key derivation.
     * @param salt cryptographically secure random salt associated with the wrapped key.
     * @return AES key suitable for wrapping and unwrapping operations.
     */
    private fun deriveKey(
        password: CharArray?, salt: ByteArray
    ): SecretKeySpec {
        val spec = PBEKeySpec(
            password, salt, 600000,  // PBKDF2 iterations
            256
        )
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")

        val keyBytes = factory.generateSecret(spec).encoded

        return SecretKeySpec(keyBytes, "AES")
    }

    /**
     * Wraps a cryptographic key using a password-derived Key Encryption Key (KEK).
     *
     * This method:
     * - generates a random salt;
     * - derives a KEK using PBKDF2;
     * - generates a random initialization vector (IV);
     * - encrypts the encoded key material using AES-GCM;
     * - returns the wrapped key together with the salt and IV required for subsequent recovery.
     *
     * The returned [ProtectedKeyRecord] should be persisted as a single unit.
     * The original password is never stored.
     *
     * @param key key to protect before persistence.
     * @param password password used to derive the KEK.
     * @return wrapped key material and associated cryptographic parameters.
     */
    fun wrap(
        key: Key, password: CharArray?
    ): ProtectedKeyRecord {
        val random = SecureRandom()
        val salt = ByteArray(16)
        random.nextBytes(salt)

        val kek: SecretKeySpec = deriveKey(password, salt)

        val iv = ByteArray(12)
        random.nextBytes(iv)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")

        cipher.init(
            Cipher.ENCRYPT_MODE, kek, GCMParameterSpec(128, iv)
        )

        val wrappedKey = cipher.doFinal(key.encoded)

        return ProtectedKeyRecord(
            wrappedKey = wrappedKey,
            salt = salt,
            iv = iv,
        )
    }

    /**
     * Unwraps previously protected key material.
     *
     * The supplied password and salt are used to derive the same Key Encryption
     * Key (KEK) that was used during wrapping. The wrapped key material is then
     * decrypted using AES-GCM and returned in its original encoded form.
     *
     * Decryption will fail if:
     * - the password is incorrect;
     * - the salt or IV does not match the original values;
     * - the wrapped key material has been modified or corrupted.
     *
     * @param encrypted wrapped key material retrieved from persistent storage.
     * @param salt salt originally used during key derivation.
     * @param iv initialization vector originally used during wrapping.
     * @param password password used to derive the KEK.
     * @return the original encoded key bytes.
     */
    fun unwrap(
        encrypted: ByteArray, salt: ByteArray, iv: ByteArray, password: CharArray?
    ): ByteArray? {
        val aesKey: SecretKeySpec = deriveKey(password, salt)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")

        cipher.init(
            Cipher.DECRYPT_MODE, aesKey, GCMParameterSpec(128, iv)
        )

        return cipher.doFinal(encrypted)
    }
}
