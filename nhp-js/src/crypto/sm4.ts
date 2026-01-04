/**
 * SM4 Block Cipher with GCM mode
 * Chinese cryptographic standard (GB/T 32907-2016)
 *
 * SM4 is a 128-bit block cipher with 128-bit key.
 * For NHP, it's used in GCM mode for authenticated encryption.
 *
 * This is a placeholder implementation that throws an error.
 * To use GM/SM cryptography, install a GM crypto library:
 *   npm install sm-crypto
 */

/** SM4 key size in bytes */
export const SM4_KEY_SIZE = 16;

/** SM4 block size in bytes */
export const SM4_BLOCK_SIZE = 16;

/** GCM nonce size in bytes */
export const SM4_GCM_NONCE_SIZE = 12;

/** GCM authentication tag size in bytes */
export const SM4_GCM_TAG_SIZE = 16;

/**
 * Encrypt data using SM4-GCM AEAD
 * @param key - 16-byte encryption key
 * @param nonce - 12-byte nonce
 * @param plaintext - Data to encrypt
 * @param additionalData - Additional authenticated data (AAD)
 * @returns Ciphertext with 16-byte authentication tag appended
 */
export function sm4GcmSeal(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  additionalData: Uint8Array
): Uint8Array {
  if (key.length !== SM4_KEY_SIZE) {
    throw new Error(`SM4 key must be ${SM4_KEY_SIZE} bytes`);
  }
  if (nonce.length !== SM4_GCM_NONCE_SIZE) {
    throw new Error(`SM4-GCM nonce must be ${SM4_GCM_NONCE_SIZE} bytes`);
  }
  throw new Error('SM4-GCM not implemented. Install sm-crypto package for GM support.');
}

/**
 * Decrypt data using SM4-GCM AEAD
 * @param key - 16-byte encryption key
 * @param nonce - 12-byte nonce
 * @param ciphertextWithTag - Ciphertext with authentication tag
 * @param additionalData - Additional authenticated data (AAD)
 * @returns Decrypted plaintext
 * @throws Error if authentication fails
 */
export function sm4GcmOpen(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertextWithTag: Uint8Array,
  additionalData: Uint8Array
): Uint8Array {
  if (key.length !== SM4_KEY_SIZE) {
    throw new Error(`SM4 key must be ${SM4_KEY_SIZE} bytes`);
  }
  if (nonce.length !== SM4_GCM_NONCE_SIZE) {
    throw new Error(`SM4-GCM nonce must be ${SM4_GCM_NONCE_SIZE} bytes`);
  }
  throw new Error('SM4-GCM not implemented. Install sm-crypto package for GM support.');
}

/**
 * Check if SM4 is available
 */
export function isSM4Available(): boolean {
  return false; // Will return true when sm-crypto is implemented
}
