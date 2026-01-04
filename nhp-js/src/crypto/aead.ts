/**
 * AEAD encryption using ChaCha20-Poly1305
 * Uses @noble/ciphers for cryptographic operations
 */

import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { FIELD_SIZES } from '../protocol/constants.js';

/**
 * Encrypt data using ChaCha20-Poly1305 AEAD
 * @param key - 32-byte encryption key
 * @param nonce - 12-byte nonce
 * @param plaintext - Data to encrypt
 * @param additionalData - Additional authenticated data (AAD)
 * @returns Ciphertext with 16-byte authentication tag appended
 */
export function chacha20Seal(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  additionalData: Uint8Array
): Uint8Array {
  const cipher = chacha20poly1305(key, nonce, additionalData);
  const output = new Uint8Array(plaintext.length + FIELD_SIZES.AEAD_TAG);
  return cipher.encrypt(plaintext, output);
}

/**
 * Decrypt data using ChaCha20-Poly1305 AEAD
 * @param key - 32-byte encryption key
 * @param nonce - 12-byte nonce
 * @param ciphertextWithTag - Ciphertext with authentication tag
 * @param additionalData - Additional authenticated data (AAD)
 * @returns Decrypted plaintext
 * @throws Error if authentication fails
 */
export function chacha20Open(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertextWithTag: Uint8Array,
  additionalData: Uint8Array
): Uint8Array {
  const cipher = chacha20poly1305(key, nonce, additionalData);
  const output = new Uint8Array(ciphertextWithTag.length - FIELD_SIZES.AEAD_TAG);
  return cipher.decrypt(ciphertextWithTag, output);
}
