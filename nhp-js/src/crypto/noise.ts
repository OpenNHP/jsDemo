/**
 * Noise protocol key derivation and hashing
 * Uses @noble/hashes for cryptographic operations
 */

import { sha256 } from '@noble/hashes/sha256';
import { hmac } from '@noble/hashes/hmac';
import { concatBytes } from './utils.js';

/**
 * SHA-256 hash state for incremental hashing
 */
export class SHA256Hasher {
  private data: Uint8Array[] = [];

  /**
   * Update the hash with additional data
   */
  update(bytes: Uint8Array): void {
    this.data.push(bytes);
  }

  /**
   * Get the final hash without consuming the hasher
   * Allows continued updates after getting intermediate hash
   */
  sum(): Uint8Array {
    const combined = concatBytes(...this.data);
    return sha256(combined);
  }

  /**
   * Create a clone of this hasher for getting intermediate results
   */
  clone(): SHA256Hasher {
    const cloned = new SHA256Hasher();
    cloned.data = [...this.data];
    return cloned;
  }
}

/**
 * Create a new SHA-256 hasher
 */
export function newSHA256Hash(): SHA256Hasher {
  return new SHA256Hasher();
}

/**
 * Update SHA-256 hasher with data
 */
export function updateSHA256(hasher: SHA256Hasher, bytes: Uint8Array): void {
  hasher.update(bytes);
}

/**
 * Get the current hash value (non-consuming)
 */
export function sumSHA256(hasher: SHA256Hasher): Uint8Array {
  return hasher.clone().sum();
}

/**
 * Compute HMAC-SHA256 with a single message
 */
export function hmac1(key: Uint8Array, msg: Uint8Array): Uint8Array {
  return hmac(sha256, key, msg);
}

/**
 * Compute HMAC-SHA256 with two concatenated messages
 */
export function hmac2(key: Uint8Array, msg0: Uint8Array, msg1: Uint8Array): Uint8Array {
  const combined = concatBytes(msg0, msg1);
  return hmac(sha256, key, combined);
}

/**
 * Derive a single key from key and message using HKDF-like construction
 * keyGen1(key, msg) = HMAC(HMAC(key, msg), 0x01)
 */
export function keyGen1(key: Uint8Array, msg: Uint8Array): Uint8Array {
  const prk = hmac1(key, msg);
  const n = new Uint8Array([0x01]);
  return hmac1(prk, n);
}

/**
 * Derive two keys from key and message using HKDF-like construction
 * Returns { first: T1, second: T2 } where:
 *   prk = HMAC(key, msg)
 *   T1 = HMAC(prk, 0x01)
 *   T2 = HMAC(prk, T1 || 0x02)
 */
export function keyGen2(key: Uint8Array, msg: Uint8Array): { first: Uint8Array; second: Uint8Array } {
  const prk = hmac1(key, msg);
  const n1 = new Uint8Array([0x01]);
  const n2 = new Uint8Array([0x02]);

  const first = hmac1(prk, n1);
  const second = hmac2(prk, first, n2);

  return { first, second };
}

/**
 * Mix key material into chain key
 * mixKey(key, msg) = keyGen1(key, msg)
 */
export function mixKey(key: Uint8Array, msg: Uint8Array): Uint8Array {
  return keyGen1(key, msg);
}

/**
 * Mix data into chain hash
 * mixHash(hash, msg) = SHA256(hash || msg)
 */
export function mixHash(hash: Uint8Array, msg: Uint8Array): Uint8Array {
  const combined = concatBytes(hash, msg);
  return sha256(combined);
}
