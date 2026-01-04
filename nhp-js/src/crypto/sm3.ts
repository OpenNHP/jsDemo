/**
 * SM3 Hash Function
 * Chinese cryptographic hash standard (GB/T 32905-2016)
 *
 * This is a placeholder implementation that throws an error.
 * To use GM/SM cryptography, install a GM crypto library:
 *   npm install sm-crypto
 *
 * Then this module can be updated to use the actual implementation.
 */

/**
 * SM3 hash state for incremental hashing
 */
export class SM3Hasher {
  private data: Uint8Array[] = [];

  /**
   * Update the hash with additional data
   */
  update(bytes: Uint8Array): void {
    this.data.push(bytes);
  }

  /**
   * Get the final hash
   */
  sum(): Uint8Array {
    // Placeholder - actual implementation requires sm-crypto or similar library
    throw new Error('SM3 not implemented. Install sm-crypto package for GM support.');
  }

  /**
   * Create a clone of this hasher
   */
  clone(): SM3Hasher {
    const cloned = new SM3Hasher();
    cloned.data = [...this.data];
    return cloned;
  }
}

/**
 * Create a new SM3 hasher
 */
export function newSM3Hash(): SM3Hasher {
  return new SM3Hasher();
}

/**
 * Compute SM3 hash of data
 */
export function sm3(data: Uint8Array): Uint8Array {
  throw new Error('SM3 not implemented. Install sm-crypto package for GM support.');
}

/**
 * Compute HMAC-SM3
 */
export function hmacSM3(key: Uint8Array, msg: Uint8Array): Uint8Array {
  throw new Error('HMAC-SM3 not implemented. Install sm-crypto package for GM support.');
}
