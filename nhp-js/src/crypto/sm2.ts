/**
 * SM2 Elliptic Curve Cryptography
 * Chinese cryptographic standard (GB/T 32918-2016)
 *
 * SM2 uses a specific elliptic curve with parameters similar to secp256r1/P-256.
 * Key sizes:
 *   - Private key: 32 bytes
 *   - Public key: 64 bytes (uncompressed X, Y coordinates)
 *   - Shared secret: 32 bytes
 *
 * This is a placeholder implementation that throws an error.
 * To use GM/SM cryptography, install a GM crypto library:
 *   npm install sm-crypto
 */

import { bytesToBase64, base64ToBytes } from './utils.js';

/** SM2 private key size in bytes */
export const SM2_PRIVATE_KEY_SIZE = 32;

/** SM2 public key size in bytes (uncompressed) */
export const SM2_PUBLIC_KEY_SIZE = 64;

/** SM2 key pair as raw bytes */
export interface SM2KeyPairRaw {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

/** SM2 key pair as Base64 strings */
export interface SM2KeyPairBase64 {
  privateKey: string;
  publicKey: string;
}

/**
 * Generate a new SM2 key pair
 */
export function generateSM2KeyPair(): SM2KeyPairRaw {
  throw new Error('SM2 not implemented. Install sm-crypto package for GM support.');
}

/**
 * Generate a new SM2 key pair and return as Base64 strings
 */
export function generateSM2KeyPairBase64(): SM2KeyPairBase64 {
  const { privateKey, publicKey } = generateSM2KeyPair();
  return {
    privateKey: bytesToBase64(privateKey),
    publicKey: bytesToBase64(publicKey),
  };
}

/**
 * Derive SM2 public key from private key
 */
export function deriveSM2PublicKey(privateKey: Uint8Array): Uint8Array {
  if (privateKey.length !== SM2_PRIVATE_KEY_SIZE) {
    throw new Error(`SM2 private key must be ${SM2_PRIVATE_KEY_SIZE} bytes`);
  }
  throw new Error('SM2 not implemented. Install sm-crypto package for GM support.');
}

/**
 * Derive SM2 public key from Base64-encoded private key
 */
export function deriveSM2PublicKeyFromBase64(privateKeyBase64: string): string {
  const privateKey = base64ToBytes(privateKeyBase64);
  const publicKey = deriveSM2PublicKey(privateKey);
  return bytesToBase64(publicKey);
}

/**
 * Perform SM2 ECDH key exchange
 * @param privateKey - 32-byte private key
 * @param publicKey - 64-byte public key (uncompressed)
 * @returns 32-byte shared secret
 */
export function sm2ECDH(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  if (privateKey.length !== SM2_PRIVATE_KEY_SIZE) {
    throw new Error(`SM2 private key must be ${SM2_PRIVATE_KEY_SIZE} bytes`);
  }
  if (publicKey.length !== SM2_PUBLIC_KEY_SIZE) {
    throw new Error(`SM2 public key must be ${SM2_PUBLIC_KEY_SIZE} bytes`);
  }
  throw new Error('SM2 ECDH not implemented. Install sm-crypto package for GM support.');
}

/**
 * Check if SM2 is available
 */
export function isSM2Available(): boolean {
  return false; // Will return true when sm-crypto is implemented
}
