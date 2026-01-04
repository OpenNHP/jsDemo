/**
 * Utility functions for cryptographic operations
 */

/**
 * Convert Uint8Array to Base64 string
 */
export function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Convert Base64 string to Uint8Array
 */
export function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Convert string to UTF-8 bytes
 */
export function stringToBytes(str: string): Uint8Array {
  const encoder = new TextEncoder();
  return encoder.encode(str);
}

/**
 * Convert UTF-8 bytes to string
 */
export function bytesToString(bytes: Uint8Array): string {
  const decoder = new TextDecoder();
  return decoder.decode(bytes);
}

/**
 * Compare two byte arrays for equality
 */
export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/**
 * Get current Unix timestamp in nanoseconds
 */
export function getUnixNano(): bigint {
  const ms = Date.now();
  const subMs = performance.now() % 1;
  return BigInt(ms) * 1_000_000n + BigInt(Math.floor(subMs * 1_000_000));
}

/**
 * Compress data using zlib deflate
 */
export async function zlibCompress(data: Uint8Array): Promise<Uint8Array> {
  const cs = new CompressionStream('deflate');
  const writer = cs.writable.getWriter();
  // Copy to a new ArrayBuffer to avoid SharedArrayBuffer issues
  const buffer = new Uint8Array(data).buffer;
  await writer.write(buffer);
  await writer.close();

  const response = new Response(cs.readable);
  const compressedBuffer = await response.arrayBuffer();
  return new Uint8Array(compressedBuffer);
}

/**
 * Decompress data using zlib inflate
 */
export async function zlibDecompress(compressedData: Uint8Array): Promise<Uint8Array> {
  const ds = new DecompressionStream('deflate');
  const writer = ds.writable.getWriter();
  // Copy to a new ArrayBuffer to avoid SharedArrayBuffer issues
  const buffer = new Uint8Array(compressedData).buffer;
  await writer.write(buffer);
  await writer.close();

  const response = new Response(ds.readable);
  const arrayBuffer = await response.arrayBuffer();
  return new Uint8Array(arrayBuffer);
}

/**
 * Generate cryptographically secure random bytes
 */
export function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

/**
 * Concatenate multiple Uint8Arrays
 */
export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}
