import CryptoJS from "crypto-js"
import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { bytesToBase64, base64ToBytes} from "./utils.js"

export async function generateX25519KeyPair() {
  return await window.crypto.subtle.generateKey(
    { name: "X25519" },
    true, // extractable
    ["deriveBits", "deriveKey"]
  );
}

export async function generateX25519KeyPairBase64() {
  const keyPair = await window.crypto.subtle.generateKey(
    { name: "X25519" },
    true, // extractable
    ["deriveBits", "deriveKey"]
  );

  const bytesPri = await x25519PrivateKeyToBytes(keyPair.privateKey);
  const bytesPub = await x25519PublicKeyToBytes(keyPair.publicKey);

  return {
    privKeyStr: bytesToBase64(bytesPri),
    pubKeyStr: bytesToBase64(bytesPub)
  }
}

export async function ecdhX25519(privateKey, remotePublicKey) {
  // The 'deriveKey' method is used to both derive the shared secret and immediately
  // use it as the base for a new key (e.g., an AES key).
  return await window.crypto.subtle.deriveKey(
    {
      name: "X25519",
      public: remotePublicKey, // The remote party's public key
    },
    privateKey, // Your private key
    {
      //name: "HMAC", // The algorithm for the shared secret key
      //hash: "SHA-256",
      //length: 256,
      name: "AES-GCM",
      length: 256,
    },
    true, // extractable
    ["encrypt", "decrypt"]
  );
}

export async function x25519PublicKeyToBytes(key) {
  const keyBin = await window.crypto.subtle.exportKey("raw", key);
  return new Uint8Array(keyBin);
}

export async function bytesToX25519PublicKey(bytes) {
  return await window.crypto.subtle.importKey(
    "raw", // format
    bytes, // keyData
    { name: "X25519" }, // algorithm
    true, // extractable
    [] // key usages (public keys usually have no usage on their own)
  );
}

function decodeASN1Length(bytes, offset) {
    let len = bytes[offset++];
    if (len < 0x80) return { length: len, nextOffset: offset };

    let numBytes = len & 0x7f;
    len = 0;
    for (let i = 0; i < numBytes; i++) {
        len = (len << 8) | bytes[offset++];
    }
    return { length: len, nextOffset: offset };
}

function readASN1(bytes, offset) {
    let tag = bytes[offset++];
    let { length, nextOffset } = decodeASN1Length(bytes, offset);
    let end = nextOffset + length;

    return { tag, offset: nextOffset, length, end };
}

// Extract raw 32-byte X25519 from PKCS#8
function extractX25519FromPKCS8(pkcs8) {
    const bytes = new Uint8Array(pkcs8);

    // Root SEQUENCE
    let root = readASN1(bytes, 0);

    // Skip: version (INTEGER), algorithm identifier (SEQUENCE)
    let p = root.offset;

    // INTEGER (version)
    let ver = readASN1(bytes, p);
    p = ver.end;

    // AlgorithmIdentifier SEQUENCE
    let alg = readASN1(bytes, p);
    p = alg.end;

    // privateKey OCTET STRING
    let pkOuter = readASN1(bytes, p);

    // parse inner OCTET STRING inside privateKey
    let inner = readASN1(bytes, pkOuter.offset);

    // raw private key = inner OCTET STRING content
    return bytes.slice(inner.offset, inner.offset + inner.length);
}

function encodeLength(len) {
    if (len < 0x80) return [len];
    // long form
    const bytes = [];
    while (len > 0) {
        bytes.unshift(len & 0xff);
        len >>= 8;
    }
    return [0x80 | bytes.length, ...bytes];
}

function derEncodeInteger(n) {
    // version = 0
    return [0x02, 0x01, n];
}

function derEncodeOID(oid) {
    const parts = oid.split('.').map(Number);
    const first = 40 * parts[0] + parts[1];
    const rest = parts.slice(2).map(n => {
        const bytes = [];
        let val = n;
        do {
            bytes.unshift(val & 0x7f);
            val >>= 7;
        } while (val > 0);
        for (let i = 0; i < bytes.length - 1; i++) bytes[i] |= 0x80;
        return bytes;
    }).flat();
    return [0x06, rest.length + 1, first, ...rest];
}

function derEncodeOctetString(bytes) {
    return [0x04, ...encodeLength(bytes.length), ...bytes];
}

function derEncodeSequence(bytes) {
    return [0x30, ...encodeLength(bytes.length), ...bytes];
}

// Wrap raw 32-byte X25519 key in PKCS#8
export async function bytesToX25519PrivateKey(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length !== 32) {
        throw new Error("rawBytes must be Uint8Array(32)");
    }

    // AlgorithmIdentifier SEQUENCE
    const algOid = derEncodeOID("1.3.101.110"); // X25519 OID
    const algIdSeq = derEncodeSequence(algOid);

    // privateKey OCTET STRING
    const privOctet = derEncodeOctetString(bytes);
    const privAttrOctet = derEncodeOctetString(privOctet); // no attributes

    // version INTEGER
    const version = derEncodeInteger(0);

    // Full PrivateKeyInfo SEQUENCE
    const seq = derEncodeSequence([...version, ...algIdSeq, ...privAttrOctet]);
    
    const buf = new Uint8Array(seq);

    return await window.crypto.subtle.importKey(
    "pkcs8", // format
    buf.buffer, // keyData
    { name: "X25519" }, // algorithm
    true, // extractable
    ["deriveBits", "deriveKey"] // key usages (public keys usually have no usage on their own)
  );
}

export async function x25519PrivateKeyToBytes(key) {
  const pkcs8Key = await window.crypto.subtle.exportKey("pkcs8", key);
  return extractX25519FromPKCS8(pkcs8Key);
}

export async function base64ToX25519PrivateKey(b64) {
  const bytes = base64ToBytes(b64);
  return await bytesToX25519PrivateKey(bytes);
}

export async function base64ToX25519PublicKey(b64) {
  const bytes = base64ToBytes(b64);
  return await bytesToX25519PublicKey(bytes);
}

// sha256 hash
function uint8ArrayToWordArray(u8) {
  const words = [];
  for (let i = 0; i < u8.length; i += 4) {
    words.push(
      (u8[i] << 24) |
      (u8[i + 1] << 16) |
      (u8[i + 2] << 8) |
      (u8[i + 3])
    );
  }
  return CryptoJS.lib.WordArray.create(words, u8.length);
}

function wordArrayToUint8Array(wordArray) {
  const { words, sigBytes } = wordArray;
  const u8 = new Uint8Array(sigBytes);

  let i = 0;
  for (let w = 0; w < words.length; w++) {
    const word = words[w];

    // break word into 4 bytes, big endian
    u8[i++] = (word >> 24) & 0xff;
    if (i >= sigBytes) break;
    u8[i++] = (word >> 16) & 0xff;
    if (i >= sigBytes) break;
    u8[i++] = (word >> 8) & 0xff;
    if (i >= sigBytes) break;
    u8[i++] = word & 0xff;
    if (i >= sigBytes) break;
  }

  return u8;
}

export function newSHA256Hash() {
  return CryptoJS.algo.SHA256.create();
}

export function updateSHA256(hasher, bytes) {
  hasher.update(uint8ArrayToWordArray(bytes));
}

export function sumSHA256(hasher) {
  const hash = hasher.clone().finalize();
  return wordArrayToUint8Array(hash);
}

export function hmac1(key, msg) {
  const hmacHasher = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA256, uint8ArrayToWordArray(key));
  hmacHasher.update(uint8ArrayToWordArray(msg));
  const hmac = hmacHasher.finalize();
  return wordArrayToUint8Array(hmac);
}

export function hmac2(key, msg0, msg1) {
	const hmacHasher = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA256, uint8ArrayToWordArray(key));
  hmacHasher.update(uint8ArrayToWordArray(msg0));
  hmacHasher.update(uint8ArrayToWordArray(msg1));
  const hmac = hmacHasher.finalize();
  return wordArrayToUint8Array(hmac);
}

export function keyGen1(key, msg) {
	const hmac = hmac1(key, msg);
  const n = new Uint8Array(1);
  n[0] = 0x1;
	return hmac1(hmac, n);
}

export function keyGen2(key, msg) {
	const base = hmac1(key, msg);
  const n = new Uint8Array(1);
  n[0] = 0x1;
	const key0 = hmac1(base, n)
  n[0] = 0x2;
  const key1 = hmac2(base, key0, n);
  return {first: key0, second: key1}
}

export function mixKey(key, msg) {
  return keyGen1(key, msg);
}

export function mixHash(key, msg) {
  const hasher = newSHA256Hash();
  updateSHA256(hasher, key)
  updateSHA256(hasher, msg)
  return sumSHA256(hasher)
}

// aead
export async function bytesToChacha20AEADKey(bytes) {
  if (bytes.byteLength !== 32) {
    throw new Error("ChaCha20-Poly1305 key must be exactly 32 bytes (256 bits).");
  }

  return await window.crypto.subtle.importKey(
    "raw", // 1. Format: raw bytes
    bytes, // 2. Key Data: The 32-byte Uint8Array
    { 
      name: "ChaCha20-Poly1305" // 3. Algorithm: The AEAD mode
    },
    true, // 4. Extractable: Usually false for symmetric keys for security
    ["encrypt", "decrypt"] // 5. Key Usages: Required for AEAD operations
  );
}

export function chacha20Seal(key, nonce, plainData, additionalData) {
  const cipher = chacha20poly1305(key, nonce, additionalData);
  const buf = new Uint8Array(plainData.byteLength + 16)
  return cipher.encrypt(plainData, buf);
}

export function chacha20Open(key, nonce, ciphertextWithTag, additionalData) {
  const cipher = chacha20poly1305(key, nonce, additionalData);
  const buf = new Uint8Array(ciphertextWithTag.byteLength - 16)
  return cipher.decrypt(ciphertextWithTag, buf);
}
