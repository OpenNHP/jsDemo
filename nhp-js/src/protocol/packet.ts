/**
 * NHP Packet Building and Parsing
 * Implements the core NHP protocol packet operations
 */

import type { PacketType, ParsedPacket } from '../types.js';
import { NHPHeader } from './header.js';
import {
  PACKET_BUFFER_SIZE,
  HEADER_SIZE,
  INITIAL_CHAIN_KEY_STRING,
  INITIAL_HASH_STRING,
  NHP_PACKET_TYPES,
  PROTOCOL_VERSION,
  FIELD_SIZES,
  STALE_PACKET_THRESHOLD_NS,
  FLOOD_PACKET_THRESHOLD_NS,
} from './constants.js';
import {
  generateX25519KeyPair,
  ecdhX25519,
  x25519PublicKeyToBytes,
  base64ToX25519PublicKey,
  base64ToX25519PrivateKey,
  bytesToX25519PublicKey,
} from '../crypto/ecdh.js';
import { chacha20Seal, chacha20Open } from '../crypto/aead.js';
import {
  newSHA256Hash,
  updateSHA256,
  sumSHA256,
  keyGen2,
  mixKey,
} from '../crypto/noise.js';
import {
  base64ToBytes,
  stringToBytes,
  bytesToString,
  equalBytes,
  getUnixNano,
  zlibCompress,
  zlibDecompress,
} from '../crypto/utils.js';

// Global state for packet management
let globalCounter = 0n;
const serverCookieMap = new Map<string, Uint8Array>();
const lastSendTimeMap = new Map<string, bigint>();
const lastRemoteSendTimeMap = new Map<string, bigint>();

/**
 * Build an NHP packet for transmission
 * @param type - Packet type (KNK, ACK, etc.)
 * @param privateKey - Base64-encoded local private key
 * @param publicKey - Base64-encoded local public key
 * @param remotePublicKey - Base64-encoded remote public key
 * @param message - Message payload to encrypt
 * @param compress - Whether to compress the payload
 * @returns Encrypted packet bytes
 */
export async function buildNHPPacket(
  type: number,
  privateKey: string,
  publicKey: string,
  remotePublicKey: string,
  message: string,
  compress: boolean
): Promise<Uint8Array> {
  // Only support X25519 for now (44 char base64 = 32 bytes)
  if (privateKey.length !== 44) {
    throw new Error('GM SM2 scheme is not supported yet');
  }

  const packet = new Uint8Array(PACKET_BUFFER_SIZE);
  const header = new NHPHeader(packet.buffer);

  const localPrivKey = await base64ToX25519PrivateKey(privateKey);
  const localPubKey = await base64ToX25519PublicKey(publicKey);
  const remotePubKey = await base64ToX25519PublicKey(remotePublicKey);

  const localPubKeyBytes = base64ToBytes(publicKey);
  const remotePubKeyBytes = base64ToBytes(remotePublicKey);
  const msgBytes = stringToBytes(message);

  // Set header fields
  header.version = { major: PROTOCOL_VERSION.MAJOR, minor: PROTOCOL_VERSION.MINOR };
  header.flags = { extended: false, compressed: compress };
  globalCounter++;
  header.counter = globalCounter;
  const nonce = header.nonce;

  // Initialize chain key and hash
  const chainKey = new Uint8Array(32);
  const chainHash = new Uint8Array(32);
  const hmacHasher = newSHA256Hash();
  const chainHasher = newSHA256Hash();

  // Initialize with protocol strings
  updateSHA256(hmacHasher, stringToBytes(INITIAL_HASH_STRING));
  updateSHA256(chainHasher, stringToBytes(INITIAL_HASH_STRING));
  chainHash.set(sumSHA256(chainHasher));
  chainKey.set(mixKey(chainHash, stringToBytes(INITIAL_CHAIN_KEY_STRING)));

  // Mix in remote public key
  updateSHA256(hmacHasher, remotePubKeyBytes);
  updateSHA256(chainHasher, remotePubKeyBytes);

  // Generate ephemeral key pair and perform ECDH
  const ephemeralKeys = await generateX25519KeyPair();
  const ephemeralPublicKeyBytes = await x25519PublicKeyToBytes(ephemeralKeys.publicKey);
  header.ephemeral = ephemeralPublicKeyBytes;

  updateSHA256(chainHasher, ephemeralPublicKeyBytes);
  chainHash.set(sumSHA256(chainHasher));
  chainKey.set(mixKey(chainKey, ephemeralPublicKeyBytes));

  // ECDH: ephemeral private * remote public
  const essKey = await ecdhX25519(ephemeralKeys.privateKey, remotePubKey);
  const ess = await x25519PublicKeyToBytes(essKey);

  // Encrypt local public key
  const derivedKeys0 = keyGen2(chainKey, ess);
  chainKey.set(derivedKeys0.first);

  const keyStatic = chacha20Seal(derivedKeys0.second, nonce, localPubKeyBytes, chainHash);
  header.static = keyStatic;

  updateSHA256(chainHasher, keyStatic);
  chainHash.set(sumSHA256(chainHasher));

  // ECDH: local private * remote public
  const ssKey = await ecdhX25519(localPrivKey, remotePubKey);
  const ss = await x25519PublicKeyToBytes(ssKey);

  // Encrypt timestamp
  const derivedKeys1 = keyGen2(chainKey, ss);
  chainKey.set(derivedKeys1.first);

  const tsBuf = new ArrayBuffer(8);
  const tsView = new DataView(tsBuf);
  const timestamp = getUnixNano();
  tsView.setBigUint64(0, timestamp);
  const ts = new Uint8Array(tsBuf);
  lastSendTimeMap.set(remotePublicKey, timestamp);

  const tsStatic = chacha20Seal(derivedKeys1.second, nonce, ts, chainHash);
  header.timestamp = tsStatic;

  // Encrypt message payload
  const derivedKeys2 = keyGen2(chainKey, tsStatic);
  chainKey.set(derivedKeys2.first);
  updateSHA256(chainHasher, tsStatic);
  chainHash.set(sumSHA256(chainHasher));

  let payload = msgBytes;
  if (compress) {
    payload = await zlibCompress(msgBytes);
  }

  const msgStatic = chacha20Seal(derivedKeys2.second, nonce, payload, chainHash);
  packet.set(msgStatic, header.size);

  const payloadSize = payload.byteLength + FIELD_SIZES.AEAD_TAG;
  header.typeAndPayloadSize = { type, size: payloadSize };

  // Compute HMAC
  if (type === NHP_PACKET_TYPES.RNK) {
    const cookie = serverCookieMap.get(remotePublicKey);
    if (cookie) {
      updateSHA256(hmacHasher, cookie);
    }
  }
  updateSHA256(hmacHasher, packet.subarray(0, header.size - FIELD_SIZES.HMAC));
  header.hmac = sumSHA256(hmacHasher);

  return packet.subarray(0, header.size + payloadSize);
}

/**
 * Parse an incoming NHP packet
 * @param packet - Raw packet bytes
 * @param privateKey - Base64-encoded local private key
 * @param publicKey - Base64-encoded local public key
 * @param remotePublicKey - Base64-encoded expected remote public key
 * @returns Parsed packet with type and decrypted message
 */
export async function parseNHPPacket(
  packet: Uint8Array,
  privateKey: string,
  publicKey: string,
  remotePublicKey: string
): Promise<ParsedPacket> {
  if (packet.length < HEADER_SIZE) {
    throw new Error('Packet size is too small');
  }

  // Create a clean ArrayBuffer copy to avoid SharedArrayBuffer issues
  const packetBuffer = new ArrayBuffer(packet.length);
  new Uint8Array(packetBuffer).set(packet);
  const header = new NHPHeader(packetBuffer);
  const { extended, compressed } = header.flags;

  if (extended) {
    throw new Error('GM SM2 scheme is not supported yet');
  }

  const { type, size } = header.typeAndPayloadSize;

  if (type !== NHP_PACKET_TYPES.ACK && type !== NHP_PACKET_TYPES.COK) {
    throw new Error('Not an ACK or COK packet');
  }

  if (packet.length !== header.size + size) {
    throw new Error('Wrong packet size');
  }

  const recvTime = getUnixNano();

  // Verify HMAC
  const localPubKeyBytes = base64ToBytes(publicKey);
  const hmacHasher = newSHA256Hash();
  updateSHA256(hmacHasher, stringToBytes(INITIAL_HASH_STRING));
  updateSHA256(hmacHasher, localPubKeyBytes);
  updateSHA256(hmacHasher, packet.subarray(0, header.size - FIELD_SIZES.HMAC));
  const checkSum = sumSHA256(hmacHasher);

  if (!equalBytes(checkSum, header.hmac)) {
    throw new Error('HMAC check failed');
  }

  const localPrivKey = await base64ToX25519PrivateKey(privateKey);
  const remotePubKey = await base64ToX25519PublicKey(remotePublicKey);
  const remotePubKeyBytes = base64ToBytes(remotePublicKey);

  const ephemeralPublicKeyBytes = header.ephemeral;
  const ephemeralPublicKey = await bytesToX25519PublicKey(ephemeralPublicKeyBytes);
  const nonce = header.nonce;
  const keyStatic = header.static;
  const tsStatic = header.timestamp;
  const msgStatic = packet.subarray(header.size);

  // Initialize chain key and hash
  const chainKey = new Uint8Array(32);
  const chainHash = new Uint8Array(32);
  const chainHasher = newSHA256Hash();

  updateSHA256(chainHasher, stringToBytes(INITIAL_HASH_STRING));
  chainHash.set(sumSHA256(chainHasher));
  chainKey.set(mixKey(chainHash, stringToBytes(INITIAL_CHAIN_KEY_STRING)));

  updateSHA256(chainHasher, localPubKeyBytes);
  updateSHA256(chainHasher, ephemeralPublicKeyBytes);
  chainHash.set(sumSHA256(chainHasher));
  chainKey.set(mixKey(chainKey, ephemeralPublicKeyBytes));

  // ECDH: local private * ephemeral public
  const essKey = await ecdhX25519(localPrivKey, ephemeralPublicKey);
  const ess = await x25519PublicKeyToBytes(essKey);

  // Decrypt remote public key
  const derivedKeys0 = keyGen2(chainKey, ess);
  chainKey.set(derivedKeys0.first);
  const decryptedPubKeyBytes = chacha20Open(derivedKeys0.second, nonce, keyStatic, chainHash);

  if (!equalBytes(remotePubKeyBytes, decryptedPubKeyBytes)) {
    throw new Error('Remote public key check failed');
  }

  updateSHA256(chainHasher, keyStatic);
  chainHash.set(sumSHA256(chainHasher));

  // ECDH: local private * remote public
  const ssKey = await ecdhX25519(localPrivKey, remotePubKey);
  const ss = await x25519PublicKeyToBytes(ssKey);

  // Decrypt timestamp
  const derivedKeys1 = keyGen2(chainKey, ss);
  chainKey.set(derivedKeys1.first);

  const decryptedTs = chacha20Open(derivedKeys1.second, nonce, tsStatic, chainHash);
  // Create a new ArrayBuffer to avoid SharedArrayBuffer issues
  const tsBuf = new ArrayBuffer(decryptedTs.length);
  new Uint8Array(tsBuf).set(decryptedTs);
  const tsView = new DataView(tsBuf);
  const remoteSendTime = tsView.getBigUint64(0);

  // Anti-replay checks
  const lastRemoteSendTime = lastRemoteSendTimeMap.get(remotePublicKey);
  lastRemoteSendTimeMap.set(remotePublicKey, remoteSendTime);

  if (lastRemoteSendTime !== undefined) {
    if (remoteSendTime < lastRemoteSendTime) {
      throw new Error('Received replay packet');
    }
    if (remoteSendTime < lastRemoteSendTime + FLOOD_PACKET_THRESHOLD_NS) {
      throw new Error('Received flood packet');
    }
  }

  if (remoteSendTime < recvTime - STALE_PACKET_THRESHOLD_NS) {
    throw new Error('Received stale packet');
  }

  // Decrypt message
  const derivedKeys2 = keyGen2(chainKey, header.timestamp);
  chainKey.set(derivedKeys2.first);
  updateSHA256(chainHasher, tsStatic);
  chainHash.set(sumSHA256(chainHasher));

  let msg = chacha20Open(derivedKeys2.second, nonce, msgStatic, chainHash);

  if (compressed) {
    msg = await zlibDecompress(msg);
  }

  // Handle cookie packets
  if (type === NHP_PACKET_TYPES.COK) {
    serverCookieMap.set(remotePublicKey, msg);
  }

  return {
    type: type as PacketType,
    message: bytesToString(msg),
    remotePublicKey,
  };
}

/**
 * Clear stored cookies for a server
 */
export function clearServerCookie(remotePublicKey: string): void {
  serverCookieMap.delete(remotePublicKey);
}

/**
 * Reset the global packet counter (for testing)
 */
export function resetGlobalCounter(): void {
  globalCounter = 0n;
}
