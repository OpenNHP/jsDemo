export {bytesToBase64, base64ToBytes, bytesToString, stringToBytes, getUnixNano} from "./utils.js"
export {generateX25519KeyPairBase64} from "./crypto.js"

import {generateX25519KeyPair} from "./crypto.js"
import {copyBytes} from "@noble/ciphers/utils.js"
import {ecdhX25519, bytesToX25519PublicKey, x25519PublicKeyToBytes, bytesToX25519PrivateKey, x25519PrivateKeyToBytes, base64ToX25519PublicKey, base64ToX25519PrivateKey, mixKey} from "./crypto.js"
import {chacha20Seal, chacha20Open} from "./crypto.js"
import {newSHA256Hash, updateSHA256, sumSHA256, keyGen1, keyGen2} from "./crypto.js"
//export {generateSM2KeyPair, generateSM2KeyPairBase64} from "./crypto_gm.js"
import {ecdhSM2Raw, bytesToSM2PrivateKey, bytesToSM2PublicKey, base64ToSM2PrivateKey, base64ToSM2PublicKey} from "./crypto_gm.js"
import {base64ToBytes, equalBytes, stringToBytes, bytesToString, getUnixNano, zlibCompress, zlibDecompress} from "./utils.js"

const minimalRecvIntervalMs = 2;
const PacketBufferSize = 4096;
const InitialChainKeyString = "NHP keygen v.20230421@clouddeep.cn";
const	InitialHashString     = "NHP hashgen v.20230421@deepcloudsdp.com";
const GlobalCounter = new BigUint64Array(1);
const serverCookieMap = new Map();
const lastSendTimeMap = new Map();
const lastRemoteSendTimeMap = new Map();

const NHP_KNK_TYPE = 1;
const NHP_ACK_TYPE = 2;
const NHP_COK_TYPE = 7;
const NHP_RNK_TYPE = 8;

class NHPHeader {
  static SIZE = 240;

  constructor(buffer, offset = 0) {
    this.view = new DataView(buffer, offset, this.constructor.SIZE);
    this.bytes = new Uint8Array(buffer, offset);
  }

  size() {
    return this.constructor.SIZE;
  }

  get typeAndPayloadSize() {
    const val = (this.view.getUint32(0) ^ this.view.getUint32(4)) >>> 0;
    return {
      type: ((val & 0xFFFF0000) >>> 16) >>> 0,
      size: (val & 0x0000FFFF) >>> 0
    }
  }

  set typeAndPayloadSize({type, size}) {
    const preamble = new Uint32Array(1);
    window.crypto.getRandomValues(preamble);
    let tns = ((type & 0x0000FFFF) << 16 | size & 0x0000FFFF) >>> 0;
    tns = (preamble[0] ^ tns) >>> 0;
    this.view.setUint32(0, preamble[0]);
    this.view.setUint32(4, tns);
  }

  get version() { return {major: this.view.getUint8(8), minor: this.view.getUint8(9)}; }
  set version({major, minor}) { this.view.setUint8(8, major); this.view.setUint8(9, minor); }

  get flags() {
    const flag = this.view.getUint16(10);
    return {
      extended: Boolean((flag & 0x1) >>> 0),
      compressed: Boolean((flag & 0x2) >>> 0)
    }
  }
  set flags({extended, compressed}) {
    const flag = new Uint16Array(1)
    if (extended) {
      flag[0] = (flag[0] | 0x1) >>> 0;
    }
    if (compressed) {
      flag[0] = (flag[0] | 0x2) >>> 0;
    }
    this.view.setUint16(10, flag[0]);
  }

  get counter() { return this.view.getBigUint64(16); }
  set counter(v) { this.view.setBigUint64(16, v); }

  get nonce() {
    const bytes = new Uint8Array(12);
    bytes.set(this.bytes.subarray(16, 24), 4);
    return bytes;
  }

  get ephermeral() { return this.bytes.subarray(24, 24+32); }
  set ephermeral(bytes) {
    if (bytes.length == 32) {
      this.bytes.set(bytes, 24);
    }
  }

  get identity() { return this.bytes.subarray(56, 56+80); }
  set identity(bytes) {
    if (bytes.length == 80) {
      this.bytes.set(bytes, 56);
    }
  }

  get static() { return this.bytes.subarray(136, 136+48); }
  set static(bytes) {
    if (bytes.length == 48) {
      this.bytes.set(bytes, 136);
    }
  }

  get timestamp() { return this.bytes.subarray(184, 184+24); }
  set timestamp(bytes) {
    if (bytes.length == 24) {
      this.bytes.set(bytes, 184);
    }
  }

  get hmac() { return this.bytes.subarray(208, 208+32); }
  set hmac(bytes) {
    if (bytes.length == 32) {
      this.bytes.set(bytes, 208);
    }
  }
}

class NHPHeaderEx {
  static SIZE = 304;

  constructor(buffer, offset = 0) {
    this.view = new DataView(buffer, offset, this.constructor.SIZE);
    this.bytes = new Uint8Array(buffer, offset);
  }

  size() {
    return this.constructor.SIZE;
  }

  get typeAndPayloadSize() {
    const val = (this.view.getUint32(0) ^ this.view.getUint32(4)) >>> 0;
    return {
      type: ((val & 0xFFFF0000) >>> 16) >>> 0,
      size: (val & 0x0000FFFF) >>> 0
    }
  }

  set typeAndPayloadSize({type, size}) {
    const preamble = new Uint32Array(1);
    window.crypto.getRandomValues(preamble);
    let tns = ((type & 0x0000FFFF) << 16 | size & 0x0000FFFF) >>> 0;
    tns = (preamble[0] ^ tns) >>> 0;
    this.view.setUint32(0, preamble[0]);
    this.view.setUint32(4, tns);
  }

  get version() { return {major: this.view.getUint8(8), minor: this.view.getUint8(9)}; }
  set version({major, minor}) { this.view.setUint8(8, major); this.view.setUint8(9, minor); }

  get flags() {
    const flag = this.view.getUint16(10);
    return {
      extended: Boolean((flag & 0x1) >>> 0),
      compressed: Boolean((flag & 0x2) >>> 0)
    }
  }
  set flags({extended, compressed}) {
    const flag = new Uint16Array(1)
    if (extended) {
      flag[0] = (flag[0] | 0x1) >>> 0;
    }
    if (compressed) {
      flag[0] = (flag[0] | 0x2) >>> 0;
    }
    this.view.setUint16(10, flag[0]);
  }

  get counter() { return this.view.getBigUint64(16); }
  set counter(v) { this.view.setBigUint64(16, v); }

  get nonce() {
    const bytes = new Uint8Array(12);
    bytes.set(this.bytes.subarray(16, 24), 4);
    return bytes;
  }

  get ephermeral() { return this.bytes.subarray(24, 24+64); }
  set ephermeral(bytes) {
    if (bytes.length == 64) {
      this.bytes.set(bytes, 24);
    }
  }

  get identity() { return this.bytes.subarray(88, 88+80); }
  set identity(bytes) {
    if (bytes.length == 80) {
      this.bytes.set(bytes, 88);
    }
  }

  get static() { return this.bytes.subarray(168, 168+80); }
  set static(bytes) {
    if (bytes.length == 80) {
      this.bytes.set(bytes, 168);
    }
  }

  get timestamp() { return this.bytes.subarray(248, 248+24); }
  set timestamp(bytes) {
    if (bytes.length == 24) {
      this.bytes.set(bytes, 248);
    }
  }

  get hmac() { return this.bytes.subarray(272, 272+32); }
  set hmac(bytes) {
    if (bytes.length == 32) {
      this.bytes.set(bytes, 272);
    }
  }
}

export async function buildNHPPacket(type, privateKey, publicKey, remotePublicKey, msg, compress, identity) {
  let header;
  let localPrivKey;
  let localPubKey;
  let remotePubKey;
  const packet = new Uint8Array(PacketBufferSize);
  if (privateKey.length === 44) {
    header = new NHPHeader(packet.buffer);
    localPrivKey = await base64ToX25519PrivateKey(privateKey);
    localPubKey = await base64ToX25519PublicKey(publicKey);
    remotePubKey = await base64ToX25519PublicKey(remotePublicKey);
    header.flags = {extended: false, compressed: compress};
  } else {
    // header = new NHPHeaderEx(packet.buffer);
    // localPrivKey = base64ToSM2PrivateKey(privateKey);
    // localPubKey = base64ToSM2PublicKey(publicKey);
    // remotePubKey = base64ToSM2PublicKey(remotePublicKey);
    // header.flags = {extended: true, compressed: compress};
    throw new Error('gm scheme is not supported by now');
  }
  const localPrivKeyBytes = base64ToBytes(privateKey);
  const localPubKeyBytes = base64ToBytes(publicKey);
  const remotePubKeyBytes = base64ToBytes(remotePublicKey);
  const msgBytes = stringToBytes(msg);
  //console.log("localPrivKeyBytes: ", localPrivKeyBytes);
  //console.log("localPubKeyBytes: ", localPubKeyBytes);
  //console.log("remotePubKeyBytes: ", remotePubKeyBytes);
  //console.log("msgBytes: ", msgBytes);

  header.version = {major: 1, minor: 0};
  GlobalCounter[0]++;
  header.counter = GlobalCounter[0];
  const nonce = header.nonce;

  const chainKey = new Uint8Array(32);
  const chainHash = new Uint8Array(32);
  const hmacHasher = newSHA256Hash();
  const chainHasher = newSHA256Hash();
  //console.log("chainHash: ", chainHash, "\nchainKey:", chainKey);

  updateSHA256(hmacHasher, stringToBytes(InitialHashString));
  updateSHA256(chainHasher, stringToBytes(InitialHashString));
  chainHash.set(sumSHA256(chainHasher));
  chainKey.set(mixKey(chainHash, stringToBytes(InitialChainKeyString)));
  //console.log("chainHash0: ", chainHash, "\nchainKey0:", chainKey);

  updateSHA256(hmacHasher, remotePubKeyBytes);
  updateSHA256(chainHasher, remotePubKeyBytes);

  const ephermeralKeys = await generateX25519KeyPair();
  const ePublickeyBytes = await x25519PublicKeyToBytes(ephermeralKeys.publicKey);
  header.ephermeral = ePublickeyBytes;
  updateSHA256(chainHasher, ePublickeyBytes);
  chainHash.set(sumSHA256(chainHasher));
  chainKey.set(mixKey(chainKey, ePublickeyBytes));
  //console.log("chainHash1: ", chainHash, "\nchainKey1:", chainKey);

  const essKey = await ecdhX25519(ephermeralKeys.privateKey, remotePubKey);
  const ess = await x25519PublicKeyToBytes(essKey);
  //console.log("essBytes: ", ess);

  // encrypt local public key
  const derivedKeys0 = keyGen2(chainKey, ess);
  chainKey.set(derivedKeys0.first);
  
  //console.log("chainHash2: ", chainHash, "\nchainKey2:", chainKey);
  //console.log("key: ", derivedKeys0.second);
  //console.log("localPubKeyBytes: ", localPubKeyBytes);
  //console.log("nonce: ", nonce);
  const keyStatic = chacha20Seal(derivedKeys0.second, nonce, localPubKeyBytes, chainHash);
  //console.log("keyStaticBytes: ", keyStatic)
  header.static = keyStatic;

  updateSHA256(chainHasher, keyStatic);
  chainHash.set(sumSHA256(chainHasher));

  const ssKey = await ecdhX25519(localPrivKey, remotePubKey);
  const ss = await x25519PublicKeyToBytes(ssKey);

  // encrypt timestamp
  const derivedKeys1 = keyGen2(chainKey, ss);
  chainKey.set(derivedKeys1.first);
  //console.log("chainHash3: ", chainHash, "\nchainKey3:", chainKey);

  const tsBuf = new ArrayBuffer(8);
  const tsView = new DataView(tsBuf);
  const timestamp = getUnixNano();
  tsView.setBigUint64(0, timestamp);
  const ts = new Uint8Array(tsBuf);
  lastSendTimeMap.set(remotePublicKey, timestamp);

  const tsStatic = chacha20Seal(derivedKeys1.second, nonce, ts, chainHash);
  header.timestamp = tsStatic;

  // encrypt msg
  const derivedKeys2 = keyGen2(chainKey, tsStatic);
  chainKey.set(derivedKeys2.first);
  updateSHA256(chainHasher, tsStatic);
  chainHash.set(sumSHA256(chainHasher));
  //console.log("chainHash4: ", chainHash, "\nchainKey4:", chainKey);

  let payload = msgBytes;
  if (compress) {
    payload = await zlibCompress(msgBytes);
  }
  //console.log("payload: ", payload)
  const msgStatic = chacha20Seal(derivedKeys2.second, nonce, payload, chainHash);
  //console.log("msgStatic: ", msgStatic);
  packet.set(msgStatic, header.size());

  const payloadSize = payload.byteLength + 16;
  header.typeAndPayloadSize = {type: type, size: payloadSize};

  // hmac
  if (type === NHP_RNK_TYPE) {
    const cookie = serverCookieMap.get(remotePublicKey);
    if (cookie != null) {
      updateSHA256(hmacHasher, cookie);
    }
  }
  updateSHA256(hmacHasher, packet.subarray(0, header.size()-32));
  header.hmac = sumSHA256(hmacHasher);
  //console.log("hmac: ", header.hmac);
  //console.log("header size: ", header.size());

  return packet.subarray(0, header.size()+payloadSize);
}

export async function parseNHPPacket(packet, privateKey, publicKey, remotePublicKey) {
  if (packet.length < NHPHeader.SIZE) {
    throw new Error('packet size is too small');
  }
  let header = new NHPHeader(packet.buffer);
  const {extended, compressed} = header.flags;
  if (extended) {
    //header = new NHPHeaderEx(packet.buffer);
    throw new Error('gm scheme is not supported by now');
  }

  const {type, size} = header.typeAndPayloadSize;
  //console.log("header type: ", type, "size: ", size);
  if (type !== NHP_ACK_TYPE && type !== NHP_COK_TYPE) {
    throw new Error('not an ACK or COK packet');
  }

  if (packet.length !== header.size() + size) {
    throw new Error('wrong packet size');
  }

  const recvTime = getUnixNano();
  // check hmac
  const localPubKeyBytes = base64ToBytes(publicKey);
  const hmacHasher = newSHA256Hash();
  updateSHA256(hmacHasher, stringToBytes(InitialHashString));
  updateSHA256(hmacHasher, localPubKeyBytes);
  updateSHA256(hmacHasher, packet.subarray(0, header.size()-32));
  const checkSum = sumSHA256(hmacHasher);
  if (!equalBytes(checkSum, header.hmac)) {
    throw new Error('hmac check failed');
  }

  const localPrivKey = await base64ToX25519PrivateKey(privateKey);
  const localPubKey = await base64ToX25519PublicKey(publicKey);
  const remotePubKey = await base64ToX25519PublicKey(remotePublicKey);
  const remotePubKeyBytes = base64ToBytes(remotePublicKey);

  //const localPrivKeyBytes = base64ToBytes(privateKey);
  //console.log("localPrivKeyBytes: ", localPrivKeyBytes);
  //console.log("localPubKeyBytes: ", localPubKeyBytes);
  //console.log("remotePubKeyBytes: ", remotePubKeyBytes);

  const ePublicKeyBytes = header.ephermeral;
  //console.log("ePublicKeyBytes: ", ePublicKeyBytes);
  const ePublickey = await bytesToX25519PublicKey(ePublicKeyBytes);
  const nonce = header.nonce;
  const keyStatic = header.static;
  const tsStatic = header.timestamp;
  const msgStatic = packet.subarray(header.size());
  //console.log("msgStatic: ", msgStatic);

  const chainKey = new Uint8Array(32);
  const chainHash = new Uint8Array(32);
  //console.log("pchainHash: ", chainHash, "\npchainKey:", chainKey);

  const chainHasher = newSHA256Hash();
  updateSHA256(chainHasher, stringToBytes(InitialHashString));
  chainHash.set(sumSHA256(chainHasher));
  chainKey.set(mixKey(chainHash, stringToBytes(InitialChainKeyString)));
  //console.log("pchainHash1: ", chainHash, "\npchainKey1:", chainKey);

  updateSHA256(chainHasher, localPubKeyBytes);
  updateSHA256(chainHasher, ePublicKeyBytes);
  chainHash.set(sumSHA256(chainHasher));
  chainKey.set(mixKey(chainKey, ePublicKeyBytes));
  //console.log("pchainHash2: ", chainHash, "\npchainKey2:", chainKey);

  const essKey = await ecdhX25519(localPrivKey, ePublickey);
  const ess = await x25519PublicKeyToBytes(essKey);

  // decrypt remote public key
  const derivedKeys0 = keyGen2(chainKey, ess);
  chainKey.set(derivedKeys0.first);
  const decryptedPubKeyBytes = chacha20Open(derivedKeys0.second, nonce, keyStatic, chainHash);
  if (!equalBytes(remotePubKeyBytes, decryptedPubKeyBytes)) {
    throw new Error('remote public key check failed');
  }

  updateSHA256(chainHasher, keyStatic);
  chainHash.set(sumSHA256(chainHasher));
  //console.log("pchainHash3: ", chainHash, "\npchainKey3:", chainKey);

  const ssKey = await ecdhX25519(localPrivKey, remotePubKey);
  const ss = await x25519PublicKeyToBytes(ssKey);

  // decrypt timestamp
  const derivedKeys1 = keyGen2(chainKey, ss);
  chainKey.set(derivedKeys1.first);

  const decryptedTs = chacha20Open(derivedKeys1.second, nonce, tsStatic, chainHash);
  const tsView = new DataView(decryptedTs.buffer);
  const remoteSendTime = tsView.getBigUint64(0);
  const lastRemoteSendTime = lastRemoteSendTimeMap.get(remotePublicKey);
  lastRemoteSendTimeMap.set(remotePublicKey, remoteSendTime);
  if (lastRemoteSendTime != null) {
    if (remoteSendTime < lastRemoteSendTime) {
      throw new Error('received replay packet');
    }
  }
  if (lastRemoteSendTime != null) {
    if (remoteSendTime < lastRemoteSendTime + BigInt(20*1000*1000)) {
      throw new Error('received flood packet');
    }
  }
  if (remoteSendTime < recvTime - BigInt(600*1000*1000*1000)) {
    throw new Error('received stale packet');
  }

  // decrypt msg
  const derivedKeys2 = keyGen2(chainKey, header.timestamp);
  chainKey.set(derivedKeys2.first);
  updateSHA256(chainHasher, tsStatic);
  chainHash.set(sumSHA256(chainHasher));
  //console.log("pchainHash4: ", chainHash, "\npchainKey4:", chainKey);

  let msg = chacha20Open(derivedKeys2.second, nonce, msgStatic, chainHash);
  //console.log("compressed msg", msg);
  if (compressed) {
    msg = await zlibDecompress(msg);
  }

  //console.log("msg", msg);
  if (type === NHP_COK_TYPE) {
    updateCookie(remotePublicKey, msg);
  }

  return {
    type: type,
    msg: bytesToString(msg)
  };
}

function updateCookie(remotePublicKey, bytes)
{
  serverCookieMap.set(remotePublicKey, bytes);
}
