import { SM2, SM3, SM4 } from 'gm-crypto';
import { Field } from '@noble/curves/abstract/modular.js';
import { weierstrass } from '@noble/curves/abstract/weierstrass.js';
import { hexToBytes, bytesToHex } from '@noble/curves/utils.js';
import { bytesToBase64, base64ToBytes} from "./utils.js"

export function generateSM2KeyPair()
{
  return SM2.generateKeyPair();
}

export function generateSM2KeyPairBase64()
{
  const { publicKey, privateKey } = SM2.generateKeyPair();
  const actualPublicKey = publicKey.slice(2); // strip the first 04 byte
  const privKeyBytes = hexToBytes(privateKey);
  const pubKeyBytes = hexToBytes(actualPublicKey);
  return {
    privKeyStr: bytesToBase64(privKeyBytes),
    pubKeyStr: bytesToBase64(pubKeyBytes)
  };
}

export function bytesToSM2PrivateKey(bytes) {
    return bytesToHex(bytes);
}

export function bytesToSM2PublicKey(bytes) {
    return "04" + bytesToHex(bytes);
}

export function base64ToSM2PrivateKey(b64) {
  const bytes = base64ToBytes(b64);
  return bytesToSM2PrivateKey(bytes);
}

export function base64ToSM2PublicKey(b64) {
  const bytes = base64ToBytes(b64);
  return bytesToSM2PublicKey(bytes);
}

function bigIntToUint8Array(bi, length = 32) {
  let hex = bi.toString(16);
  if (hex.length % 2) hex = '0' + hex;

  const bytes = Uint8Array.from(
    hex.match(/.{2}/g).map(b => parseInt(b, 16))
  );

  if (bytes.length > length) {
    throw new Error('BigInt too large');
  }

  // left-pad with zeros (big-endian)
  const out = new Uint8Array(length);
  out.set(bytes, length - bytes.length);
  return out;
}

// sm2p256v1 curve
const sm2Curve = weierstrass({
  a: BigInt('0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC'),
  b: BigInt('0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93'),
  p: BigInt('0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF'),
  n: BigInt('0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123'),
  Gx: BigInt('0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7'),
  Gy: BigInt('0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0'),
  h: BigInt(1),
});

export function ecdhSM2Raw(privateKey, remotePublicKey) {
  // shared point
  const P = sm2Curve.ProjectivePoint.fromHex(remotePublicKey)
      .multiply(BigInt('0x' + privateKey));
  // raw shared secret
  const S = P.toAffine();
  const xBytes = bigIntToUint8Array(S.x);
  const bytes = new Uint8Array(32);
  bytes.set(xBytes, 0);

  return bytes;
}
