# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

OpenNHP JavaScript Agent — A TypeScript/JavaScript SDK (`@opennhp/agent`) implementing the NHP (Network-infrastructure Hiding Protocol) for zero-trust network security, plus a static demo page.

**Live Demo:** https://js-agent.opennhp.org

## Repository Structure

Two independent components:

1. **`/index.html`** — Static demo page with i18n (EN/ZH/ES) and Okta OAuth integration. Deployed to GitHub Pages at `js-agent.opennhp.org`.

2. **`/nhp-js/`** — Core SDK library. TypeScript source in `src/`, built with Vite into `dist/`.

## Build & Dev Commands

All commands run from `/nhp-js/`:

```bash
cd nhp-js
npm install

npm run dev          # Vite dev server (http://localhost:5173), loads main.js
npm run build        # Build to dist/ (ES + CJS + .d.ts)
npm run preview      # Preview production build

npm test             # Vitest watch mode
npm run test:run     # Run tests once
npm run test:coverage  # Coverage report in coverage/

npm run lint         # ESLint
npm run lint:fix     # Auto-fix
npm run format       # Prettier
npm run docs         # TypeDoc → docs/
```

Build outputs: `dist/index.js` (ESM), `dist/index.cjs` (CJS), `dist/index.d.ts` (types).

## Architecture

### Source layout (`nhp-js/src/`)

```text
src/
├── index.ts          # Public API exports
├── NHPAgent.ts       # High-level agent class (main SDK entry point)
├── types.ts          # All TypeScript interfaces and enums
├── crypto/
│   ├── index.ts      # Re-exports key crypto utilities
│   ├── ecdh.ts       # X25519 key generation and ECDH
│   ├── aead.ts       # AES-256-GCM encrypt/decrypt
│   ├── noise.ts      # Blake2s hash, HMAC, HKDF-like key derivation (Noise protocol)
│   ├── sm2.ts        # SM2 elliptic curve key generation and ECDH (GMSM)
│   ├── sm3.ts        # SM3 hash and HMAC (GMSM)
│   ├── sm4.ts        # SM4-GCM encrypt/decrypt (GMSM)
│   └── utils.ts      # base64, hex, zlib compress/decompress, getUnixNano
├── protocol/
│   ├── index.ts      # Re-exports
│   ├── constants.ts  # Packet types, header sizes, offsets, field sizes
│   ├── header.ts     # NHPHeader (240 B, curve25519) / NHPHeaderEx (304 B, gmsm)
│   └── packet.ts     # buildNHPPacket(), parseNHPPacket(), clearServerCookie()
└── transport/
    ├── index.ts      # Re-exports
    ├── udp.ts        # UDP transport (Node.js default)
    ├── webrtc.ts     # WebRTC DataChannel transport (experimental)
    ├── websocket.ts  # WebSocket transport (legacy)
    └── relay.ts      # HTTP Relay transport (browser → relay → NHP Server)
```

### Key classes and functions

**`NHPAgent`** (`NHPAgent.ts`) — High-level SDK class:

- `init()` — generates or loads key pair
- `setIdentity({ userId, deviceId, organizationId })` — set knock identity
- `addServer({ publicKey, host, port })` — register an NHP server
- `knockResource({ resourceId, serviceId, serverHost, serverPort })` — returns `KnockResult`
- `close()` — disconnect and cleanup
- Transport auto-selected: `relay` in browser (requires `relayUrl`), `udp` in Node.js

**`buildNHPPacket(type, privKey, pubKey, remotePubKey, message, compress, cipherScheme)`** — builds binary NHP packet. Both keys and remote key are base64 strings.

**`parseNHPPacket(packet, privKey, pubKey, remotePubKey)`** — decrypts and validates an ACK or COK packet. Throws on HMAC failure, wrong size, replay, or stale timestamp.

### Protocol

4-step handshake (Noise-protocol-inspired):

1. Agent → Server: **KNK** (knock with identity + resource)
2. Server → Agent: **COK** (optional, server overloaded — contains cookie)
3. Agent → Server: **RNK** (re-knock with cookie in HMAC)
4. Server → Agent: **ACK** (access granted, contains resource hosts + expiry)

### Cipher schemes

| Scheme | Key Exchange | Hash | AEAD | Header |
| ------ | ------------ | ---- | ---- | ------ |
| `curve25519` (default) | X25519 ECDH | Blake2s-256 | AES-256-GCM | 240 bytes |
| `gmsm` | SM2 ECDH | SM3 | SM4-GCM | 304 bytes |

Auto-detection: if public key base64 length > 50 chars → `gmsm`, otherwise `curve25519`.

**Important:** `parseNHPPacket` routes to GMSM parser by reading the `extended` flag bit at header offset 10–11 (big-endian uint16, bit 0x1). Do not change this to little-endian.

### Key dependencies

- `@noble/ciphers` — AES-256-GCM
- `@noble/curves` — X25519
- `@noble/hashes` — Blake2s
- `sm-crypto-v2` — SM2/SM3/SM4

### Test layout (`nhp-js/test/`)

```text
test/
├── crypto/
│   ├── aead.test.ts    # AES-256-GCM round-trip and error cases
│   ├── ecdh.test.ts    # X25519 key gen, ECDH, Go test vectors
│   ├── gmsm.test.ts    # SM2/SM3/SM4 operations
│   └── noise.test.ts   # Blake2s, HMAC, key derivation
└── protocol/
    ├── header.test.ts  # NHPHeader / NHPHeaderEx field read-write
    └── packet.test.ts  # buildNHPPacket/parseNHPPacket round-trips,
                        # COK/RNK flow, error cases, anti-replay, GMSM
```

### Known issues / gotchas

- **UDP and zlib** use Node.js built-ins (`dgram`, `zlib`). Vite externalizes them for browser builds — this is expected. Browser zlib uses `CompressionStream` API (see `utils.ts`).
- **`main.js`** is a manual debug entry point for the Vite dev server, not a production file. It is excluded from ESLint.
- **`resetGlobalCounter()`** is exported for test isolation — call it in `beforeEach` when writing packet tests to avoid counter-dependent failures. It also clears the internal `lastBuildChainKeyMap`.
- **Noise chain key between KNK and ACK is all-zeros.** Both Go server (`decryptBody` defer) and Go agent (`encryptBody` defer) clear `chainKey` after processing. The JS agent passes `new Uint8Array(32)` as `prevChainKey` when parsing ACK responses to match this behavior. Do not change this without updating both Go and JS sides.
- **Relay transport response matching** uses the inner packet's counter (header bytes `[16:24]`, big-endian uint64) to correlate HTTP requests with UDP responses. The relay does not decrypt ACK/COK packets — it forwards raw encrypted bytes.
- **`errCode: "0"` means success** in the NHP protocol. The `parseAckResponse` method treats `"0"` and `""` as success; any other value is an error.

## Deployment

`/index.html` auto-deploys to `js-agent.opennhp.org` via GitHub Pages on push to `main`. CI (`.github/workflows/ci.yml`) runs build + tests on Node.js 18, 20, 22 for every push and PR.
