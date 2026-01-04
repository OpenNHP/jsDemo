# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

OpenNHP JavaScript Agent - A JavaScript implementation of the NHP (Network-infrastructure Hiding Protocol) for zero-trust network security. The project demonstrates NHP authentication flows and connection status visualization.

**Live Demo:** https://js-agent.opennhp.org

## Project Structure

The repository has two main components:

1. **Root-level demo** (`/index.html`) - Static HTML demo page with i18n support (EN/ZH/ES) that demonstrates the NHP authentication flow via Okta integration. Deployed directly to GitHub Pages.

2. **NHP-JS library** (`/nhp-js/`) - The core NHP protocol implementation as a Vite-bundled JavaScript library.

## Build Commands

All commands must be run from the `/nhp-js` directory:

```bash
cd nhp-js

# Install dependencies
npm install

# Development server with hot reload
npm run dev

# Build the library (outputs to nhp-js/dist/)
npm run build

# Preview the production build
npm run preview
```

The build produces `nhp-js/dist/nhp-js-lib.js` which is imported by `main.js` for testing.

## Architecture

### NHP Protocol Library (`nhp-js/src/`)

- **nhp.js** - Main entry point. Implements NHP packet building and parsing:
  - `buildNHPPacket()` - Constructs encrypted NHP packets with X25519 key exchange
  - `parseNHPPacket()` - Decrypts and validates incoming NHP packets
  - `NHPHeader` / `NHPHeaderEx` - Binary packet header structures (240 / 304 bytes)
  - Packet types: KNK (1), ACK (2), COK (7), RNK (8)

- **crypto.js** - Cryptographic primitives:
  - X25519 key generation and ECDH via Web Crypto API
  - PKCS#8 encoding/decoding for private keys
  - SHA-256 hashing and HMAC via CryptoJS
  - ChaCha20-Poly1305 AEAD encryption via @noble/ciphers

- **crypto_gm.js** - Chinese GM/T cryptographic standards (SM2) - currently disabled

- **utils.js** - Utility functions: base64 encoding, zlib compression via CompressionStream API

### Key Dependencies

- `@noble/ciphers` - ChaCha20-Poly1305 AEAD
- `@noble/curves` - Elliptic curve operations
- `crypto-js` - SHA-256 and HMAC
- `gm-crypto` - SM2/SM3/SM4 (Chinese cryptography standards)

### Demo Page (`/index.html`)

Static single-file demo with:
- Tailwind CSS (CDN)
- Built-in i18n system with translations object
- Okta OAuth integration for authentication
- Connection to `acdemo.opennhp.org` protected server

## Deployment

The root `index.html` is deployed via GitHub Pages to `js-agent.opennhp.org`. The CNAME file configures the custom domain.
