/**
 * TypeScript interfaces for OpenNHP Agent SDK
 */

/** Cipher scheme for cryptographic operations */
export type CipherScheme = 'curve25519' | 'gmsm';

/** Log level for SDK output */
export type LogLevel = 'silent' | 'error' | 'info' | 'debug';

/** Configuration for initializing the NHP Agent */
export interface NHPAgentConfig {
  /** Base64-encoded private key. If not provided, one will be generated */
  privateKey?: string;
  /** Cipher scheme to use for cryptographic operations */
  cipherScheme?: CipherScheme;
  /** Logging level */
  logLevel?: LogLevel;
}

/** Configuration for an NHP server */
export interface ServerConfig {
  /** Unique identifier for the server */
  id?: string;
  /** Base64-encoded public key of the server */
  publicKey: string;
  /** Server hostname or IP address */
  host: string;
  /** Server port number */
  port: number;
  /** Optional expiration timestamp (Unix milliseconds) */
  expiresAt?: number;
}

/** Configuration for a resource to knock */
export interface ResourceConfig {
  /** Resource identifier */
  resourceId: string;
  /** Service identifier */
  serviceId: string;
  /** Server hostname for the knock */
  serverHost: string;
  /** Server port for the knock */
  serverPort: number;
}

/** Result of a knock operation */
export interface KnockResult {
  /** Whether the knock was successful */
  success: boolean;
  /** Access token received on success */
  accessToken?: string;
  /** Expiration timestamp of the access (Unix milliseconds) */
  expiresAt?: number;
  /** Error message if knock failed */
  error?: string;
  /** Error code if knock failed */
  errorCode?: number;
}

/** Events emitted by the NHP Agent */
export type NHPAgentEvent = 'connected' | 'disconnected' | 'error' | 'knock' | 'ack';

/** Event handler function type */
export type EventHandler<T = unknown> = (data: T) => void;

/** X25519 Key pair */
export interface KeyPair {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
}

/** Base64 encoded key pair */
export interface KeyPairBase64 {
  privateKey: string;
  publicKey: string;
}

/** NHP packet type identifiers */
export enum PacketType {
  KNK = 1,  // Knock
  ACK = 2,  // Acknowledge
  AOP = 3,  // Agent Operation
  ART = 4,  // Agent Report
  LST = 5,  // List
  LRT = 6,  // List Report
  COK = 7,  // Cookie
  RNK = 8,  // Re-knock
  RLY = 9,  // Relay
  AOL = 10, // Agent Online
}

/** NHP protocol version */
export interface ProtocolVersion {
  major: number;
  minor: number;
}

/** NHP packet header flags */
export interface HeaderFlags {
  /** Whether extended header format is used (for GM crypto) */
  extended: boolean;
  /** Whether payload is compressed */
  compressed: boolean;
}

/** Parsed NHP packet result */
export interface ParsedPacket {
  /** Packet type */
  type: PacketType;
  /** Decoded message payload */
  message: string;
  /** Remote public key (base64) */
  remotePublicKey?: string;
}

/** Connection state for transport */
export type ConnectionState = 'disconnected' | 'connecting' | 'connected' | 'reconnecting';

/** WebSocket transport configuration */
export interface WebSocketTransportConfig {
  /** WebSocket URL */
  url: string;
  /** Reconnect automatically on disconnect */
  autoReconnect?: boolean;
  /** Maximum reconnection attempts */
  maxReconnectAttempts?: number;
  /** Base delay between reconnection attempts (ms) */
  reconnectDelay?: number;
}

/** Transport message */
export interface TransportMessage {
  /** Raw packet data */
  data: Uint8Array;
  /** Source address (if applicable) */
  remoteAddress?: string;
  /** Source port (if applicable) */
  remotePort?: number;
}
