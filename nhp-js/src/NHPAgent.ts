/**
 * NHPAgent - Main OpenNHP Agent SDK Class
 * Provides a high-level API for NHP authentication and connection management
 */

import type {
  NHPAgentConfig,
  ServerConfig,
  ResourceConfig,
  KnockResult,
  NHPAgentEvent,
  EventHandler,
  KeyPairBase64,
  LogLevel,
} from './types.js';
import { generateX25519KeyPairBase64 } from './crypto/ecdh.js';
import { base64ToBytes } from './crypto/utils.js';
import { buildNHPPacket, parseNHPPacket, clearServerCookie } from './protocol/packet.js';
import { NHP_PACKET_TYPES } from './protocol/constants.js';
import { WebSocketTransport } from './transport/websocket.js';

/** Default agent configuration */
const DEFAULT_CONFIG: Required<Omit<NHPAgentConfig, 'privateKey'>> = {
  cipherScheme: 'curve25519',
  logLevel: 'error',
};

/**
 * OpenNHP Agent SDK
 *
 * @example
 * ```typescript
 * const agent = new NHPAgent({
 *   cipherScheme: 'curve25519',
 *   logLevel: 'info'
 * });
 *
 * await agent.init();
 * agent.setUser('user123', 'opennhp.org');
 * agent.addServer({
 *   publicKey: 'abc123...',
 *   host: 'nhp.example.com',
 *   port: 62206
 * });
 *
 * const result = await agent.knockResource({
 *   resourceId: 'demo',
 *   serviceId: 'example',
 *   serverHost: 'nhp.example.com',
 *   serverPort: 62206
 * });
 *
 * if (result.success) {
 *   console.log('Access granted until:', result.expiresAt);
 * }
 *
 * await agent.close();
 * ```
 */
export class NHPAgent {
  private config: Required<Omit<NHPAgentConfig, 'privateKey'>> & { privateKey?: string };
  private keyPair: KeyPairBase64 | null = null;
  private userId: string | null = null;
  private organizationId: string | null = null;
  private servers: Map<string, ServerConfig> = new Map();
  private transports: Map<string, WebSocketTransport> = new Map();
  private eventHandlers: Map<NHPAgentEvent, Set<EventHandler>> = new Map();
  private initialized = false;

  constructor(config: NHPAgentConfig = {}) {
    this.config = {
      ...DEFAULT_CONFIG,
      ...config,
    };

    if (this.config.cipherScheme === 'gmsm') {
      throw new Error('GM SM2/SM3/SM4 cipher scheme is not yet supported');
    }
  }

  /**
   * Initialize the agent
   * Generates key pair if not provided in config
   */
  async init(): Promise<void> {
    if (this.initialized) {
      return;
    }

    if (this.config.privateKey) {
      // Derive public key from provided private key
      const privateKeyBytes = base64ToBytes(this.config.privateKey);
      if (privateKeyBytes.length !== 32) {
        throw new Error('Invalid private key length');
      }
      // For now, we require both keys to be provided
      throw new Error('Public key derivation not implemented. Please provide both keys.');
    } else {
      // Generate new key pair
      this.keyPair = await generateX25519KeyPairBase64();
      this.log('info', 'Generated new X25519 key pair');
    }

    this.initialized = true;
    this.log('info', 'NHPAgent initialized');
  }

  /**
   * Close the agent and cleanup resources
   */
  async close(): Promise<void> {
    // Disconnect all transports
    for (const transport of this.transports.values()) {
      transport.disconnect();
    }
    this.transports.clear();

    // Clear server cookies
    for (const server of this.servers.values()) {
      clearServerCookie(server.publicKey);
    }
    this.servers.clear();

    this.initialized = false;
    this.log('info', 'NHPAgent closed');
  }

  /**
   * Set the user identity for knock requests
   */
  setUser(userId: string, organizationId?: string): void {
    this.userId = userId;
    this.organizationId = organizationId ?? null;
    this.log('debug', `User set: ${userId}${organizationId ? ` (${organizationId})` : ''}`);
  }

  /**
   * Add a server configuration
   */
  addServer(config: ServerConfig): void {
    const serverId = config.id ?? `${config.host}:${config.port}`;
    this.servers.set(serverId, { ...config, id: serverId });
    this.log('debug', `Server added: ${serverId}`);
  }

  /**
   * Remove a server configuration
   */
  removeServer(serverId: string): void {
    const server = this.servers.get(serverId);
    if (server) {
      clearServerCookie(server.publicKey);
      this.servers.delete(serverId);

      const transport = this.transports.get(serverId);
      if (transport) {
        transport.disconnect();
        this.transports.delete(serverId);
      }

      this.log('debug', `Server removed: ${serverId}`);
    }
  }

  /**
   * Get the agent's public key (base64 encoded)
   */
  getPublicKey(): string {
    if (!this.keyPair) {
      throw new Error('Agent not initialized');
    }
    return this.keyPair.publicKey;
  }

  /**
   * Knock on a resource to request access
   */
  async knockResource(resource: ResourceConfig): Promise<KnockResult> {
    if (!this.initialized || !this.keyPair) {
      return {
        success: false,
        error: 'Agent not initialized',
        errorCode: 1,
      };
    }

    if (!this.userId) {
      return {
        success: false,
        error: 'User not set',
        errorCode: 2,
      };
    }

    const serverId = `${resource.serverHost}:${resource.serverPort}`;
    const server = this.servers.get(serverId);

    if (!server) {
      return {
        success: false,
        error: `Server not configured: ${serverId}`,
        errorCode: 3,
      };
    }

    try {
      // Build knock message
      const knockMessage = JSON.stringify({
        userId: this.userId,
        organizationId: this.organizationId,
        resourceId: resource.resourceId,
        serviceId: resource.serviceId,
        timestamp: Date.now(),
      });

      // Build knock packet
      const packet = await buildNHPPacket(
        NHP_PACKET_TYPES.KNK,
        this.keyPair.privateKey,
        this.keyPair.publicKey,
        server.publicKey,
        knockMessage,
        true // compress
      );

      this.log('debug', `Knock packet built: ${packet.length} bytes`);
      this.emit('knock', { resource, packet });

      // Get or create transport
      let transport = this.transports.get(serverId);
      if (!transport) {
        const wsUrl = `wss://${resource.serverHost}:${resource.serverPort}/nhp`;
        transport = new WebSocketTransport({
          url: wsUrl,
          autoReconnect: false,
        });
        this.transports.set(serverId, transport);
      }

      // Send packet and wait for response
      const response = await this.sendAndWaitForResponse(transport, packet, server.publicKey);

      if (response) {
        this.log('info', 'Knock successful');
        this.emit('ack', response);

        return {
          success: true,
          accessToken: response.accessToken,
          expiresAt: response.expiresAt,
        };
      }

      return {
        success: false,
        error: 'No response received',
        errorCode: 4,
      };
    } catch (err) {
      const error = err instanceof Error ? err.message : 'Unknown error';
      this.log('error', `Knock failed: ${error}`);
      this.emit('error', err);

      return {
        success: false,
        error,
        errorCode: 5,
      };
    }
  }

  /**
   * Exit/release access to a resource
   */
  async exitResource(resource: ResourceConfig): Promise<void> {
    const serverId = `${resource.serverHost}:${resource.serverPort}`;
    const server = this.servers.get(serverId);

    if (server) {
      clearServerCookie(server.publicKey);
    }

    const transport = this.transports.get(serverId);
    if (transport) {
      transport.disconnect();
      this.transports.delete(serverId);
    }

    this.log('debug', `Exited resource: ${resource.resourceId}`);
  }

  /**
   * Register an event handler
   */
  on(event: NHPAgentEvent, handler: EventHandler): void {
    if (!this.eventHandlers.has(event)) {
      this.eventHandlers.set(event, new Set());
    }
    this.eventHandlers.get(event)!.add(handler);
  }

  /**
   * Remove an event handler
   */
  off(event: NHPAgentEvent, handler: EventHandler): void {
    const handlers = this.eventHandlers.get(event);
    if (handlers) {
      handlers.delete(handler);
    }
  }

  private async sendAndWaitForResponse(
    transport: WebSocketTransport,
    packet: Uint8Array,
    serverPublicKey: string
  ): Promise<{ accessToken?: string; expiresAt?: number } | null> {
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        transport.off('message', messageHandler);
        resolve(null);
      }, 10000); // 10 second timeout

      const messageHandler = async (msg: unknown) => {
        clearTimeout(timeout);
        transport.off('message', messageHandler);

        try {
          if (!this.keyPair) {
            throw new Error('Agent not initialized');
          }

          const message = msg as { data: Uint8Array };
          const parsed = await parseNHPPacket(
            message.data,
            this.keyPair.privateKey,
            this.keyPair.publicKey,
            serverPublicKey
          );

          // Parse response message
          try {
            const responseData = JSON.parse(parsed.message);
            resolve({
              accessToken: responseData.accessToken,
              expiresAt: responseData.expiresAt,
            });
          } catch {
            resolve({});
          }
        } catch (err) {
          reject(err);
        }
      };

      transport.on('message', messageHandler);

      transport
        .connect()
        .then(() => {
          transport.send(packet);
        })
        .catch((err) => {
          clearTimeout(timeout);
          transport.off('message', messageHandler);
          reject(err);
        });
    });
  }

  private emit(event: NHPAgentEvent, data: unknown): void {
    const handlers = this.eventHandlers.get(event);
    if (handlers) {
      handlers.forEach((handler) => handler(data));
    }
  }

  private log(level: LogLevel, message: string): void {
    const levels: Record<LogLevel, number> = {
      silent: 0,
      error: 1,
      info: 2,
      debug: 3,
    };

    if (levels[level] <= levels[this.config.logLevel]) {
      const prefix = `[NHPAgent:${level.toUpperCase()}]`;
      switch (level) {
        case 'error':
          console.error(prefix, message);
          break;
        case 'info':
          console.info(prefix, message);
          break;
        case 'debug':
          console.debug(prefix, message);
          break;
      }
    }
  }
}
