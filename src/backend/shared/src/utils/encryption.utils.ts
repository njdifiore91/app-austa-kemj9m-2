/**
 * @fileoverview Enhanced encryption utilities for AUSTA SuperApp
 * Implements HIPAA and LGPD compliant encryption standards with comprehensive security features
 * @version 1.0.0
 */

import { ErrorCode } from '../constants/error-codes';
import * as crypto from 'crypto';
import { KMS } from 'aws-sdk';
import NodeCache from 'node-cache';
import * as winston from 'winston';

/**
 * Interface for encrypted data
 */
export interface EncryptedData {
  ciphertext: Buffer;
  iv: Buffer;
  authTag: Buffer;
}

/**
 * Interface for key rotation result
 */
export interface KeyRotationResult {
  oldKeyId: string;
  newKeyId: string;
  rotationTimestamp: Date;
}

/**
 * Interface for encryption service configuration
 */
export interface EncryptionConfig {
  algorithm: string;
  keyId: string;
  region: string;
  cacheExpiry: number;
}

/**
 * Default encryption configuration
 */
const DEFAULT_CONFIG: EncryptionConfig = {
  algorithm: 'aes-256-gcm',
  keyId: process.env.KMS_KEY_ID || '',
  region: process.env.AWS_REGION || 'us-east-1',
  cacheExpiry: 3600 // 1 hour
};

/**
 * Error handling decorator factory
 */
function handleEncryptionError() {
  return function (target: any, propertyKey: string, descriptor: PropertyDescriptor): PropertyDescriptor {
    const originalMethod = descriptor.value;

    descriptor.value = async function (...args: any[]) {
      try {
        return await originalMethod.apply(this, args);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        throw new Error(`Encryption operation failed: ${errorMessage}`);
      }
    };

    return descriptor;
  };
}

/**
 * HIPAA-compliant encryption service
 */
export class EncryptionService {
  private readonly config: EncryptionConfig;
  private readonly kms: KMS;
  private readonly keyCache: NodeCache;
  protected readonly logger: winston.Logger;

  constructor(config: Partial<EncryptionConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.kms = new KMS({ region: this.config.region });
    this.keyCache = new NodeCache({ stdTTL: this.config.cacheExpiry });
    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      ),
      defaultMeta: {
        service: 'encryption-service'
      },
      transports: [
        new winston.transports.Console({
          format: winston.format.combine(
            winston.format.colorize(),
            winston.format.simple()
          )
        })
      ]
    });
  }

  /**
   * Encrypts sensitive data
   */
  @handleEncryptionError()
  public async encrypt(data: Buffer | string): Promise<EncryptedData> {
    const key = await this.getEncryptionKey(this.config.keyId);
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv(this.config.algorithm, key, iv) as crypto.CipherGCM;

    const ciphertext = Buffer.concat([
      cipher.update(Buffer.isBuffer(data) ? data : Buffer.from(data)),
      cipher.final()
    ]);

    const authTag = cipher.getAuthTag();

    this.logger.info('Data encrypted successfully', {
      keyId: this.config.keyId,
      algorithm: this.config.algorithm
    });

    return { ciphertext, iv, authTag };
  }

  /**
   * Decrypts encrypted data
   */
  @handleEncryptionError()
  public async decrypt(encryptedData: EncryptedData): Promise<Buffer> {
    const key = await this.getEncryptionKey(this.config.keyId);
    const decipher = crypto.createDecipheriv(this.config.algorithm, key, encryptedData.iv) as crypto.DecipherGCM;

    decipher.setAuthTag(encryptedData.authTag);

    const decrypted = Buffer.concat([
      decipher.update(encryptedData.ciphertext),
      decipher.final()
    ]);

    this.logger.info('Data decrypted successfully', {
      keyId: this.config.keyId,
      algorithm: this.config.algorithm
    });

    return decrypted;
  }

  /**
   * Rotates encryption keys
   */
  @handleEncryptionError()
  public async rotateKey(): Promise<KeyRotationResult> {
    const oldKeyId = this.config.keyId;

    // Create new key
    const newKey = await this.kms.createKey({
      Description: 'HIPAA-compliant encryption key',
      KeyUsage: 'ENCRYPT_DECRYPT',
      Origin: 'AWS_KMS',
      Tags: [
        {
          TagKey: 'Purpose',
          TagValue: 'HIPAA-Compliance'
        },
        {
          TagKey: 'Application',
          TagValue: 'AUSTA-SuperApp'
        }
      ]
    }).promise();

    if (!newKey.KeyMetadata?.KeyId) {
      throw new Error('Failed to create new encryption key');
    }

    // Update key references
    await this.updateKeyReferences(oldKeyId, newKey.KeyMetadata.KeyId);

    const result: KeyRotationResult = {
      oldKeyId,
      newKeyId: newKey.KeyMetadata.KeyId,
      rotationTimestamp: new Date()
    };

    this.logger.info('Key rotation completed', result);

    return result;
  }

  /**
   * Gets encryption key from KMS or cache
   */
  private async getEncryptionKey(keyId: string): Promise<Buffer> {
    const cachedKey = this.keyCache.get<Buffer>(keyId);
    if (cachedKey) {
      this.logger.debug('Using cached encryption key', { keyId });
      return cachedKey;
    }

    const { Plaintext } = await this.kms.generateDataKey({
      KeyId: keyId,
      KeySpec: 'AES_256'
    }).promise();

    if (!Plaintext) {
      throw new Error('Failed to generate data key');
    }

    // Handle AWS.KMS.generateDataKey response type
    const key = Buffer.from(Plaintext as Uint8Array);
    this.keyCache.set(keyId, key);

    this.logger.debug('Generated new encryption key', { keyId });
    return key;
  }

  /**
   * Updates key references after rotation
   */
  private async updateKeyReferences(oldKeyId: string, newKeyId: string): Promise<void> {
    // Schedule old key for deletion after a grace period
    const gracePeriodDays = 30;
    await this.kms.scheduleKeyDeletion({
      KeyId: oldKeyId,
      PendingWindowInDays: gracePeriodDays
    }).promise();

    this.logger.info('Key references updated', {
      oldKeyId,
      newKeyId,
      gracePeriodDays
    });
  }
}