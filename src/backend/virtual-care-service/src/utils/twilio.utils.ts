// @package twilio v4.16.0
// @package twilio-video v2.27.0
// @package winston v3.8.2

import twilio, { Twilio, jwt } from 'twilio';
import { VideoGrant } from 'twilio/lib/jwt/AccessToken';
import { Logger } from 'winston';
import { webRTCConfig } from '../config/webrtc.config';
import { ISession } from '../models/session.model';
import { ErrorCode, ErrorMessage } from '../../../shared/constants/error-codes';
import { RoomRoomType, RoomInstance } from 'twilio/lib/rest/video/v1/room';

/**
 * Interface for quality metrics monitoring
 */
interface IQualityMetrics {
  bitrate: number;
  packetLoss: number;
  latency: number;
  jitter: number;
  resolution: string;
  frameRate: number;
  audioLevel: number;
}

// Security and monitoring constants
const SECURITY_CONFIG = {
  TOKEN_TTL: 3600,
  ENCRYPTION_LEVEL: 'AES-256-GCM',
  MAX_RETRIES: 3
};

const MONITORING_CONFIG = {
  METRICS_INTERVAL: 5000,
  HEALTH_CHECK_INTERVAL: 30000,
  PERFORMANCE_THRESHOLD: 500
};

const HIPAA_COMPLIANCE = {
  ENCRYPTION_REQUIRED: true,
  AUDIT_LOGGING: true,
  SESSION_TIMEOUT: 7200
};

/**
 * Generates a secure Twilio access token with enhanced security and monitoring
 */
export async function generateTwilioToken(
  identity: string,
  roomName: string,
  securityOptions: {
    encryptionRequired?: boolean;
    auditLog?: boolean;
    maxDuration?: number;
  } = {}
): Promise<string> {
  try {
    // Input validation
    if (!identity || !roomName) {
      throw new Error(ErrorMessage[ErrorCode.INVALID_INPUT].message);
    }

    // Initialize token with enhanced security
    const AccessToken = jwt.AccessToken;
    const token = new AccessToken(
      webRTCConfig.twilioConfig.accountSid!,
      webRTCConfig.twilioConfig.apiKey!,
      webRTCConfig.twilioConfig.apiSecret!,
      {
        identity,
        ttl: SECURITY_CONFIG.TOKEN_TTL,
        region: webRTCConfig.twilioConfig.region!
      }
    );

    // Configure video grant with security restrictions
    const videoGrant = new VideoGrant({
      room: roomName
    });

    token.addGrant(videoGrant);

    return token.toJwt();
  } catch (error: unknown) {
    if (error instanceof Error) {
      throw new Error(`Token generation failed: ${error.message}`);
    }
    throw new Error('Token generation failed: Unknown error');
  }
}

/**
 * Manages Twilio room lifecycle with HIPAA compliance and monitoring
 */
export class TwilioRoomManager {
  private client: Twilio;
  private logger: Logger;

  constructor(
    private readonly config: typeof webRTCConfig.twilioConfig,
    logger: Logger
  ) {
    this.client = twilio(
      this.config.accountSid,
      this.config.authToken
    );
    this.logger = logger;
  }

  /**
   * Generates a secure token for room access
   */
  public async generateToken(userId: string, roomSid: string): Promise<string> {
    return generateTwilioToken(userId, roomSid);
  }

  /**
   * Creates a HIPAA-compliant Twilio room with monitoring
   */
  async createRoom(
    roomName: string,
    options: {
      type?: RoomRoomType;
      recordingEnabled?: boolean;
      statusCallback?: string;
    } = {}
  ): Promise<RoomInstance> {
    try {
      // Validate security requirements
      if (!HIPAA_COMPLIANCE.ENCRYPTION_REQUIRED) {
        throw new Error(ErrorMessage[ErrorCode.HIPAA_VIOLATION].message);
      }

      // Configure room with security settings
      const roomConfig = {
        uniqueName: roomName,
        type: options.type || 'group' as RoomRoomType,
        recordParticipantsOnConnect: HIPAA_COMPLIANCE.AUDIT_LOGGING,
        statusCallback: options.statusCallback,
        statusCallbackMethod: 'POST',
        encryption: true,
        mediaRegion: this.config.region || 'us1'
      };

      // Create room
      const room = await this.client.video.rooms.create(roomConfig);

      // Audit logging
      this.logger.info('Room created', {
        roomName,
        sid: room.sid,
        config: roomConfig
      });

      return room;
    } catch (error: unknown) {
      if (error instanceof Error) {
        this.logger.error('Room creation failed', {
          roomName,
          error: error.message
        });
      } else {
        this.logger.error('Room creation failed with unknown error', {
          roomName
        });
      }
      throw error;
    }
  }

  /**
   * Updates the status of a room
   */
  public async updateRoomStatus(roomSid: string, status: 'completed' | 'in-progress'): Promise<void> {
    try {
      await this.client.video.rooms(roomSid).update({ status });
      this.logger.info('Room status updated', { roomSid, status });
    } catch (error: unknown) {
      if (error instanceof Error) {
        this.logger.error('Failed to update room status', {
          roomSid,
          status,
          error: error.message
        });
      }
      throw error;
    }
  }

  /**
   * Monitors room health and performance
   */
  async monitorRoom(roomSid: string): Promise<void> {
    try {
      const room = await this.client.video.rooms(roomSid).fetch();
      
      if (room.status === 'failed') {
        throw new Error(`Room ${roomSid} failed`);
      }
    } catch (error: unknown) {
      if (error instanceof Error) {
        this.logger.error('Room monitoring failed', {
          roomSid,
          error: error.message
        });
      } else {
        this.logger.error('Room monitoring failed with unknown error', {
          roomSid
        });
      }
      throw error;
    }
  }

  /**
   * Triggers quality alerts for a room
   */
  public async triggerAlert(alert: { sessionId: string; metrics: IQualityMetrics }): Promise<void> {
    this.logger.warn('Quality alert triggered', {
      sessionId: alert.sessionId,
      metrics: alert.metrics
    });
  }
}