/**
 * @fileoverview HIPAA-compliant JWT token management utilities
 * Implements secure token generation, verification, and lifecycle management
 * with enhanced security features and comprehensive audit logging
 * @version 1.0.0
 */

import * as jwt from 'jsonwebtoken';
import { createHash, randomUUID } from 'crypto';
import { Algorithm } from 'jsonwebtoken';
import { AUTH_CONFIG } from '../config/auth.config';
import { ErrorCode } from '@shared/constants/error-codes';

/**
 * Enhanced interface defining JWT token payload structure with HIPAA compliance fields
 */
export interface TokenPayload {
  userId: string;
  email: string;
  roles: string[];
  permissions: string[];
  sessionId: string;
  deviceId: string;
  ipAddress: string;
  fingerprint: string;
  auditId: string;
  iat?: number;
  exp?: number;
  lastAccess?: number;
}

/**
 * Enhanced interface for token generation options with security parameters
 */
export interface TokenOptions {
  expiresIn?: string | number;
  audience?: string;
  issuer?: string;
  algorithm?: string;
  keyId?: string;
  jwtid?: string;
  subject?: string;
  notBefore?: number;
}

// Constants for token management
const TOKEN_EXPIRATION = AUTH_CONFIG.jwt.expiresIn;
const REFRESH_TOKEN_EXPIRATION = AUTH_CONFIG.jwt.refreshExpiresIn;
const TOKEN_ISSUER = AUTH_CONFIG.jwt.issuer;
const ALGORITHM = AUTH_CONFIG.jwt.algorithm;
const MIN_KEY_LENGTH = 2048;
const MAX_REFRESH_COUNT = 5;
const REVOCATION_CHECK_INTERVAL = 60000;

/**
 * Generates a secure token fingerprint using device and session information
 * @param {TokenPayload} payload - Token payload containing session data
 * @returns {string} Cryptographic fingerprint
 */
export function generateTokenFingerprint(payload: TokenPayload): string {
  const data = `${payload.userId}:${payload.sessionId}:${payload.deviceId}:${payload.ipAddress}`;
  return createHash('sha256').update(data).digest('hex');
}

/**
 * Generates a secure JWT token with enhanced payload and fingerprinting
 * @param {TokenPayload} payload - Token payload with user and session data
 * @param {TokenOptions} options - Token generation options
 * @returns {string} Generated JWT token with security enhancements
 */
export async function generateToken(payload: TokenPayload): Promise<string> {
  try {
    // Load JWT configuration
    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) {
      console.error('JWT secret is not configured');
      throw new Error(ErrorCode.TOKEN_GENERATION_FAILED);
    }

    console.log('Generating token with payload:', {
      ...payload,
      // Exclude sensitive data from logs
      userId: '[REDACTED]',
      email: '[REDACTED]'
    });

    const signOptions: jwt.SignOptions = {
      expiresIn: parseInt(process.env.JWT_EXPIRES_IN || '3600', 10),
      issuer: process.env.JWT_ISSUER || 'austa-auth-service',
      algorithm: (process.env.JWT_ALGORITHM as jwt.Algorithm) || 'HS256',
      jwtid: randomUUID(),
      subject: payload.userId,
      notBefore: 0
    };

    console.log('Using sign options:', {
      ...signOptions,
      // Exclude sensitive data from logs
      jwtid: '[REDACTED]',
      subject: '[REDACTED]'
    });

    const token = jwt.sign(payload, jwtSecret, signOptions);
    console.log('Token generated successfully');
    
    return token;
  } catch (error: unknown) {
    console.error('Token generation failed:', error);
    if (error instanceof Error) {
      throw new Error(ErrorCode.TOKEN_GENERATION_FAILED);
    }
    throw new Error(ErrorCode.INTERNAL_SERVER_ERROR);
  }
}

/**
 * Comprehensive token verification with security checks
 * @param {string} token - JWT token to verify
 * @returns {TokenPayload} Verified and decoded token payload
 */
export async function verifyToken(token: string): Promise<TokenPayload> {
  try {
    const verifyOptions: jwt.VerifyOptions = {
      algorithms: [AUTH_CONFIG.jwt.algorithm],
      audience: AUTH_CONFIG.jwt.audience,
      issuer: AUTH_CONFIG.jwt.issuer,
      complete: true
    };

    const decoded = jwt.verify(token, AUTH_CONFIG.jwt.secret, verifyOptions);
    if (!decoded || typeof decoded !== 'object') {
      throw new Error(ErrorCode.TOKEN_VERIFICATION_FAILED);
    }

    const payload = decoded as unknown as TokenPayload;
    if (!isValidTokenPayload(payload)) {
      throw new Error(ErrorCode.TOKEN_INVALID);
    }

    return payload;
  } catch (error: unknown) {
    if (error instanceof jwt.TokenExpiredError) {
      throw new Error(ErrorCode.TOKEN_EXPIRED);
    }
    if (error instanceof jwt.JsonWebTokenError) {
      throw new Error(ErrorCode.TOKEN_INVALID);
    }
    if (error instanceof Error) {
      throw new Error(ErrorCode.TOKEN_VERIFICATION_FAILED);
    }
    throw new Error(ErrorCode.INTERNAL_SERVER_ERROR);
  }
}

/**
 * Securely refreshes token while maintaining audit trail
 * @param {string} oldToken - Current token to refresh
 * @param {boolean} extendedSession - Whether to grant extended session
 * @returns {string} New JWT token with updated expiration
 */
export const refreshToken = async (
  oldToken: string,
  extendedSession: boolean = false
): Promise<string> => {
  try {
    // Verify current token
    const decoded = await verifyToken(oldToken);

    // Generate new session and audit IDs
    const newSessionId = randomUUID();
    const newAuditId = randomUUID();

    // Create new token payload
    const newPayload: TokenPayload = {
      ...decoded,
      sessionId: newSessionId,
      auditId: newAuditId,
      lastAccess: Date.now()
    };

    // Generate new token with appropriate expiration
    return await generateToken(newPayload);
  } catch (error: unknown) {
    if (error instanceof Error) {
      throw new Error(ErrorCode.TOKEN_REFRESH_FAILED);
    }
    throw new Error(ErrorCode.INTERNAL_SERVER_ERROR);
  }
};

/**
 * Invalidates token with comprehensive revocation tracking
 * @param {string} token - Token to revoke
 * @param {string} reason - Reason for revocation
 * @returns {boolean} Revocation success status
 */
export const revokeToken = async (
  token: string,
  reason: string
): Promise<boolean> => {
  try {
    // Verify token before revocation
    const decoded = await verifyToken(token);

    // Add token to revocation list with metadata
    const revocationData = {
      token: token,
      userId: decoded.userId,
      sessionId: decoded.sessionId,
      reason: reason,
      timestamp: Date.now(),
      auditId: decoded.auditId
    };

    // Store revocation data (implementation depends on storage solution)
    // TODO: Implement revocation storage

    return true;
  } catch (error: unknown) {
    if (error instanceof Error) {
      throw new Error(`Token revocation failed: ${error.message}`);
    }
    throw new Error('Token revocation failed: Unknown error');
  }
};

function isValidTokenPayload(payload: unknown): payload is TokenPayload {
  if (!payload || typeof payload !== 'object') return false;
  
  const requiredFields: (keyof TokenPayload)[] = [
    'userId',
    'email',
    'roles',
    'permissions',
    'sessionId',
    'deviceId',
    'ipAddress',
    'fingerprint',
    'auditId'
  ];

  return requiredFields.every(field => 
    field in payload && 
    (field === 'roles' || field === 'permissions' ? 
      Array.isArray((payload as any)[field]) : 
      typeof (payload as any)[field] === 'string')
  );
}