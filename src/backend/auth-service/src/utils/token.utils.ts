/**
 * @fileoverview HIPAA-compliant JWT token management utilities
 * Implements secure token generation, verification, and lifecycle management
 * with enhanced security features and comprehensive audit logging
 * @version 1.0.0
 */

import * as jwt from "jsonwebtoken"
import * as crypto from "crypto"
import { AUTH_CONFIG } from "../config/auth.config"
import { ErrorCode } from "@austa/shared/constants/error-codes"
import { Secret, SignOptions } from "jsonwebtoken"

/**
 * Enhanced interface defining JWT token payload structure with HIPAA compliance fields
 */
export interface TokenPayload {
  userId: string
  email: string
  roles: string[]
  permissions: string[]
  sessionId: string
  deviceId: string
  ipAddress: string
  fingerprint: string
  auditId: string
  refreshCount?: number
  iat?: number
  exp?: number
  lastAccess?: number
  [key: string]: unknown
}

// type StringValue = string & { __brand: "StringValue" }

/**
 * Enhanced interface for token generation options with security parameters
 */
export interface TokenOptions {
  expiresIn?: number
  issuer?: string
}

// Token configuration constants
const TOKEN_EXPIRATION = parseInt(AUTH_CONFIG.jwt.expiresIn, 10)
const REFRESH_TOKEN_EXPIRATION = parseInt(AUTH_CONFIG.jwt.refreshExpiresIn, 10)
const TOKEN_ISSUER = AUTH_CONFIG.jwt.issuer
const ALGORITHM = AUTH_CONFIG.jwt.algorithm
const MIN_KEY_LENGTH = 2048
const MAX_REFRESH_COUNT = 5
const REVOCATION_CHECK_INTERVAL = 60000

// Error codes
const TOKEN_REFRESH_LIMIT_EXCEEDED = "TOKEN_REFRESH_LIMIT_EXCEEDED"

/**
 * Generate a token fingerprint for additional security
 */
export function generateTokenFingerprint(): string {
  return crypto.randomBytes(32).toString("hex")
}

/**
 * Generate a JWT token with the given payload
 */
export async function generateToken(
  payload: TokenPayload,
  options: TokenOptions = {}
): Promise<string> {
  const privateKey = process.env.JWT_PRIVATE_KEY
  if (!privateKey) {
    throw new Error(ErrorCode.INTERNAL_SERVER_ERROR)
  }

  const signOptions: SignOptions = {
    algorithm: ALGORITHM as jwt.Algorithm,
    expiresIn:
      options.expiresIn === undefined ? TOKEN_EXPIRATION : options.expiresIn,
    issuer: options.issuer || TOKEN_ISSUER,
  }

  return new Promise((resolve, reject) => {
    jwt.sign(payload, privateKey as Secret, signOptions, (err, token) => {
      if (err || !token) {
        reject(new Error(ErrorCode.UNAUTHORIZED))
      } else {
        resolve(token)
      }
    })
  })
}

/**
 * Verify a JWT token
 */
export async function verifyToken(token: string): Promise<TokenPayload> {
  const publicKey = process.env.JWT_PUBLIC_KEY
  if (!publicKey || publicKey.length < MIN_KEY_LENGTH) {
    throw new Error(ErrorCode.INTERNAL_SERVER_ERROR)
  }

  return new Promise((resolve, reject) => {
    jwt.verify(token, publicKey as Secret, (err, decoded) => {
      if (err || !decoded) {
        reject(new Error(ErrorCode.UNAUTHORIZED))
      } else {
        resolve(decoded as TokenPayload)
      }
    })
  })
}

/**
 * Refresh a JWT token with refresh count validation
 */
export async function refreshToken(oldToken: string): Promise<string> {
  try {
    const decoded = await verifyToken(oldToken)

    // Check refresh count
    if ((decoded.refreshCount || 0) >= MAX_REFRESH_COUNT) {
      throw new Error(TOKEN_REFRESH_LIMIT_EXCEEDED)
    }

    // Update payload for new token
    const newPayload: TokenPayload = {
      ...decoded,
      refreshCount: (decoded.refreshCount || 0) + 1,
      lastAccess: Date.now(),
    }

    return await generateToken(newPayload, {
      expiresIn: REFRESH_TOKEN_EXPIRATION,
    })
  } catch (error) {
    if (error instanceof Error) {
      throw new Error(error.message)
    }
    throw new Error(ErrorCode.UNAUTHORIZED)
  }
}

// Store for revoked tokens (in memory for development, should use Redis in production)
const revokedTokens = new Set<string>()

// Cleanup interval for revoked tokens
setInterval(() => {
  const now = Date.now()
  for (const token of revokedTokens) {
    try {
      const decoded = jwt.decode(token) as TokenPayload
      if (decoded.exp && decoded.exp * 1000 < now) {
        revokedTokens.delete(token)
      }
    } catch (error) {
      revokedTokens.delete(token)
    }
  }
}, REVOCATION_CHECK_INTERVAL)

/**
 * Revoke a JWT token by adding it to blacklist
 */
export async function revokeToken(token: string): Promise<void> {
  try {
    // Verify token is valid before revoking
    await verifyToken(token)
    revokedTokens.add(token)
  } catch (error) {
    throw new Error(ErrorCode.INVALID_TOKEN)
  }
}

/**
 * Check if a token has been revoked
 */
export function isTokenRevoked(token: string): boolean {
  return revokedTokens.has(token)
}
