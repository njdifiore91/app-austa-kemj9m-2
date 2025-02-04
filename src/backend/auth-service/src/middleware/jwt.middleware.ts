/**
 * @fileoverview HIPAA-compliant JWT middleware for authentication and authorization
 * Implements secure token validation with role-based access control and audit logging
 * @version 1.0.0
 */

import { Request, Response, NextFunction } from "express"
import { createLogger, format, transports } from "winston"
import { verifyToken, TokenPayload } from "../utils/token.utils"
import { AUTH_CONFIG } from "../config/auth.config"
import { ErrorCode } from "../../../shared/constants/error-codes"

// Custom error class for authentication errors
class AuthError extends Error {
  constructor(code: ErrorCode) {
    super(code)
    this.name = "AuthError"
  }
}

// Security audit logger configuration
const auditLogger = createLogger({
  level: "info",
  format: format.combine(format.timestamp(), format.json()),
  transports: [new transports.File({ filename: "security-audit.log" })],
})

// Constants
const BEARER_PREFIX = "Bearer "
const DEFAULT_OPTIONS: Required<JWTMiddlewareOptions> = {
  requireAuth: true,
  requiredRoles: [],
  requiredPermissions: [],
  validateDevice: true,
  enforceFingerprint: true,
  auditLevel: "STANDARD",
  sessionTimeout: AUTH_CONFIG.security.hipaa.inactivityTimeout,
}

// Enhanced request interface with security context
export interface AuthenticatedRequest extends Request {
  user?: TokenPayload
  deviceId?: string
  sessionContext?: {
    lastAccess: number
    activityCount: number
  }
  securityContext?: {
    ipAddress: string
    userAgent: string
    geoLocation?: string
  }
}

// Middleware configuration interface
export interface JWTMiddlewareOptions {
  requireAuth: boolean
  requiredRoles?: string[]
  requiredPermissions?: string[]
  validateDevice?: boolean
  enforceFingerprint?: boolean
  auditLevel?: "BASIC" | "STANDARD" | "DETAILED"
  sessionTimeout?: number
}

/**
 * Enhanced JWT middleware for secure token validation and RBAC
 * @param {JWTMiddlewareOptions} options - Configuration options
 * @returns {Function} Express middleware function
 */
export const jwtMiddleware = (options: Partial<JWTMiddlewareOptions> = {}) => {
  const config: Required<JWTMiddlewareOptions> = {
    ...DEFAULT_OPTIONS,
    ...options,
  }

  return async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
  ) => {
    try {
      // Extract authorization header
      const authHeader = req.headers.authorization
      if (!authHeader?.startsWith(BEARER_PREFIX)) {
        if (!config.requireAuth) return next()
        throw new AuthError(ErrorCode.UNAUTHORIZED)
      }

      // Extract and verify token
      const token = authHeader.substring(BEARER_PREFIX.length)
      const decoded = await verifyToken(token)

      // Validate session timeout
      if (
        decoded.lastAccess &&
        Date.now() - decoded.lastAccess > config.sessionTimeout * 1000
      ) {
        throw new AuthError(ErrorCode.SESSION_EXPIRED)
      }

      // Device validation if enabled
      if (config.validateDevice) {
        const deviceId = req.headers["x-device-id"]
        if (
          !deviceId ||
          typeof deviceId !== "string" ||
          deviceId !== decoded.deviceId
        ) {
          throw new AuthError(ErrorCode.UNAUTHORIZED)
        }
      }

      // Role-based access control
      if (config.requiredRoles.length && Array.isArray(decoded.roles)) {
        const hasRequiredRole = decoded.roles.some((role) =>
          config.requiredRoles.includes(role)
        )
        if (!hasRequiredRole) {
          throw new AuthError(ErrorCode.FORBIDDEN)
        }
      }

      // Permission-based access control
      if (
        config.requiredPermissions.length &&
        Array.isArray(decoded.permissions)
      ) {
        const hasRequiredPermissions = config.requiredPermissions.every(
          (permission) => decoded.permissions.includes(permission)
        )
        if (!hasRequiredPermissions) {
          throw new AuthError(ErrorCode.FORBIDDEN)
        }
      }

      // Enhance request with security context
      req.user = decoded
      req.deviceId = req.headers["x-device-id"]?.toString()
      req.sessionContext = {
        lastAccess: Date.now(),
        activityCount: (req.sessionContext?.activityCount || 0) + 1,
      }

      const userAgent = req.headers["user-agent"]?.toString() || "unknown"
      const geoLocation = req.headers["x-geo-location"]?.toString()

      req.securityContext = {
        ipAddress: req.ip || "unknown",
        userAgent,
        ...(geoLocation && { geoLocation }),
      }

      // Security audit logging
      auditLogger.info("JWT Authentication", {
        userId: decoded.userId,
        sessionId: decoded.sessionId,
        ipAddress: req.ip || "unknown",
        userAgent,
        path: req.path,
        method: req.method,
        timestamp: new Date().toISOString(),
      })

      next()
    } catch (error) {
      // Enhanced error handling with security context
      const userAgent = req.headers["user-agent"]?.toString() || "unknown"

      auditLogger.error("JWT Authentication Failed", {
        error: error instanceof Error ? error.message : "Unknown error",
        ipAddress: req.ip || "unknown",
        userAgent,
        path: req.path,
        method: req.method,
        timestamp: new Date().toISOString(),
      })

      // Map internal error codes to HTTP responses
      const errorResponse = {
        code:
          error instanceof AuthError
            ? error.message
            : ErrorCode.INTERNAL_SERVER_ERROR,
        message: "Authentication failed",
        timestamp: new Date().toISOString(),
      }

      if (error instanceof AuthError) {
        switch (error.message) {
          case ErrorCode.UNAUTHORIZED:
          case ErrorCode.TOKEN_EXPIRED:
            return res.status(401).json(errorResponse)
          case ErrorCode.FORBIDDEN:
            return res.status(403).json(errorResponse)
          default:
            return res.status(500).json(errorResponse)
        }
      }

      return res.status(500).json({
        code: ErrorCode.INTERNAL_SERVER_ERROR,
        message: "Internal server error",
        timestamp: new Date().toISOString(),
      })
    }
  }
}

export default jwtMiddleware
