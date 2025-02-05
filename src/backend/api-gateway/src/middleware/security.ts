/**
 * @fileoverview Enhanced security middleware for API Gateway implementing HIPAA and LGPD compliant measures
 * @version 1.0.0
 */

import { Request, Response, NextFunction } from "express"
import { Socket } from "net"
import helmet from "helmet"
import hpp from "hpp"
import cors from "cors"
import { RateLimiterMemory } from "rate-limiter-flexible"
import { EncryptionService } from "@austa/shared/utils/encryption.utils"
import { HttpStatus } from "@austa/shared/constants/http-status"
import { ErrorCode } from "@austa/shared/constants/error-codes"
import winston from "winston"

// Constants for security configuration
const REQUIRED_TLS_VERSION = "1.3"

const SECURITY_HEADERS = {
  HSTS: "strict-transport-security",
  CSP: "content-security-policy",
  FRAME_OPTIONS: "x-frame-options",
  XSS_PROTECTION: "x-xss-protection",
  CONTENT_TYPE_OPTIONS: "x-content-type-options",
  REFERRER_POLICY: "referrer-policy",
  FEATURE_POLICY: "feature-policy",
} as const

const RATE_LIMIT_CONFIG = {
  points: 100,
  duration: 60,
  blockDuration: 300,
}

// Initialize logger and rate limiter
const logger = winston.createLogger({
  level: "info",
  format: winston.format.json(),
  defaultMeta: { service: "security-middleware" },
  transports: [new winston.transports.File({ filename: "security-audit.log" })],
})

const rateLimiter = new RateLimiterMemory(RATE_LIMIT_CONFIG)

interface TLSSocket extends Socket {
  encrypted?: boolean
  getCipher?: () => {
    version: string
  } | null
}

interface SecureRequest extends Omit<Request, 'socket'> {
  socket: TLSSocket
}

/**
 * Enhanced security middleware implementing HIPAA and LGPD compliant security measures
 */
export default async function securityMiddleware(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    // Apply Helmet with strict CSP and security headers
    await new Promise<void>((resolve) => {
      helmet({
        contentSecurityPolicy: {
          directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"],
            fontSrc: ["'self'"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"],
            upgradeInsecureRequests: [],
          },
        },
        hsts: {
          maxAge: 31536000,
          includeSubDomains: true,
          preload: true,
        },
        frameguard: {
          action: "deny",
        },
        xssFilter: true,
        noSniff: true,
        referrerPolicy: { policy: "strict-origin-when-cross-origin" },
      })(req as Request, res, () => resolve())
    })

    // Apply HTTP Parameter Pollution protection
    await new Promise<void>((resolve) => {
      hpp()(req as Request, res, () => resolve())
    })

    // Configure strict CORS
    await new Promise<void>((resolve) => {
      cors({
        origin: process.env.ALLOWED_ORIGINS?.split(",") || [],
        methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allowedHeaders: ["Content-Type", "Authorization"],
        exposedHeaders: ["X-Request-ID"],
        credentials: true,
        maxAge: 600,
      })(req as Request, res, () => resolve())
    })

    // Rate limiting check
    try {
      await rateLimiter.consume(req.ip || "unknown")
    } catch (error) {
      logger.warn("Rate limit exceeded", {
        ip: req.ip,
        path: req.path,
        method: req.method,
      })
      res.status(429).json({ error: ErrorCode.RATE_LIMIT_EXCEEDED })
      return
    }

    // Validate TLS version
    if (!validateTLS(req as SecureRequest)) {
      logger.error("Invalid TLS version", {
        version: req.protocol,
        required: REQUIRED_TLS_VERSION,
      })
      res
        .status(HttpStatus.FORBIDDEN)
        .json({ error: ErrorCode.HIPAA_VIOLATION })
      return
    }

    // Validate security headers
    if (!validateSecurityHeaders(req)) {
      logger.error("Security headers validation failed", {
        headers: req.headers,
      })
      res
        .status(HttpStatus.FORBIDDEN)
        .json({ error: ErrorCode.HIPAA_VIOLATION })
      return
    }

    // Validate request encryption for sensitive routes
    if (req.path.includes("/api/health") || req.path.includes("/api/claims")) {
      const encryptionService = new EncryptionService(
        {
          region: process.env.AWS_REGION || "us-east-1",
          endpoint: process.env.AWS_KMS_ENDPOINT || "",
          keyId: process.env.AWS_KMS_KEY_ID || "",
          cacheTimeout: 3600,
          keyRotationInterval: 30 * 24 * 60 * 60 * 1000, // 30 days
        },
        logger
      )

      try {
        const encryptedBody = await encryptionService.encryptField(
          JSON.stringify(req.body),
          "sensitive_data",
          { isPhiPii: true }
        )
        if (!encryptedBody) {
          throw new Error("Encryption failed")
        }
      } catch (error) {
        logger.error("Encryption validation failed", {
          path: req.path,
          method: req.method,
          error,
        })
        res
          .status(HttpStatus.FORBIDDEN)
          .json({ error: ErrorCode.HIPAA_VIOLATION })
        return
      }
    }

    next()
  } catch (error) {
    logger.error("Security middleware error", { error })
    res
      .status(HttpStatus.INTERNAL_SERVER_ERROR)
      .json({ error: ErrorCode.INTERNAL_SERVER_ERROR })
  }
}

/**
 * Validates TLS version and certificate
 */
function validateTLS(req: SecureRequest): boolean {
  const tlsSocket = req.socket
  if (!tlsSocket?.encrypted || !tlsSocket?.getCipher) {
    return false
  }

  const cipher = tlsSocket.getCipher()
  return cipher?.version === REQUIRED_TLS_VERSION
}

/**
 * Validates required security headers
 */
function validateSecurityHeaders(req: Request): boolean {
  const requiredHeaders = [
    SECURITY_HEADERS.HSTS,
    SECURITY_HEADERS.CSP,
    SECURITY_HEADERS.FRAME_OPTIONS,
    SECURITY_HEADERS.XSS_PROTECTION,
    SECURITY_HEADERS.CONTENT_TYPE_OPTIONS,
    SECURITY_HEADERS.REFERRER_POLICY,
  ]

  return requiredHeaders.every((header) => req.headers[header])
}
