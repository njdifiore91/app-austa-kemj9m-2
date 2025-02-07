/**
 * @fileoverview Enhanced security middleware for API Gateway implementing HIPAA and LGPD compliant measures
 * @version 1.0.0
 */

import { Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import hpp from 'hpp';
import cors from 'cors';
import { RateLimiterMemory } from 'rate-limiter-flexible';
import { ErrorCode } from '@shared/constants/error-codes';
import { HttpStatus } from '@shared/constants/http-status';
import { Logger } from '@shared/middleware/logger';
import { EncryptionService, EncryptedData } from '@shared/utils/encryption.utils';

// Constants for security configuration
const REQUIRED_TLS_VERSION = '1.3';
const NODE_ENV = process.env.NODE_ENV || 'development';

const SECURITY_HEADERS = {
  HSTS: 'strict-transport-security',
  CSP: 'content-security-policy',
  FRAME_OPTIONS: 'x-frame-options',
  XSS_PROTECTION: 'x-xss-protection',
  CONTENT_TYPE_OPTIONS: 'x-content-type-options',
  REFERRER_POLICY: 'referrer-policy',
  FEATURE_POLICY: 'feature-policy'
};

// Different rate limit configs for dev and prod
const RATE_LIMIT_CONFIG = {
  development: {
    points: 1000, // More lenient in development
    duration: 60,
    blockDuration: 0 // No blocking in development
  },
  production: {
    points: 100,
    duration: 60,
    blockDuration: 300
  }
};

// Initialize logger and rate limiter
const logger = new Logger();
const rateLimiter = new RateLimiterMemory(
  NODE_ENV === 'development' 
    ? RATE_LIMIT_CONFIG.development 
    : RATE_LIMIT_CONFIG.production
);

// Initialize middleware
const hppMiddleware = hpp();
// Remove CORS middleware from security middleware
// const corsMiddleware = cors({
//   origin: process.env.ALLOWED_ORIGINS?.split(',') || [],
//   methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
//   allowedHeaders: ['Content-Type', 'Authorization'],
//   exposedHeaders: ['X-Request-ID'],
//   credentials: true,
//   maxAge: 600
// });

/**
 * Enhanced security middleware implementing HIPAA and LGPD compliant security measures
 */
export default function securityMiddleware(): (req: Request, res: Response, next: NextFunction) => void {
  // Initialize helmet middleware with default configuration
  const helmetMiddleware = helmet();

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      // Apply middleware chain using composition
      const applyMiddleware = (middleware: (req: Request, res: Response, next: NextFunction) => void) => {
        return new Promise<void>((resolve, reject) => {
          middleware(req, res, (error: unknown) => {
            if (error) {
              reject(error);
            } else {
              resolve();
            }
          });
        });
      };

      try {
        // Apply middleware chain with default configurations
        await applyMiddleware(helmetMiddleware);
        await applyMiddleware(hppMiddleware);
        // Remove CORS middleware from chain
        // await applyMiddleware(corsMiddleware);
        await handleSecurityChecks(req, res, next);
      } catch (error) {
        logger.error('Middleware error', { error });
        res.status(HttpStatus.INTERNAL_SERVER_ERROR)
          .json({ error: ErrorCode.INTERNAL_SERVER_ERROR });
      }
    } catch (error) {
      logger.error('Security middleware error', { error });
      res.status(HttpStatus.INTERNAL_SERVER_ERROR)
        .json({ error: ErrorCode.INTERNAL_SERVER_ERROR });
    }
  };
}

/**
 * Handles security checks after basic middleware is applied
 */
function handleSecurityChecks(req: Request, res: Response, next: NextFunction): void {
  try {
    // Skip security checks for health endpoint and development mode OPTIONS requests
    if (req.path === '/health' || req.path === '/metrics' || 
        (NODE_ENV === 'development' && req.method === 'OPTIONS')) {
      return next();
    }

    // Rate limiting check with error handling
    try {
      rateLimiter.consume(req.ip || 'unknown')
        .then(() => {
          // Continue with other security checks
          handleOtherSecurityChecks(req, res, next);
        })
        .catch((rateLimitErr) => {
          if (NODE_ENV === 'development') {
            // In development, log and continue even if rate limit is exceeded
            logger.warn('Rate limit exceeded in development', {
              ip: req.ip,
              path: req.path,
              method: req.method
            });
            handleOtherSecurityChecks(req, res, next);
          } else {
            logger.warn('Rate limit exceeded', {
              ip: req.ip,
              path: req.path,
              method: req.method
            });
            res.status(HttpStatus.TOO_MANY_REQUESTS)
              .json({ error: ErrorCode.RATE_LIMIT_EXCEEDED });
          }
        });
    } catch (error) {
      // Handle rate limiter initialization errors
      logger.error('Rate limiter error', { error });
      if (NODE_ENV === 'development') {
        // In development, continue without rate limiting if there's an error
        handleOtherSecurityChecks(req, res, next);
      } else {
        res.status(HttpStatus.INTERNAL_SERVER_ERROR)
          .json({ error: 'Rate limiting service unavailable' });
      }
    }
  } catch (error) {
    logger.error('Security middleware error', { error });
    res.status(HttpStatus.INTERNAL_SERVER_ERROR)
      .json({ error: ErrorCode.INTERNAL_SERVER_ERROR });
  }
}

/**
 * Handles the remaining security checks after rate limiting
 */
function handleOtherSecurityChecks(req: Request, res: Response, next: NextFunction): void {
  try {
    // Validate TLS version
    if (!validateTLS(req)) {
      logger.error('Invalid TLS version', {
        version: req.protocol,
        required: REQUIRED_TLS_VERSION
      });
      res.status(HttpStatus.FORBIDDEN)
        .json({ error: ErrorCode.HIPAA_VIOLATION });
      return;
    }

    // Validate security headers
    if (!validateSecurityHeaders(req)) {
      logger.error('Security headers validation failed', {
        headers: req.headers
      });
      res.status(HttpStatus.FORBIDDEN)
        .json({ error: ErrorCode.HIPAA_VIOLATION });
      return;
    }

    // Only validate encryption for sensitive routes in production
    if (!NODE_ENV.startsWith('dev') && 
        (req.path.includes('/api/health') || req.path.includes('/api/claims'))) {
      validateEncryption(req, res, next);
      return;
    }

    next();
  } catch (error) {
    logger.error('Security checks error', { error });
    res.status(HttpStatus.INTERNAL_SERVER_ERROR)
      .json({ error: ErrorCode.INTERNAL_SERVER_ERROR });
  }
}

/**
 * Validates encryption for sensitive routes
 */
function validateEncryption(req: Request, res: Response, next: NextFunction): void {
  const encryptionService = new EncryptionService({
    keyId: process.env.KMS_KEY_ID || '',
    region: process.env.AWS_REGION || '',
    algorithm: 'aes-256-gcm'
  });
  
  try {
    // Check if the request body is encrypted by attempting to decrypt it
    if (!(req.body as EncryptedData).ciphertext) {
      logger.error('Encryption validation failed - missing ciphertext', {
        path: req.path,
        method: req.method
      });
      res.status(HttpStatus.FORBIDDEN)
        .json({ error: ErrorCode.HIPAA_VIOLATION });
      return;
    }
    
    // Attempt to decrypt - will throw if not properly encrypted
    encryptionService.decrypt(req.body as EncryptedData);
    next();
  } catch (error) {
    logger.error('Encryption validation failed', {
      path: req.path,
      method: req.method,
      error
    });
    res.status(HttpStatus.FORBIDDEN)
      .json({ error: ErrorCode.HIPAA_VIOLATION });
  }
}

/**
 * Validates TLS version and certificate
 */
function validateTLS(req: Request): boolean {
  // Skip TLS validation in development mode
  if (NODE_ENV === 'development') {
    return true;
  }

  const tlsSocket = req.socket as any;
  if (!tlsSocket?.encrypted || !tlsSocket?.getCipher) {
    return false;
  }

  const cipher = tlsSocket.getCipher();
  return cipher?.version === REQUIRED_TLS_VERSION;
}

/**
 * Validates required security headers
 */
function validateSecurityHeaders(req: Request): boolean {
  // Skip security headers validation in development mode
  if (NODE_ENV === 'development') {
    return true;
  }

  const requiredHeaders = [
    SECURITY_HEADERS.HSTS,
    SECURITY_HEADERS.CSP,
    SECURITY_HEADERS.FRAME_OPTIONS,
    SECURITY_HEADERS.XSS_PROTECTION,
    SECURITY_HEADERS.CONTENT_TYPE_OPTIONS,
    SECURITY_HEADERS.REFERRER_POLICY
  ];

  return requiredHeaders.every(header => req.headers[header]);
}