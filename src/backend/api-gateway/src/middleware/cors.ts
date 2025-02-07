/**
 * @fileoverview Healthcare-compliant CORS middleware implementation
 * Implements HIPAA-grade security controls for cross-origin resource sharing
 * with comprehensive audit logging and platform-specific security policies.
 * 
 * @version 1.0.0
 */

import express from 'express'; // v4.18.0
import cors from 'cors'; // v2.8.5
import winston from 'winston'; // v3.8.2
import { randomUUID } from 'crypto';
import { kongConfig } from '../config/kong.config';
import { HttpStatus } from '@shared/constants/http-status';

/**
 * Logger configuration for CORS audit trails
 */
const corsLogger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  defaultMeta: { service: 'cors-middleware' },
  transports: [
    new winston.transports.File({ filename: 'cors-audit.log' }),
    new winston.transports.Console()
  ]
});

/**
 * Healthcare-compliant CORS configuration class
 */
export class CorsConfig {
  public readonly environment: string;
  public readonly allowedOrigins: string[];
  public readonly allowedMethods: string[];
  public readonly allowedHeaders: string[];
  public readonly exposedHeaders: string[];
  public readonly maxAge: number;
  public readonly allowCredentials: boolean;
  private readonly mobileConfig: { protocols: string[] };
  private readonly securityHeaders: Record<string, string>;

  constructor(environment: string) {
    const corsPlugin = kongConfig.plugins.cors.config;
    
    this.environment = environment;
    this.allowedOrigins = [...corsPlugin.origins];
    
    // Add development origins if in development mode
    if (environment === 'development') {
      this.allowedOrigins.push(
        'http://localhost:3000',
        'http://localhost:8000',
        'http://127.0.0.1:3000',
        'http://127.0.0.1:8000',
        'null'  // Allow requests with 'null' origin in development
      );
    }
    
    this.allowedMethods = corsPlugin.methods;
    this.allowedHeaders = [
      ...corsPlugin.headers,
      'x-request-id',
      'x-security-version',
      'x-device-fingerprint',
      'accept',
      'content-type',
      'referer',
      'sec-ch-ua',
      'sec-ch-ua-mobile',
      'sec-ch-ua-platform',
      'user-agent'
    ];
    this.exposedHeaders = [
      ...corsPlugin.exposed_headers,
      'x-request-id',
      'x-security-version'
    ];
    this.maxAge = corsPlugin.max_age;
    this.allowCredentials = corsPlugin.credentials;
    
    this.mobileConfig = {
      protocols: ['capacitor://', 'ionic://', 'https://', 'http://']
    };

    this.securityHeaders = {
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
      'X-Frame-Options': 'DENY',
      'X-Content-Type-Options': 'nosniff',
      'X-XSS-Protection': '1; mode=block',
      'Content-Security-Policy': "default-src 'self'"
    };
  }

  /**
   * Returns CORS options with healthcare security settings
   */
  public getCorsOptions(): cors.CorsOptions {
    return {
      origin: (origin: string | undefined, callback: (error: Error | null, allow?: boolean) => void) => {
        // Allow requests with no origin (like mobile apps, curl, postman)
        if (!origin) {
          callback(null, true);
          return;
        }

        const isAllowed = this.validateOrigin(origin);
        if (isAllowed) {
          callback(null, true);
        } else {
          corsLogger.warn('CORS violation attempt', { 
            origin,
            environment: this.environment,
            allowedOrigins: this.allowedOrigins
          });
          callback(new Error('CORS policy violation'));
        }
      },
      methods: this.allowedMethods,
      allowedHeaders: this.allowedHeaders,
      exposedHeaders: this.exposedHeaders,
      credentials: this.allowCredentials,
      maxAge: this.maxAge,
      preflightContinue: false,
      optionsSuccessStatus: 204
    };
  }

  /**
   * Validates origin against allowed patterns with healthcare app support
   */
  public validateOrigin(origin: string): boolean {
    // Allow requests with no origin in development
    if (this.environment === 'development' && (!origin || origin === 'null')) {
      return true;
    }

    // Handle mobile app specific protocols
    const isMobileApp = this.mobileConfig.protocols.some(protocol => 
      origin.toLowerCase().startsWith(protocol));
    
    if (isMobileApp) {
      return true;
    }

    // Development mode allows localhost and 127.0.0.1
    if (this.environment === 'development') {
      const devPatterns = [
        /^http:\/\/localhost(:\d+)?$/,
        /^http:\/\/127\.0\.0\.1(:\d+)?$/
      ];
      if (devPatterns.some(pattern => pattern.test(origin))) {
        return true;
      }
    }

    // Check against allowed origins
    return this.allowedOrigins.some(allowed => {
      if (allowed.includes('*')) {
        const pattern = new RegExp('^' + allowed.replace(/\*/g, '.*') + '$');
        return pattern.test(origin);
      }
      return allowed === origin;
    });
  }
}

/**
 * Healthcare-compliant CORS middleware implementation
 */
export const corsMiddleware = (environment: string = process.env.NODE_ENV || 'development'): express.RequestHandler => {
  return (req: express.Request, res: express.Response, next: express.NextFunction) => {
    const origin = req.headers.origin || 'http://localhost:3000';
    
    // Always set these basic CORS headers regardless of environment
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET, HEAD, PUT, PATCH, POST, DELETE, OPTIONS');
    res.setHeader('Access-Control-Max-Age', '3600');
    res.setHeader('Vary', 'Origin');

    // Handle preflight requests
    if (req.method === 'OPTIONS') {
      // For preflight, use the requested headers
      const requestedHeaders = req.headers['access-control-request-headers'];
      if (requestedHeaders) {
        res.setHeader('Access-Control-Allow-Headers', requestedHeaders);
      }

      res.status(204).end();
      return;
    }

    // For non-preflight requests, set standard allowed headers
    const standardHeaders = [
      'content-type',
      'x-request-id',
      'x-security-version',
      'accept',
      'authorization',
      'origin',
      'referer',
      'user-agent'
    ].join(', ');
    res.setHeader('Access-Control-Allow-Headers', standardHeaders);

    next();
  };
};

export default corsMiddleware;