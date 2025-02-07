/**
 * @fileoverview Main entry point for AUSTA SuperApp API Gateway
 * Implements enterprise-grade API Gateway with HIPAA compliance, enhanced security,
 * comprehensive monitoring, and intelligent routing for microservices.
 * 
 * @version 1.0.0
 */

import express from 'express';
import morgan from 'morgan';
import dotenv from 'dotenv';
import { createProxyMiddleware, RequestHandler, Options as ProxyOptions } from 'http-proxy-middleware';
import { register, collectDefaultMetrics } from 'prom-client';
import winston from 'winston';
import { IncomingMessage, ServerResponse, ClientRequest } from 'http';
import * as httpProxy from 'http-proxy';

import { kongConfig } from './config/kong.config';
import corsMiddleware from './middleware/cors';
import createRateLimiter from './middleware/rate-limiter';
import securityMiddleware from './middleware/security';
import { HttpStatus } from '@shared/constants/http-status';
import { ErrorCode, ErrorMessage } from '@shared/constants/error-codes';
import { Logger, globalLogger } from '@shared/middleware/logger';
import { EncryptionService } from '@shared/utils/encryption.utils';

// Load environment variables
dotenv.config();

// Global constants
const PORT = process.env.PORT || 8000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const API_VERSION = process.env.API_VERSION || 'v1';
const LOG_LEVEL = process.env.LOG_LEVEL || 'info';
const AUDIT_ENABLED = process.env.AUDIT_ENABLED === 'true';

// Type definitions for Kong config indexing
type ServiceName = keyof typeof kongConfig.services;
type RouteConfig = typeof kongConfig.routes[ServiceName];

/**
 * Initializes Express server with enhanced security and monitoring
 */
function initializeServer(): express.Express {
  const app = express();

  // Initialize metrics collection
  collectDefaultMetrics();

  // Initialize encryption service
  const encryptionService = new EncryptionService({
    keyId: process.env.KMS_KEY_ID!,
    region: process.env.AWS_REGION!,
    algorithm: 'aes-256-gcm',
    cacheExpiry: 3600 // 1 hour
  });

  setupMiddleware(app);
  setupRoutes(app);

  return app;
}

/**
 * Configures comprehensive middleware chain
 */
function setupMiddleware(app: express.Express): void {
  // Body parsing middleware must come first
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true, limit: '10mb' }));

  // Request logging with audit trail
  app.use(globalLogger.createRequestLogger());
  app.use(globalLogger.createHttpLogger());

  // Apply CORS first
  app.use(corsMiddleware(NODE_ENV));
  
  // Then apply other security middleware
  app.use(securityMiddleware());
  app.use(createRateLimiter({
    redis: {
      nodes: [
        {
          host: process.env.REDIS_URL?.split('://')[1]?.split(':')[0] || 'redis',
          port: parseInt(process.env.REDIS_URL?.split(':')[2] || '6379')
        }
      ],
      options: {
        enableReadyCheck: true,
        maxRedirections: 16,
        clusterRetryStrategy: (times: number) => Math.min(times * 100, 3000),
        redisOptions: {
          password: process.env.REDIS_PASSWORD,
          username: process.env.REDIS_USERNAME
        }
      }
    },
    limits: {
      standard: parseInt(process.env.RATE_LIMIT_PER_MINUTE || '60'),
      premium: parseInt(process.env.RATE_LIMIT_PER_MINUTE || '60') * 2
    },
    windowMs: 60000,
    fallbackStrategy: 'PERMISSIVE',
    circuitBreaker: {
      timeout: 5000,
      resetTimeout: 30000,
      errorThreshold: 50
    }
  }));
}

/**
 * Configures API routes with security and validation
 */
function setupRoutes(app: express.Express): void {
  // Health check endpoint
  app.get('/health', async (req: express.Request, res: express.Response) => {
    try {
      const result = {
        status: 'up',
        version: process.env.npm_package_version,
        timestamp: new Date().toISOString()
      };
      res.status(HttpStatus.OK).json(result);
    } catch (error) {
      res.status(HttpStatus.SERVICE_UNAVAILABLE).json({
        status: 'error',
        error: error instanceof Error ? error.message : 'Health check failed'
      });
    }
  });

  // Metrics endpoint
  app.get('/metrics', async (req: express.Request, res: express.Response) => {
    res.set('Content-Type', register.contentType);
    res.end(await register.metrics());
  });

  // API version prefix
  const apiRouter = express.Router();

  // Configure service routes with proxying
  Object.entries(kongConfig.services).forEach(([serviceName, serviceConfig]) => {
    const routeConfig = kongConfig.routes[serviceName as ServiceName];
    const pathPrefix = routeConfig.paths[0].replace(`/api/${API_VERSION}`, '');
    
    console.log('🔧 Setting up proxy for service:', {
      service: serviceName,
      pathPrefix,
      targetUrl: serviceConfig.url,
      routePaths: routeConfig.paths
    });

    // Create custom proxy middleware
    const proxyMiddleware = async (req: express.Request, res: express.Response, next: express.NextFunction) => {
      try {
        // Log incoming request
        console.log('📝 Request hit proxy middleware:', {
          service: serviceName,
          method: req.method,
          path: req.path,
          originalUrl: req.originalUrl,
          pathPrefix,
          body: req.method === 'POST' ? { ...req.body, password: '[REDACTED]' } : undefined,
          headers: req.headers
        });

        // Calculate target path
        const targetPath = req.path.replace(pathPrefix, '');
        const targetUrl = new URL(`${serviceConfig.url}/api/${API_VERSION}${targetPath}`);

        console.log('🎯 Proxy target:', {
          originalUrl: req.originalUrl,
          targetUrl: targetUrl.toString(),
          method: req.method,
          service: serviceName
        });

        // Create proxy request options
        const proxyOptions = {
          method: req.method,
          headers: {
            ...req.headers,
            host: targetUrl.host,
          },
        };

        // Log proxy request
        console.log('📤 Sending proxy request:', {
          url: targetUrl.toString(),
          method: proxyOptions.method,
          headers: proxyOptions.headers,
          service: serviceName
        });

        // Make the proxy request
        const proxyReq = require('http').request(targetUrl, proxyOptions, (proxyRes: IncomingMessage) => {
          console.log('📥 Received proxy response:', {
            statusCode: proxyRes.statusCode,
            headers: proxyRes.headers,
            service: serviceName
          });

          // Forward status and headers
          res.status(proxyRes.statusCode || 500);
          Object.entries(proxyRes.headers).forEach(([key, value]) => {
            if (value) res.setHeader(key, value);
          });

          // Forward response body
          let responseBody = '';
          proxyRes.on('data', (chunk) => {
            responseBody += chunk;
            res.write(chunk);
          });

          proxyRes.on('end', () => {
            console.log('📥 Response completed:', {
              statusCode: proxyRes.statusCode,
              service: serviceName,
              body: responseBody.length > 1000 ? responseBody.substring(0, 1000) + '...' : responseBody
            });
            res.end();
          });
        });

        // Handle proxy errors
        proxyReq.on('error', (error: Error) => {
          console.error('❌ Proxy request error:', {
            error: error.message,
            stack: error.stack,
            service: serviceName,
            targetUrl: targetUrl.toString()
          });

          res.status(HttpStatus.SERVICE_UNAVAILABLE).json({
            error: ErrorCode.SERVICE_UNAVAILABLE,
            message: 'Service temporarily unavailable'
          });
        });

        // Write request body for POST/PUT/PATCH
        if (['POST', 'PUT', 'PATCH'].includes(req.method) && req.body) {
          const bodyData = JSON.stringify(req.body);
          proxyReq.setHeader('Content-Type', 'application/json');
          proxyReq.setHeader('Content-Length', Buffer.byteLength(bodyData));
          
          console.log('📦 Writing request body:', {
            method: req.method,
            contentLength: Buffer.byteLength(bodyData),
            service: serviceName
          });
          
          proxyReq.write(bodyData);
        }

        // End the request
        proxyReq.end();

      } catch (error) {
        console.error('❌ Proxy middleware error:', {
          error: error instanceof Error ? error.message : 'Unknown error',
          stack: error instanceof Error ? error.stack : undefined,
          service: serviceName
        });
        next(error);
      }
    };

    // Mount the proxy middleware
    apiRouter.use(pathPrefix, proxyMiddleware);
    
    console.log('🔌 Mounted proxy middleware for:', {
      service: serviceName,
      pathPrefix,
      targetUrl: serviceConfig.url
    });
  });

  // Mount the API router
  app.use(`/api/${API_VERSION}`, apiRouter);

  // Error handling middleware must be last
  app.use((err: Error, req: express.Request, res: express.Response, next: express.NextFunction) => {
    globalLogger.error('Unhandled error', { error: err });
    res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
      error: ErrorCode.INTERNAL_SERVER_ERROR,
      message: ErrorMessage[ErrorCode.INTERNAL_SERVER_ERROR].message
    });
  });
}

/**
 * Starts the server with comprehensive monitoring
 */
function startServer(app: express.Express): void {
  try {
    const server = app.listen(PORT, () => {
      globalLogger.info(`API Gateway started`, {
        port: PORT,
        environment: NODE_ENV,
        apiVersion: API_VERSION
      });
    });

    // Graceful shutdown
    process.on('SIGTERM', () => {
      globalLogger.info('Received SIGTERM signal, initiating graceful shutdown');
      server.close(() => {
        globalLogger.info('Server shutdown completed');
        process.exit(0);
      });
    });

  } catch (error) {
    globalLogger.error('Failed to start server', { error });
    process.exit(1);
  }
}

// Initialize and start server
const app = initializeServer();
startServer(app);

export default app;