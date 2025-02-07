/**
 * @fileoverview Advanced Rate Limiting Middleware
 * Implements sliding window rate limiting with Redis cluster support for the AUSTA SuperApp API Gateway.
 * Provides sophisticated request throttling with user type differentiation and graceful degradation.
 * 
 * @version 1.0.0
 */

import express from 'express';
import rateLimit from 'express-rate-limit';
import RedisStore from 'rate-limit-redis';
import * as Redis from 'ioredis';
const CircuitBreaker = require('opossum');
import { Request, Response, NextFunction } from 'express'; // v4.18.2
import { createLogger, format, transports } from 'winston'; // v3.8.2
import { HttpStatus } from '@shared/constants/http-status';
import { kongConfig } from '../config/kong.config';

// Add type declaration for opossum
declare module 'opossum';

// Configure logging
const logger = createLogger({
  format: format.combine(
    format.timestamp(),
    format.json()
  ),
  transports: [
    new transports.File({ filename: 'rate-limiter.log' })
  ]
});

// Type definitions
type UserType = 'standard' | 'premium';

interface RateLimiterConfig {
  redis: {
    nodes: { host: string; port: number }[];
    options: Redis.ClusterOptions;
  };
  limits: {
    standard: number;
    premium: number;
  };
  windowMs: number;
  fallbackStrategy: 'STRICT' | 'PERMISSIVE';
  circuitBreaker: {
    timeout: number;
    resetTimeout: number;
    errorThreshold: number;
  };
}

interface RateLimitResult {
  limited: boolean;
  remaining: number;
  reset: number;
  total: number;
}

interface SlidingWindow {
  count: number;
  timestamp: number;
}

// Extend Request type to include user property
interface AuthenticatedRequest extends Request {
  user?: {
    id: string;
    type: 'standard' | 'premium';
  };
}

/**
 * Rate Limiter class implementing sliding window algorithm with Redis cluster support
 */
class RateLimiter {
  private redisCluster!: Redis.Cluster;  // Using definite assignment assertion
  private redisBreaker: any;
  private config: RateLimiterConfig;
  private localCounters: Map<string, SlidingWindow>;
  private isRedisAvailable: boolean = true;

  constructor(config: RateLimiterConfig) {
    this.config = config;
    this.localCounters = new Map();

    // Initialize Redis cluster with better error handling
    try {
      this.redisCluster = new Redis.Cluster(config.redis.nodes, {
        ...config.redis.options,
        clusterRetryStrategy: (times) => {
          const delay = Math.min(times * 100, 3000);
          logger.warn(`Redis cluster retry attempt ${times}, waiting ${delay}ms`);
          return delay;
        }
      });

      this.redisCluster.on('error', (err) => {
        logger.error('Redis cluster error:', err);
        this.isRedisAvailable = false;
      });

      this.redisCluster.on('ready', () => {
        logger.info('Redis cluster is ready');
        this.isRedisAvailable = true;
      });

      this.redisCluster.on('connect', () => {
        logger.info('Redis cluster is connecting');
      });

      this.redisCluster.on('reconnecting', () => {
        logger.warn('Redis cluster is reconnecting');
        this.isRedisAvailable = false;
      });
    } catch (error) {
      logger.error('Failed to initialize Redis cluster:', error);
      this.isRedisAvailable = false;
    }

    // Initialize circuit breaker with better configuration
    this.redisBreaker = new CircuitBreaker(
      async (key: string) => {
        if (!this.isRedisAvailable) {
          throw new Error('Redis is unavailable');
        }
        return await this.redisCluster.get(key);
      },
      {
        timeout: config.circuitBreaker.timeout,
        resetTimeout: config.circuitBreaker.resetTimeout,
        errorThresholdPercentage: config.circuitBreaker.errorThreshold,
        name: 'redis-rate-limiter'
      }
    );

    this.redisBreaker.fallback(() => {
      logger.warn('Circuit breaker fallback activated, using local counters');
      return null;
    });

    // Periodic cleanup of local counters
    setInterval(() => {
      this.cleanupLocalCounters();
    }, config.windowMs);
  }

  private cleanupLocalCounters(): void {
    const now = Date.now();
    for (const [key, window] of this.localCounters.entries()) {
      if (now - window.timestamp > this.config.windowMs) {
        this.localCounters.delete(key);
      }
    }
  }

  public async checkLimit(clientId: string, userType: UserType): Promise<RateLimitResult> {
    const now = Date.now();
    const key = `ratelimit:${clientId}:${userType}`;
    
    try {
      if (this.isRedisAvailable) {
        // Try Redis first
        const result = await this.redisBreaker.fire(key);
        if (result !== null) {
          return JSON.parse(result);
        }
      }
      
      // Fallback to local counting if Redis is unavailable
      return this.checkLocalLimit(clientId, userType, now);
    } catch (error) {
      logger.error('Rate limiting error:', error);
      
      // Use fallback strategy based on configuration
      if (this.config.fallbackStrategy === 'PERMISSIVE') {
        return {
          limited: false,
          remaining: this.config.limits[userType],
          reset: now + this.config.windowMs,
          total: this.config.limits[userType]
        };
      }
      
      // Default to local limiting
      return this.checkLocalLimit(clientId, userType, now);
    }
  }

  private checkLocalLimit(clientId: string, userType: UserType, now: number): RateLimitResult {
    const key = `${clientId}:${userType}`;
    const limit = this.config.limits[userType];
    
    const currentWindow = this.localCounters.get(key) || { count: 0, timestamp: now };
    
    // Clean up old window
    if (now - currentWindow.timestamp > this.config.windowMs) {
      currentWindow.count = 0;
      currentWindow.timestamp = now;
    }
    
    const isLimited = currentWindow.count >= limit;
    if (!isLimited) {
      currentWindow.count++;
    }
    
    this.localCounters.set(key, currentWindow);
    
    return {
      limited: isLimited,
      remaining: Math.max(0, limit - currentWindow.count),
      reset: currentWindow.timestamp + this.config.windowMs,
      total: limit
    };
  }

  /**
   * Performs health check on Redis cluster
   */
  private async healthCheck() {
    try {
      await this.redisCluster.ping();
      logger.info('Redis health check passed');
    } catch (error) {
      logger.error('Redis health check failed', { error });
    }
  }

  /**
   * Cleanup resources on shutdown
   */
  public async cleanup(): Promise<void> {
    try {
      await this.redisCluster.quit();
      this.localCounters.clear();
      logger.info('Rate limiter cleanup completed');
    } catch (error) {
      logger.error('Rate limiter cleanup failed', { error });
    }
  }
}

/**
 * Creates rate limiter middleware instance
 */
export default function createRateLimiter(config: RateLimiterConfig) {
  const rateLimiter = new RateLimiter(config);

  // Handle graceful shutdown
  process.on('SIGTERM', async () => {
    await rateLimiter.cleanup();
  });

  return async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    // Skip rate limiting for health and metrics endpoints
    if (req.path === '/health' || req.path === '/metrics') {
      return next();
    }

    try {
      const clientId = req.user?.id || req.ip || 'anonymous';
      const userType = req.user?.type || 'standard';

      const result = await rateLimiter.checkLimit(clientId, userType);

      // Set rate limit headers
      res.set({
        'X-RateLimit-Limit': result.total.toString(),
        'X-RateLimit-Remaining': result.remaining.toString(),
        'X-RateLimit-Reset': result.reset.toString()
      });

      if (result.limited) {
        logger.warn('Rate limit exceeded', { 
          clientId, 
          userType,
          path: req.path,
          method: req.method 
        });
        
        return res.status(429).json({
          error: 'Too many requests',
          retryAfter: result.reset - Math.floor(Date.now() / 1000)
        });
      }

      next();
    } catch (error) {
      logger.error('Rate limiter error', { error });
      
      if (config.fallbackStrategy === 'PERMISSIVE') {
        next();
      } else {
        res.status(500).json({
          error: 'Rate limiting service unavailable'
        });
      }
    }
  };
}