/**
 * @fileoverview Common configuration settings used across AUSTA services
 */

/**
 * Security configuration
 */
export const SecurityConfig = {
  jwt: {
    expiresIn: '1h',
    refreshExpiresIn: '7d',
    algorithm: 'RS256' as const,
    issuer: 'austa-platform',
    audience: ['austa-services'],
  },
  password: {
    minLength: 8,
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
    requireSpecialChars: true,
    maxAge: 90, // days
    preventReuse: 5, // previous passwords
  },
  mfa: {
    required: true,
    allowedTypes: ['authenticator', 'sms', 'email'] as const,
    issuer: 'AUSTA Healthcare',
    validityWindow: 300, // seconds
    backupCodes: 10,
  },
  session: {
    maxAge: 3600, // 1 hour in seconds
    inactivityTimeout: 900, // 15 minutes in seconds
    maxConcurrent: 5,
  },
  rateLimit: {
    window: 60 * 1000, // 1 minute
    max: 100,
  },
  devices: {
    maxPerUser: 5,
    trustDuration: 30, // days
  }
};

/**
 * Redis configuration
 */
export const RedisConfig = {
  keyPrefix: 'austa:',
  defaultTTL: 3600,
  connectionTimeout: 10000,
  maxRetriesPerRequest: 3,
};

/**
 * Logging configuration
 */
export const LogConfig = {
  level: process.env.NODE_ENV === 'production' ? 'info' : 'debug',
  format: 'json',
  timestampFormat: 'YYYY-MM-DD HH:mm:ss.SSS',
  maskFields: [
    'password',
    'token',
    'refreshToken',
    'ssn',
    'creditCard',
    'mfaSecret'
  ],
};

/**
 * Health check configuration
 */
export const HealthCheckConfig = {
  interval: 30000, // 30 seconds
  timeout: 5000,   // 5 seconds
  unhealthyThreshold: 3,
}; 