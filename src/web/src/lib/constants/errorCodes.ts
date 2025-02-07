/**
 * @fileoverview Error code constants for AUSTA SuperApp frontend
 * Implements standardized error handling with HIPAA compliance
 * @version 1.0.0
 */

/**
 * Error categories for different types of errors
 */
export enum ErrorCategory {
  VALIDATION = 'VALIDATION',
  AUTHENTICATION = 'AUTHENTICATION',
  AUTHORIZATION = 'AUTHORIZATION',
  API = 'API',
  NETWORK = 'NETWORK',
  SECURITY = 'SECURITY',
  HIPAA = 'HIPAA',
  SYSTEM = 'SYSTEM'
}

/**
 * Standardized error codes for the application
 */
export enum ErrorCode {
  // Validation errors
  INVALID_INPUT = 'INVALID_INPUT',
  REQUIRED_FIELD = 'REQUIRED_FIELD',
  INVALID_FORMAT = 'INVALID_FORMAT',
  VALIDATION_FAILED = 'VALIDATION_FAILED',

  // Authentication errors
  INVALID_CREDENTIALS = 'INVALID_CREDENTIALS',
  SESSION_EXPIRED = 'SESSION_EXPIRED',
  MFA_REQUIRED = 'MFA_REQUIRED',
  INVALID_TOKEN = 'INVALID_TOKEN',
  ACCOUNT_LOCKED = 'ACCOUNT_LOCKED',

  // Authorization errors
  UNAUTHORIZED = 'UNAUTHORIZED',
  INSUFFICIENT_PERMISSIONS = 'INSUFFICIENT_PERMISSIONS',
  FORBIDDEN = 'FORBIDDEN',

  // API errors
  API_ERROR = 'API_ERROR',
  REQUEST_FAILED = 'REQUEST_FAILED',
  RESPONSE_ERROR = 'RESPONSE_ERROR',
  RATE_LIMIT_EXCEEDED = 'RATE_LIMIT_EXCEEDED',

  // Network errors
  NETWORK_ERROR = 'NETWORK_ERROR',
  CONNECTION_FAILED = 'CONNECTION_FAILED',
  TIMEOUT = 'TIMEOUT',

  // Security errors
  SECURITY_ERROR = 'SECURITY_ERROR',
  ENCRYPTION_FAILED = 'ENCRYPTION_FAILED',
  DECRYPTION_FAILED = 'DECRYPTION_FAILED',
  INTEGRITY_CHECK_FAILED = 'INTEGRITY_CHECK_FAILED',

  // HIPAA compliance errors
  HIPAA_VIOLATION = 'HIPAA_VIOLATION',
  PHI_EXPOSURE_RISK = 'PHI_EXPOSURE_RISK',
  AUDIT_LOG_FAILURE = 'AUDIT_LOG_FAILURE',

  // System errors
  INTERNAL_SERVER_ERROR = 'INTERNAL_SERVER_ERROR',
  SERVICE_UNAVAILABLE = 'SERVICE_UNAVAILABLE',
  MAINTENANCE_MODE = 'MAINTENANCE_MODE'
}

/**
 * Error tracking utility for capturing and reporting errors
 */
export const ErrorTracker = {
  captureError: (error: Error, context?: Record<string, any>) => {
    console.error('[ErrorTracker]', {
      error: {
        name: error.name,
        message: error.message,
        stack: error.stack
      },
      context,
      timestamp: new Date().toISOString()
    });
  }
};

export default ErrorCode;