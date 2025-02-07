/**
 * @fileoverview Centralized error code definitions and messages for AUSTA SuperApp
 * Implements HIPAA-compliant error handling with enhanced security and auditing
 * @version 1.0.0
 */

/**
 * High-level categorization of errors for proper handling and monitoring
 */
export enum ErrorCategory {
  AUTHENTICATION = 'AUTHENTICATION',
  AUTHORIZATION = 'AUTHORIZATION',
  BUSINESS_LOGIC = 'BUSINESS_LOGIC',
  SECURITY = 'SECURITY',
  COMPLIANCE = 'COMPLIANCE',
  SYSTEM = 'SYSTEM',
  DATABASE = 'DATABASE',
  EXTERNAL = 'EXTERNAL',
  AUDIT = 'AUDIT'
}

/**
 * Comprehensive set of error codes with security and compliance coverage
 */
export enum ErrorCode {
  INVALID_INPUT = 'INVALID_INPUT',
  INVALID_CREDENTIALS = 'INVALID_CREDENTIALS',
  UNAUTHORIZED = 'UNAUTHORIZED',
  FORBIDDEN = 'FORBIDDEN',
  NOT_FOUND = 'NOT_FOUND',
  DUPLICATE_RECORD = 'DUPLICATE_RECORD',
  INTERNAL_SERVER_ERROR = 'INTERNAL_SERVER_ERROR',
  RATE_LIMIT_EXCEEDED = 'RATE_LIMIT_EXCEEDED',
  SESSION_EXPIRED = 'SESSION_EXPIRED',
  DATA_VALIDATION_ERROR = 'DATA_VALIDATION_ERROR',
  MFA_REQUIRED = 'MFA_REQUIRED',
  MFA_INVALID = 'MFA_INVALID',
  DEVICE_NOT_TRUSTED = 'DEVICE_NOT_TRUSTED',
  DATA_ENCRYPTION_ERROR = 'DATA_ENCRYPTION_ERROR',
  HIPAA_VIOLATION = 'HIPAA_VIOLATION',
  TOKEN_GENERATION_FAILED = 'TOKEN_GENERATION_FAILED',
  TOKEN_VERIFICATION_FAILED = 'TOKEN_VERIFICATION_FAILED',
  TOKEN_INVALID = 'TOKEN_INVALID',
  TOKEN_EXPIRED = 'TOKEN_EXPIRED',
  TOKEN_REFRESH_FAILED = 'TOKEN_REFRESH_FAILED',
  SERVICE_UNAVAILABLE = 'SERVICE_UNAVAILABLE',
  DUPLICATE_ENTRY = 'DUPLICATE_ENTRY',
  USER_NOT_FOUND = 'USER_NOT_FOUND',
  INVALID_VERIFICATION_TOKEN = 'INVALID_VERIFICATION_TOKEN'
}

/**
 * Error severity levels for proper alerting and handling
 */
export enum ErrorSeverity {
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  CRITICAL = 'CRITICAL'
}

/**
 * Interface for error message metadata
 */
export interface ErrorMessageMetadata {
  code: ErrorCode;
  message: string;
  category: ErrorCategory;
  severity: ErrorSeverity;
  auditRequired?: boolean;
}

/**
 * HIPAA-compliant error messages with metadata for security and auditing
 * Messages are designed to be informative while preventing sensitive data exposure
 */
export const ErrorMessage: Record<ErrorCode, ErrorMessageMetadata> = {
  [ErrorCode.INVALID_INPUT]: {
    code: ErrorCode.INVALID_INPUT,
    message: 'Invalid input parameters',
    category: ErrorCategory.BUSINESS_LOGIC,
    severity: ErrorSeverity.LOW
  },
  [ErrorCode.INVALID_CREDENTIALS]: {
    code: ErrorCode.INVALID_CREDENTIALS,
    message: 'Invalid credentials',
    category: ErrorCategory.AUTHENTICATION,
    severity: ErrorSeverity.MEDIUM,
    auditRequired: true
  },
  [ErrorCode.UNAUTHORIZED]: {
    code: ErrorCode.UNAUTHORIZED,
    message: 'Unauthorized access',
    category: ErrorCategory.AUTHORIZATION,
    severity: ErrorSeverity.HIGH,
    auditRequired: true
  },
  [ErrorCode.FORBIDDEN]: {
    code: ErrorCode.FORBIDDEN,
    message: 'Access forbidden',
    category: ErrorCategory.AUTHORIZATION,
    severity: ErrorSeverity.HIGH,
    auditRequired: true
  },
  [ErrorCode.NOT_FOUND]: {
    code: ErrorCode.NOT_FOUND,
    message: 'Resource not found',
    category: ErrorCategory.BUSINESS_LOGIC,
    severity: ErrorSeverity.LOW
  },
  [ErrorCode.DUPLICATE_RECORD]: {
    code: ErrorCode.DUPLICATE_RECORD,
    message: 'Record already exists',
    category: ErrorCategory.BUSINESS_LOGIC,
    severity: ErrorSeverity.LOW
  },
  [ErrorCode.INTERNAL_SERVER_ERROR]: {
    code: ErrorCode.INTERNAL_SERVER_ERROR,
    message: 'Internal server error',
    category: ErrorCategory.SYSTEM,
    severity: ErrorSeverity.HIGH,
    auditRequired: true
  },
  [ErrorCode.RATE_LIMIT_EXCEEDED]: {
    code: ErrorCode.RATE_LIMIT_EXCEEDED,
    message: 'Rate limit exceeded',
    category: ErrorCategory.SECURITY,
    severity: ErrorSeverity.MEDIUM,
    auditRequired: true
  },
  [ErrorCode.SESSION_EXPIRED]: {
    code: ErrorCode.SESSION_EXPIRED,
    message: 'Session has expired',
    category: ErrorCategory.AUTHENTICATION,
    severity: ErrorSeverity.LOW
  },
  [ErrorCode.DATA_VALIDATION_ERROR]: {
    code: ErrorCode.DATA_VALIDATION_ERROR,
    message: 'Data validation failed',
    category: ErrorCategory.BUSINESS_LOGIC,
    severity: ErrorSeverity.LOW
  },
  [ErrorCode.MFA_REQUIRED]: {
    code: ErrorCode.MFA_REQUIRED,
    message: 'Multi-factor authentication required',
    category: ErrorCategory.AUTHENTICATION,
    severity: ErrorSeverity.MEDIUM
  },
  [ErrorCode.MFA_INVALID]: {
    code: ErrorCode.MFA_INVALID,
    message: 'Invalid MFA code',
    category: ErrorCategory.AUTHENTICATION,
    severity: ErrorSeverity.MEDIUM,
    auditRequired: true
  },
  [ErrorCode.DEVICE_NOT_TRUSTED]: {
    code: ErrorCode.DEVICE_NOT_TRUSTED,
    message: 'Device not trusted',
    category: ErrorCategory.SECURITY,
    severity: ErrorSeverity.HIGH,
    auditRequired: true
  },
  [ErrorCode.DATA_ENCRYPTION_ERROR]: {
    code: ErrorCode.DATA_ENCRYPTION_ERROR,
    message: 'Data encryption error',
    category: ErrorCategory.SECURITY,
    severity: ErrorSeverity.CRITICAL,
    auditRequired: true
  },
  [ErrorCode.HIPAA_VIOLATION]: {
    code: ErrorCode.HIPAA_VIOLATION,
    message: 'HIPAA compliance violation detected',
    category: ErrorCategory.COMPLIANCE,
    severity: ErrorSeverity.CRITICAL,
    auditRequired: true
  },
  [ErrorCode.TOKEN_GENERATION_FAILED]: {
    code: ErrorCode.TOKEN_GENERATION_FAILED,
    message: 'Failed to generate token',
    category: ErrorCategory.AUTHENTICATION,
    severity: ErrorSeverity.HIGH,
    auditRequired: true
  },
  [ErrorCode.TOKEN_VERIFICATION_FAILED]: {
    code: ErrorCode.TOKEN_VERIFICATION_FAILED,
    message: 'Token verification failed',
    category: ErrorCategory.AUTHENTICATION,
    severity: ErrorSeverity.HIGH,
    auditRequired: true
  },
  [ErrorCode.TOKEN_INVALID]: {
    code: ErrorCode.TOKEN_INVALID,
    message: 'Invalid token',
    category: ErrorCategory.AUTHENTICATION,
    severity: ErrorSeverity.HIGH,
    auditRequired: true
  },
  [ErrorCode.TOKEN_EXPIRED]: {
    code: ErrorCode.TOKEN_EXPIRED,
    message: 'Token has expired',
    category: ErrorCategory.AUTHENTICATION,
    severity: ErrorSeverity.MEDIUM,
    auditRequired: true
  },
  [ErrorCode.TOKEN_REFRESH_FAILED]: {
    code: ErrorCode.TOKEN_REFRESH_FAILED,
    message: 'Failed to refresh token',
    category: ErrorCategory.AUTHENTICATION,
    severity: ErrorSeverity.HIGH,
    auditRequired: true
  },
  [ErrorCode.SERVICE_UNAVAILABLE]: {
    code: ErrorCode.SERVICE_UNAVAILABLE,
    message: 'Service unavailable',
    category: ErrorCategory.SYSTEM,
    severity: ErrorSeverity.CRITICAL,
    auditRequired: true
  },
  [ErrorCode.DUPLICATE_ENTRY]: {
    code: ErrorCode.DUPLICATE_ENTRY,
    message: 'Resource already exists',
    category: ErrorCategory.BUSINESS_LOGIC,
    severity: ErrorSeverity.LOW
  },
  [ErrorCode.USER_NOT_FOUND]: {
    code: ErrorCode.USER_NOT_FOUND,
    message: 'User not found',
    category: ErrorCategory.BUSINESS_LOGIC,
    severity: ErrorSeverity.LOW
  },
  [ErrorCode.INVALID_VERIFICATION_TOKEN]: {
    code: ErrorCode.INVALID_VERIFICATION_TOKEN,
    message: 'Invalid verification token',
    category: ErrorCategory.AUTHENTICATION,
    severity: ErrorSeverity.MEDIUM,
    auditRequired: true
  }
};