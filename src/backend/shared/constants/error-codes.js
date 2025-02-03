"use strict";
/**
 * @fileoverview Centralized error code definitions and messages for AUSTA SuperApp
 * Implements HIPAA-compliant error handling with enhanced security and auditing
 * @version 1.0.0
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.ErrorMessage = exports.ErrorSeverity = exports.ErrorCode = exports.ErrorCategory = void 0;
/**
 * High-level categorization of errors for proper handling and monitoring
 */
var ErrorCategory;
(function (ErrorCategory) {
    ErrorCategory["AUTHENTICATION"] = "AUTHENTICATION";
    ErrorCategory["AUTHORIZATION"] = "AUTHORIZATION";
    ErrorCategory["VALIDATION"] = "VALIDATION";
    ErrorCategory["BUSINESS_LOGIC"] = "BUSINESS_LOGIC";
    ErrorCategory["EXTERNAL_SERVICE"] = "EXTERNAL_SERVICE";
    ErrorCategory["DATABASE"] = "DATABASE";
    ErrorCategory["NETWORK"] = "NETWORK";
    ErrorCategory["SYSTEM"] = "SYSTEM";
    ErrorCategory["COMPLIANCE"] = "COMPLIANCE";
    ErrorCategory["SECURITY"] = "SECURITY";
})(ErrorCategory = exports.ErrorCategory || (exports.ErrorCategory = {}));
/**
 * Comprehensive set of error codes with security and compliance coverage
 */
var ErrorCode;
(function (ErrorCode) {
    // Authentication & Authorization
    ErrorCode["UNAUTHORIZED"] = "UNAUTHORIZED";
    ErrorCode["FORBIDDEN"] = "FORBIDDEN";
    ErrorCode["INVALID_CREDENTIALS"] = "INVALID_CREDENTIALS";
    ErrorCode["TOKEN_EXPIRED"] = "TOKEN_EXPIRED";
    // Validation & Business Logic
    ErrorCode["INVALID_INPUT"] = "INVALID_INPUT";
    ErrorCode["RESOURCE_NOT_FOUND"] = "RESOURCE_NOT_FOUND";
    ErrorCode["DUPLICATE_RECORD"] = "DUPLICATE_RECORD";
    ErrorCode["INVALID_OPERATION"] = "INVALID_OPERATION";
    // Infrastructure & System
    ErrorCode["DATABASE_ERROR"] = "DATABASE_ERROR";
    ErrorCode["EXTERNAL_API_ERROR"] = "EXTERNAL_API_ERROR";
    ErrorCode["NETWORK_ERROR"] = "NETWORK_ERROR";
    ErrorCode["INTERNAL_SERVER_ERROR"] = "INTERNAL_SERVER_ERROR";
    ErrorCode["SERVICE_UNAVAILABLE"] = "SERVICE_UNAVAILABLE";
    // Security & Compliance
    ErrorCode["HIPAA_VIOLATION"] = "HIPAA_VIOLATION";
    ErrorCode["LGPD_VIOLATION"] = "LGPD_VIOLATION";
    ErrorCode["RATE_LIMIT_EXCEEDED"] = "RATE_LIMIT_EXCEEDED";
    ErrorCode["SESSION_EXPIRED"] = "SESSION_EXPIRED";
    ErrorCode["DATA_ENCRYPTION_ERROR"] = "DATA_ENCRYPTION_ERROR";
    ErrorCode["AUDIT_LOG_ERROR"] = "AUDIT_LOG_ERROR";
})(ErrorCode = exports.ErrorCode || (exports.ErrorCode = {}));
/**
 * Error severity levels for proper alerting and handling
 */
var ErrorSeverity;
(function (ErrorSeverity) {
    ErrorSeverity["CRITICAL"] = "CRITICAL";
    ErrorSeverity["HIGH"] = "HIGH";
    ErrorSeverity["MEDIUM"] = "MEDIUM";
    ErrorSeverity["LOW"] = "LOW";
    ErrorSeverity["INFO"] = "INFO";
})(ErrorSeverity = exports.ErrorSeverity || (exports.ErrorSeverity = {}));
/**
 * HIPAA-compliant error messages with metadata for security and auditing
 * Messages are designed to be informative while preventing sensitive data exposure
 */
exports.ErrorMessage = {
    // Authentication & Authorization Errors
    [ErrorCode.UNAUTHORIZED]: {
        message: 'Authentication required to access this resource',
        severity: ErrorSeverity.HIGH,
        category: ErrorCategory.AUTHENTICATION,
        auditRequired: true
    },
    [ErrorCode.FORBIDDEN]: {
        message: 'Insufficient permissions to perform this operation',
        severity: ErrorSeverity.HIGH,
        category: ErrorCategory.AUTHORIZATION,
        auditRequired: true
    },
    [ErrorCode.INVALID_CREDENTIALS]: {
        message: 'Invalid authentication credentials provided',
        severity: ErrorSeverity.HIGH,
        category: ErrorCategory.AUTHENTICATION,
        auditRequired: true
    },
    [ErrorCode.TOKEN_EXPIRED]: {
        message: 'Authentication token has expired',
        severity: ErrorSeverity.MEDIUM,
        category: ErrorCategory.AUTHENTICATION,
        auditRequired: true
    },
    // Validation & Business Logic Errors
    [ErrorCode.INVALID_INPUT]: {
        message: 'The provided input data is invalid or incomplete',
        severity: ErrorSeverity.LOW,
        category: ErrorCategory.VALIDATION,
        auditRequired: false
    },
    [ErrorCode.RESOURCE_NOT_FOUND]: {
        message: 'The requested resource could not be found',
        severity: ErrorSeverity.LOW,
        category: ErrorCategory.BUSINESS_LOGIC,
        auditRequired: false
    },
    [ErrorCode.DUPLICATE_RECORD]: {
        message: 'A record with this identifier already exists',
        severity: ErrorSeverity.LOW,
        category: ErrorCategory.BUSINESS_LOGIC,
        auditRequired: false
    },
    [ErrorCode.INVALID_OPERATION]: {
        message: 'The requested operation cannot be performed',
        severity: ErrorSeverity.MEDIUM,
        category: ErrorCategory.BUSINESS_LOGIC,
        auditRequired: true
    },
    // Infrastructure & System Errors
    [ErrorCode.DATABASE_ERROR]: {
        message: 'An error occurred while accessing the database',
        severity: ErrorSeverity.HIGH,
        category: ErrorCategory.DATABASE,
        auditRequired: true
    },
    [ErrorCode.EXTERNAL_API_ERROR]: {
        message: 'Error communicating with external service',
        severity: ErrorSeverity.HIGH,
        category: ErrorCategory.EXTERNAL_SERVICE,
        auditRequired: true
    },
    [ErrorCode.NETWORK_ERROR]: {
        message: 'Network communication error occurred',
        severity: ErrorSeverity.HIGH,
        category: ErrorCategory.NETWORK,
        auditRequired: true
    },
    [ErrorCode.INTERNAL_SERVER_ERROR]: {
        message: 'An unexpected internal server error occurred',
        severity: ErrorSeverity.CRITICAL,
        category: ErrorCategory.SYSTEM,
        auditRequired: true
    },
    [ErrorCode.SERVICE_UNAVAILABLE]: {
        message: 'The service is temporarily unavailable',
        severity: ErrorSeverity.CRITICAL,
        category: ErrorCategory.SYSTEM,
        auditRequired: true
    },
    // Security & Compliance Errors
    [ErrorCode.HIPAA_VIOLATION]: {
        message: 'Operation would violate HIPAA compliance requirements',
        severity: ErrorSeverity.CRITICAL,
        category: ErrorCategory.COMPLIANCE,
        auditRequired: true
    },
    [ErrorCode.LGPD_VIOLATION]: {
        message: 'Operation would violate LGPD compliance requirements',
        severity: ErrorSeverity.CRITICAL,
        category: ErrorCategory.COMPLIANCE,
        auditRequired: true
    },
    [ErrorCode.RATE_LIMIT_EXCEEDED]: {
        message: 'Request rate limit has been exceeded',
        severity: ErrorSeverity.MEDIUM,
        category: ErrorCategory.SECURITY,
        auditRequired: true
    },
    [ErrorCode.SESSION_EXPIRED]: {
        message: 'User session has expired',
        severity: ErrorSeverity.MEDIUM,
        category: ErrorCategory.SECURITY,
        auditRequired: true
    },
    [ErrorCode.DATA_ENCRYPTION_ERROR]: {
        message: 'Error occurred during data encryption/decryption',
        severity: ErrorSeverity.CRITICAL,
        category: ErrorCategory.SECURITY,
        auditRequired: true
    },
    [ErrorCode.AUDIT_LOG_ERROR]: {
        message: 'Error occurred while recording audit log',
        severity: ErrorSeverity.CRITICAL,
        category: ErrorCategory.SECURITY,
        auditRequired: true
    }
};
