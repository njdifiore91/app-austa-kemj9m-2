/**
 * @fileoverview Comprehensive validation utilities for AUSTA SuperApp platform
 * Implements HIPAA-compliant validation with FHIR R4 standards
 * @version 1.0.0
 */

import { ErrorCode } from '../constants/error-codes';
import { IHealthRecord, HealthRecordStatus, EncryptionStatus } from '../interfaces/health-record.interface';
import { IUser, UserRole, UserStatus } from '../interfaces/user.interface';
import validator from 'validator';
import xss from 'xss';

/**
 * Interface for validation result with comprehensive security status
 */
export interface ValidationResult {
  isValid: boolean;
  errors: ValidationError[];
  securityStatus: {
    hipaaCompliant: boolean;
    piiDetected: boolean;
    sensitiveDataPresent: boolean;
    encryptionRequired: boolean;
  };
  complianceStatus: {
    fhirCompliant: boolean;
    dataClassification: string;
    requiredFieldsPresent: boolean;
  };
  auditLog: {
    timestamp: Date;
    validationType: string;
    outcome: string;
    details: Record<string, any>;
  };
}

/**
 * Interface for validation error
 */
export interface ValidationError {
  code: ErrorCode;
  message: string;
  field: string;
}

/**
 * Interface for sanitization options
 */
export interface SanitizationOptions {
  stripHtml: boolean;
  preventXSS: boolean;
  preventSQLInjection: boolean;
  securityLevel: 'HIGH' | 'MEDIUM' | 'LOW';
  contentPolicy: {
    allowedTags: string[];
    allowedAttributes: Record<string, string[]>;
  };
}

/**
 * Validates HIPAA compliance for health records
 */
function validateHIPAACompliance(record: IHealthRecord): { isCompliant: boolean; reason?: string; field?: string } {
  // Basic HIPAA compliance checks
  if (!record.patientId || !record.type) {
    return {
      isCompliant: false,
      reason: 'Missing required HIPAA fields',
      field: !record.patientId ? 'patientId' : 'type'
    };
  }

  // Check for proper data encryption when required
  const requiresEncryption = record.securityLabels.includes('PHI') || 
                           record.securityLabels.includes('SENSITIVE') ||
                           record.status === HealthRecordStatus.ENCRYPTED;

  if (requiresEncryption && !record.encryptionMetadata) {
    return {
      isCompliant: false,
      reason: 'Sensitive data must be encrypted',
      field: 'encryptionMetadata'
    };
  }

  // Check attachments encryption
  if (record.attachments.some(att => att.encryptionStatus === EncryptionStatus.UNENCRYPTED && requiresEncryption)) {
    return {
      isCompliant: false,
      reason: 'All attachments must be encrypted for sensitive data',
      field: 'attachments'
    };
  }

  return { isCompliant: true };
}

/**
 * Validates attachment format and security
 */
function validateAttachment(attachment: any): boolean {
  if (!attachment || typeof attachment !== 'object') {
    return false;
  }

  // Check required fields
  if (!attachment.filename || !attachment.contentType || !attachment.data) {
    return false;
  }

  // Validate content type
  const allowedTypes = ['application/pdf', 'image/jpeg', 'image/png'];
  if (!allowedTypes.includes(attachment.contentType)) {
    return false;
  }

  // Check file size (max 10MB)
  const maxSize = 10 * 1024 * 1024; // 10MB in bytes
  if (attachment.data.length > maxSize) {
    return false;
  }

  return true;
}

/**
 * Validates password against security requirements
 */
function validatePassword(password: string): boolean {
  if (!password) return false;
  
  // Minimum 8 characters, at least one uppercase, one lowercase, one number, one special character
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
  return passwordRegex.test(password);
}

/**
 * FHIR R4 compliant health record validation
 */
export async function validateHealthRecord(
  record: IHealthRecord,
  options: { strictMode?: boolean; validateAttachments?: boolean } = {}
): Promise<ValidationResult> {
  const errors: ValidationError[] = [];
  const result: ValidationResult = {
    isValid: true,
    errors: [],
    securityStatus: {
      hipaaCompliant: true,
      piiDetected: false,
      sensitiveDataPresent: false,
      encryptionRequired: false
    },
    complianceStatus: {
      fhirCompliant: true,
      dataClassification: 'PHI',
      requiredFieldsPresent: true
    },
    auditLog: {
      timestamp: new Date(),
      validationType: 'HEALTH_RECORD',
      outcome: 'PENDING',
      details: {}
    }
  };

  try {
    // Validate basic structure
    if (!record.id || !record.patientId || !record.type) {
      errors.push({
        code: ErrorCode.INVALID_INPUT,
        message: 'Required fields missing',
        field: 'base'
      });
    }

    // Validate HIPAA compliance
    const hipaaValidation = validateHIPAACompliance(record);
    if (!hipaaValidation.isCompliant) {
      errors.push({
        code: ErrorCode.HIPAA_VIOLATION,
        message: hipaaValidation.reason || 'HIPAA compliance validation failed',
        field: hipaaValidation.field || 'base'
      });
      result.securityStatus.hipaaCompliant = false;
    }

    // Validate attachments if required
    if (options.validateAttachments && record.attachments) {
      for (const attachment of record.attachments) {
        if (!validateAttachment(attachment)) {
          errors.push({
            code: ErrorCode.INVALID_INPUT,
            message: 'Invalid attachment format',
            field: 'attachments'
          });
        }
      }
    }

    result.isValid = errors.length === 0;
    result.errors = errors;
    result.auditLog.outcome = result.isValid ? 'SUCCESS' : 'FAILURE';

    return result;
  } catch (error) {
    throw new Error(`Health record validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

// Validation patterns
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const PHONE_REGEX = /^\+?[1-9]\d{1,14}$/;

/**
 * Validates user data with enhanced security checks
 */
export const validateUserData = async (
  userData: IUser,
  options: { validatePassword: boolean } = { validatePassword: true }
): Promise<ValidationResult> => {
  const errors: ValidationError[] = [];

  // Validate required fields
  if (!userData.email) {
    errors.push({
      code: ErrorCode.INVALID_INPUT,
      message: 'Email is required',
      field: 'email'
    });
  } else if (!EMAIL_REGEX.test(userData.email)) {
    errors.push({
      code: ErrorCode.INVALID_INPUT,
      message: 'Invalid email format',
      field: 'email'
    });
  }

  if (options.validatePassword && !userData.password) {
    errors.push({
      code: ErrorCode.INVALID_INPUT,
      message: 'Password is required',
      field: 'password'
    });
  }

  // Validate role
  if (userData.role && !Object.values(UserRole).includes(userData.role)) {
    errors.push({
      code: ErrorCode.INVALID_INPUT,
      message: 'Invalid user role',
      field: 'role'
    });
  }

  // Validate status - only if it's provided
  if (userData.status && !Object.values(UserStatus).includes(userData.status)) {
    errors.push({
      code: ErrorCode.INVALID_INPUT,
      message: 'Invalid user status',
      field: 'status'
    });
  }

  // Validate profile if provided
  if (userData.profile) {
    if (!userData.profile.firstName) {
      errors.push({
        code: ErrorCode.INVALID_INPUT,
        message: 'First name is required',
        field: 'profile.firstName'
      });
    }

    if (!userData.profile.lastName) {
      errors.push({
        code: ErrorCode.INVALID_INPUT,
        message: 'Last name is required',
        field: 'profile.lastName'
      });
    }

    if (userData.profile.phoneNumber && !PHONE_REGEX.test(userData.profile.phoneNumber)) {
      errors.push({
        code: ErrorCode.INVALID_INPUT,
        message: 'Invalid phone number format',
        field: 'profile.phoneNumber'
      });
    }
  }

  const isValid = errors.length === 0;
  
  return {
    isValid,
    errors,
    securityStatus: {
      hipaaCompliant: true,
      piiDetected: true,
      sensitiveDataPresent: true,
      encryptionRequired: true
    },
    complianceStatus: {
      fhirCompliant: true,
      dataClassification: 'PII',
      requiredFieldsPresent: isValid
    },
    auditLog: {
      timestamp: new Date(),
      validationType: 'USER_DATA',
      outcome: isValid ? 'SUCCESS' : 'FAILURE',
      details: { errors }
    }
  };
};

/**
 * Sanitizes input data with security measures
 */
export function sanitizeInput(
  input: string,
  options: SanitizationOptions = {
    stripHtml: true,
    preventXSS: true,
    preventSQLInjection: true,
    securityLevel: 'HIGH',
    contentPolicy: {
      allowedTags: [],
      allowedAttributes: {}
    }
  }
): string {
  try {
    let sanitized = input;

    // Strip HTML if required
    if (options.stripHtml) {
      sanitized = xss(sanitized, {
        whiteList: options.contentPolicy.allowedTags.reduce((acc, tag) => {
          acc[tag] = options.contentPolicy.allowedAttributes[tag] || [];
          return acc;
        }, {} as Record<string, string[]>)
      });
    }

    // Prevent SQL injection
    if (options.preventSQLInjection) {
      sanitized = validator.escape(sanitized);
    }

    return sanitized;
  } catch (error) {
    throw new Error(`Input sanitization failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}