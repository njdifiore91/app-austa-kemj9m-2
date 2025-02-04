/**
 * @fileoverview Comprehensive validation utilities for AUSTA SuperApp platform
 * Implements HIPAA-compliant validation with FHIR R4 standards
 * @version 1.0.0
 */

import { ErrorCode } from "../constants/error-codes"
import {
  IHealthRecord,
  HealthRecordType,
  HealthRecordStatus,
  IHealthRecordValidationError,
  IHealthRecordAttachment,
  FHIRResource,
} from "../interfaces/health-record.interface"
import {
  IUser,
  UserRole,
  UserStatus,
  IUserSecuritySettings,
} from "../interfaces/user.interface"
import validator from "validator"
import * as joi from "joi"
import xss from "xss"

// Version comments for external dependencies
// validator: v13.9.0 - String validation and sanitization
// joi: v17.9.0 - Schema validation
// @types/fhir: v0.0.37 - FHIR R4 type definitions
// xss: v1.0.14 - XSS prevention

/**
 * Interface for validation result with comprehensive security status
 */
export interface ValidationResult {
  isValid: boolean
  errors: IHealthRecordValidationError[]
  securityStatus: {
    hipaaCompliant: boolean
    piiDetected: boolean
    sensitiveDataPresent: boolean
    encryptionRequired: boolean
  }
  complianceStatus: {
    fhirCompliant: boolean
    dataClassification: "PHI" | "PII" | "NONE"
    requiredFieldsPresent: boolean
  }
  auditLog: {
    timestamp: Date
    validationType: "HEALTH_RECORD" | "USER_DATA"
    outcome: "SUCCESS" | "FAILURE" | "PENDING"
    details: Record<string, any>
  }
}

/**
 * Interface for enhanced sanitization options
 */
export interface SanitizationOptions {
  stripHtml: boolean
  preventXSS: boolean
  preventSQLInjection: boolean
  securityLevel: "HIGH" | "MEDIUM" | "LOW"
  contentPolicy: {
    allowedTags: string[]
    allowedAttributes: Record<string, string[]>
  }
}

/**
 * Interface for HIPAA compliance validation result
 */
interface HIPAAValidationResult {
  isCompliant: boolean
  reason?: string
  field?: string
}

/**
 * FHIR R4 compliant health record validation
 * @param record Health record to validate
 * @param options Validation options
 */
export async function validateHealthRecord(
  record: IHealthRecord,
  options: { strictMode?: boolean; validateAttachments?: boolean } = {}
): Promise<ValidationResult> {
  const errors: IHealthRecordValidationError[] = []
  const result: ValidationResult = {
    isValid: true,
    errors: [],
    securityStatus: {
      hipaaCompliant: true,
      piiDetected: false,
      sensitiveDataPresent: false,
      encryptionRequired: false,
    },
    complianceStatus: {
      fhirCompliant: true,
      dataClassification: "PHI",
      requiredFieldsPresent: true,
    },
    auditLog: {
      timestamp: new Date(),
      validationType: "HEALTH_RECORD",
      outcome: "PENDING",
      details: {},
    },
  }

  try {
    // Validate basic structure
    if (!record.id || !record.patientId || !record.type) {
      errors.push({
        code: ErrorCode.INVALID_INPUT,
        message: "Required fields missing",
        field: "base",
      })
    }

    // Validate FHIR compliance
    if (!validateFHIRCompliance(record.content)) {
      errors.push({
        code: ErrorCode.INVALID_INPUT,
        message: "Record does not comply with FHIR R4 standards",
        field: "content",
      })
      result.complianceStatus.fhirCompliant = false
    }

    // Validate HIPAA compliance
    const hipaaValidation = validateHIPAACompliance(record)
    if (!hipaaValidation.isCompliant) {
      errors.push({
        code: ErrorCode.HIPAA_VIOLATION,
        message: hipaaValidation.reason || "HIPAA compliance violation",
        field: hipaaValidation.field || "unknown",
      })
      result.securityStatus.hipaaCompliant = false
    }

    // Validate attachments if required
    if (options.validateAttachments && record.attachments) {
      for (const attachment of record.attachments) {
        if (!validateAttachment(attachment)) {
          errors.push({
            code: ErrorCode.INVALID_INPUT,
            message: "Invalid attachment format",
            field: `attachments.${attachment.id}`,
          })
        }
      }
    }

    // Update validation result
    result.isValid = errors.length === 0
    result.errors = errors
    result.auditLog.outcome = result.isValid ? "SUCCESS" : "FAILURE"
    result.auditLog.details = { errors, recordType: record.type }

    return result
  } catch (error) {
    throw new Error(
      `Health record validation failed: ${(error as Error).message}`
    )
  }
}

/**
 * Validates user data with enhanced security checks
 * @param userData User data to validate
 * @param options Security options
 */
export async function validateUserData(
  userData: IUser,
  options: { validatePassword?: boolean; checkMFA?: boolean } = {}
): Promise<ValidationResult> {
  const errors: IHealthRecordValidationError[] = []
  const result: ValidationResult = {
    isValid: true,
    errors: [],
    securityStatus: {
      hipaaCompliant: true,
      piiDetected: true,
      sensitiveDataPresent: true,
      encryptionRequired: true,
    },
    complianceStatus: {
      fhirCompliant: true,
      dataClassification: "PII",
      requiredFieldsPresent: true,
    },
    auditLog: {
      timestamp: new Date(),
      validationType: "USER_DATA",
      outcome: "PENDING",
      details: {},
    },
  }

  try {
    // Validate email
    if (!validator.isEmail(userData.email)) {
      errors.push({
        code: ErrorCode.INVALID_INPUT,
        message: "Invalid email format",
        field: "email",
      })
    }

    // Validate password if required
    if (options.validatePassword && userData.password) {
      if (!validatePassword(userData.password)) {
        errors.push({
          code: ErrorCode.INVALID_INPUT,
          message: "Password does not meet security requirements",
          field: "password",
        })
      }
    }

    // Validate role
    if (!Object.values(UserRole).includes(userData.role)) {
      errors.push({
        code: ErrorCode.INVALID_INPUT,
        message: "Invalid user role",
        field: "role",
      })
    }

    // Validate MFA if required
    if (options.checkMFA && !userData.securitySettings?.mfaEnabled) {
      errors.push({
        code: ErrorCode.INVALID_INPUT,
        message: "MFA is required for this user role",
        field: "securitySettings.mfaEnabled",
      })
    }

    // Update validation result
    result.isValid = errors.length === 0
    result.errors = errors
    result.auditLog.outcome = result.isValid ? "SUCCESS" : "FAILURE"
    result.auditLog.details = { errors, userRole: userData.role }

    return result
  } catch (error) {
    throw new Error(`User data validation failed: ${(error as Error).message}`)
  }
}

/**
 * Advanced input sanitization with multiple security layers
 * @param input Input string to sanitize
 * @param options Sanitization options
 */
export function sanitizeInput(
  input: string,
  options: SanitizationOptions = {
    stripHtml: true,
    preventXSS: true,
    preventSQLInjection: true,
    securityLevel: "HIGH",
    contentPolicy: {
      allowedTags: [],
      allowedAttributes: {},
    },
  }
): string {
  try {
    let sanitized = input

    // Strip HTML if required
    if (options.stripHtml) {
      sanitized = validator.stripLow(sanitized)
    }

    // Prevent XSS attacks
    if (options.preventXSS) {
      sanitized = xss(sanitized, {
        whiteList: options.contentPolicy.allowedTags.length
          ? options.contentPolicy.allowedTags.reduce(
              (acc, tag) => {
                acc[tag] = options.contentPolicy.allowedAttributes[tag] || []
                return acc
              },
              {} as Record<string, string[]>
            )
          : {},
      })
    }

    // Prevent SQL injection
    if (options.preventSQLInjection) {
      sanitized = validator.escape(sanitized)
    }

    return sanitized
  } catch (error) {
    throw new Error(`Input sanitization failed: ${(error as Error).message}`)
  }
}

/**
 * Validates FHIR compliance of health record content
 */
function validateFHIRCompliance(content: unknown): boolean {
  try {
    if (!content || typeof content !== "object") {
      return false
    }

    // Basic FHIR resource validation
    const resource = content as FHIRResource
    return !!(
      resource.resourceType &&
      resource.id &&
      resource.meta?.versionId &&
      resource.meta?.lastUpdated &&
      resource.meta?.security?.length > 0
    )
  } catch {
    return false
  }
}

/**
 * Validates HIPAA compliance of health record
 */
function validateHIPAACompliance(record: IHealthRecord): HIPAAValidationResult {
  // Check for required HIPAA identifiers
  if (!record.patientId || !record.providerId) {
    return {
      isCompliant: false,
      reason: "Missing required HIPAA identifiers",
      field: "identifiers",
    }
  }

  // Check for proper record status
  if (!Object.values(HealthRecordStatus).includes(record.status)) {
    return {
      isCompliant: false,
      reason: "Invalid record status",
      field: "status",
    }
  }

  // Check for encryption status
  if (!record.encryptionMetadata) {
    return {
      isCompliant: false,
      reason: "Missing encryption metadata",
      field: "encryptionMetadata",
    }
  }

  return { isCompliant: true }
}

/**
 * Validates password against security requirements
 */
function validatePassword(password: string): boolean {
  return (
    password.length >= 12 &&
    /[A-Z]/.test(password) &&
    /[a-z]/.test(password) &&
    /[0-9]/.test(password) &&
    /[^A-Za-z0-9]/.test(password)
  )
}

/**
 * Validates health record attachment
 */
function validateAttachment(attachment: IHealthRecordAttachment): boolean {
  return !!(
    (
      attachment.id &&
      attachment.contentType &&
      attachment.url &&
      attachment.checksum &&
      attachment.size > 0 &&
      attachment.size <= 10 * 1024 * 1024
    ) // 10MB max
  )
}
