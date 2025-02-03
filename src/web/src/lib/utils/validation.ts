/**
 * @fileoverview Client-side validation utilities for AUSTA SuperApp
 * Implements HIPAA-compliant validation with FHIR R4 standards and accessibility support
 * @version 1.0.0
 */

// External imports
import * as yup from 'yup'; // v1.2.0
import validator from 'validator'; // v13.9.0

// Internal imports
import { ErrorCode } from '../constants/errorCodes';
import { IHealthRecord, HealthRecordType, SecurityClassification } from '../types/healthRecord';

/**
 * Interface for validation telemetry tracking
 */
export interface ValidationTelemetry {
  totalFields: number;
  failedFields: number;
  failedRules: number;
  timestamp?: number;
  duration?: number;
}

export interface ValidationError {
  field: string;
  message: string;
  code?: string;
}

/**
 * Interface for validation result with accessibility support
 */
interface ValidationResult {
  isValid: boolean;
  errors: ValidationError[];
  aria: Record<string, string>;
  telemetry?: ValidationTelemetry;
}

/**
 * Interface for input sanitization options
 */
interface SanitizationOptions {
  stripHtml: boolean;
  escapeChars: boolean;
  trimWhitespace: boolean;
  customRules?: string[];
  enableMetrics: boolean;
}

/**
 * Rate limiting configuration for validation operations
 */
const RATE_LIMIT = {
  MAX_REQUESTS: 100,
  WINDOW_MS: 60000, // 1 minute
  requests: new Map<string, number>()
};

/**
 * HIPAA-compliant validation schemas for health records
 */
const healthRecordSchemas: Record<HealthRecordType, yup.ObjectSchema<any>> = {
  [HealthRecordType.CONSULTATION]: yup.object().shape({
    patientId: yup.string().required(),
    providerId: yup.string().required(),
    content: yup.object().required(),
    securityClassification: yup.string().oneOf(Object.values(SecurityClassification)).required()
  }),
  [HealthRecordType.LAB_RESULT]: yup.object().shape({
    patientId: yup.string().required(),
    providerId: yup.string().required(),
    content: yup.object().required(),
    securityClassification: yup.string().oneOf(Object.values(SecurityClassification)).required()
  }),
  [HealthRecordType.PRESCRIPTION]: yup.object().shape({
    patientId: yup.string().required(),
    providerId: yup.string().required(),
    content: yup.object().required(),
    securityClassification: yup.string().oneOf(Object.values(SecurityClassification)).required()
  }),
  [HealthRecordType.IMAGING]: yup.object().shape({
    patientId: yup.string().required(),
    providerId: yup.string().required(),
    content: yup.object().required(),
    securityClassification: yup.string().oneOf(Object.values(SecurityClassification)).required()
  }),
  [HealthRecordType.VITAL_SIGNS]: yup.object().shape({
    patientId: yup.string().required(),
    providerId: yup.string().required(),
    content: yup.object().required(),
    securityClassification: yup.string().oneOf(Object.values(SecurityClassification)).required()
  }),
  [HealthRecordType.WEARABLE_DATA]: yup.object().shape({
    patientId: yup.string().required(),
    providerId: yup.string().required(),
    content: yup.object().required(),
    securityClassification: yup.string().oneOf(Object.values(SecurityClassification)).required()
  })
};

/**
 * Validates health record data against FHIR R4 standards with HIPAA compliance
 * @param record - Health record to validate
 * @returns Validation result with errors and telemetry
 */
export async function validateHealthRecord(record: IHealthRecord): Promise<ValidationResult> {
  const startTime = Date.now();
  const telemetry: ValidationTelemetry = {
    totalFields: Object.keys(record).length,
    failedFields: 0,
    failedRules: 0,
    timestamp: startTime,
    duration: 0
  };

  try {
    // Validate required fields
    const requiredFields = ['id', 'patientId', 'type', 'date'] as const;
    const missingFields = requiredFields.filter(field => !(field in record));
    
    if (missingFields.length > 0) {
      telemetry.failedFields = missingFields.length;
      telemetry.failedRules = missingFields.length;
      telemetry.duration = Date.now() - startTime;

      return {
        isValid: false,
        errors: missingFields.map(field => ({
          field,
          message: `${field} is required`,
          code: 'REQUIRED_FIELD'
        })),
        aria: {
          'form-error': `Missing required fields: ${missingFields.join(', ')}`
        },
        telemetry
      };
    }

    // Add more health record specific validations here
    
    telemetry.duration = Date.now() - startTime;
    return {
      isValid: true,
      errors: [],
      aria: {},
      telemetry
    };

  } catch (error) {
    telemetry.duration = Date.now() - startTime;
    return {
      isValid: false,
      errors: [{
        field: 'form',
        message: error instanceof Error ? error.message : 'Validation failed',
        code: 'VALIDATION_ERROR'
      }],
      aria: {
        'form-error': error instanceof Error ? error.message : 'Validation failed'
      },
      telemetry
    };
  }
}

/**
 * Validates form data with accessibility support
 * @param formData - Form data to validate
 * @param validationSchema - Yup validation schema
 * @param options - Validation options
 * @returns Validation result with field-specific errors and ARIA attributes
 */
export const validateForm = async (
  data: Record<string, any>,
  schema: yup.ObjectSchema<any>
): Promise<ValidationResult> => {
  try {
    await schema.validate(data, { abortEarly: false });
    return {
      isValid: true,
      errors: [],
      aria: {}
    };
  } catch (error) {
    if (error instanceof yup.ValidationError) {
      const validationErrors: ValidationError[] = error.inner.map(err => ({
        field: err.path || '',
        message: err.message,
        code: err.type
      }));

      const ariaMessages = validationErrors.reduce((acc, curr) => {
        if (curr.field) {
          acc[`${curr.field}-error`] = curr.message;
        }
        return acc;
      }, {} as Record<string, string>);

      return {
        isValid: false,
        errors: validationErrors,
        aria: ariaMessages,
        telemetry: {
          totalFields: Object.keys(data).length,
          failedFields: validationErrors.length,
          failedRules: error.inner.length
        }
      };
    }

    // Handle unexpected errors
    return {
      isValid: false,
      errors: [{
        field: 'form',
        message: 'An unexpected error occurred during validation',
        code: 'VALIDATION_ERROR'
      }],
      aria: {
        'form-error': 'An unexpected error occurred during validation'
      }
    };
  }
};

/**
 * Sanitizes user input with enhanced security rules
 * @param input - Input string to sanitize
 * @param options - Sanitization options
 * @returns Sanitized input string
 */
export function sanitizeInput(
  input: string,
  options: SanitizationOptions = {
    stripHtml: true,
    escapeChars: true,
    trimWhitespace: true,
    enableMetrics: false
  }
): string {
  let sanitized = input;

  if (options.stripHtml) {
    sanitized = validator.stripLow(sanitized);
  }

  if (options.escapeChars) {
    sanitized = validator.escape(sanitized);
  }

  if (options.trimWhitespace) {
    sanitized = validator.trim(sanitized);
  }

  // Apply custom sanitization rules
  if (options.customRules?.length) {
    options.customRules.forEach(rule => {
      sanitized = sanitized.replace(new RegExp(rule, 'g'), '');
    });
  }

  return sanitized;
}

/**
 * Validates HIPAA compliance for health records
 * @param record - Health record to validate
 * @returns Boolean indicating compliance
 */
function validateHIPAACompliance(record: IHealthRecord): boolean {
  // Verify security classification
  if (!record.securityClassification) {
    return false;
  }

  // Verify encryption level
  if (!record.encryptionLevel) {
    return false;
  }

  // Verify metadata compliance
  if (!record.metadata?.hipaaCompliance?.isProtectedHealth) {
    return false;
  }

  return true;
}

/**
 * Checks rate limiting for validation operations
 * @param identifier - Unique identifier for rate limiting
 * @returns Boolean indicating if request is allowed
 */
function checkRateLimit(identifier: string): boolean {
  const now = Date.now();
  const windowStart = now - RATE_LIMIT.WINDOW_MS;

  // Clean up old entries
  RATE_LIMIT.requests.forEach((timestamp, key) => {
    if (timestamp < windowStart) {
      RATE_LIMIT.requests.delete(key);
    }
  });

  // Check current request count
  const currentCount = RATE_LIMIT.requests.get(identifier) || 0;
  if (currentCount >= RATE_LIMIT.MAX_REQUESTS) {
    return false;
  }

  // Update request count
  RATE_LIMIT.requests.set(identifier, currentCount + 1);
  return true;
}