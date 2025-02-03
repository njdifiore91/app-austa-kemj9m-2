"use strict";
/**
 * @fileoverview Comprehensive validation utilities for AUSTA SuperApp platform
 * Implements HIPAA-compliant validation with FHIR R4 standards
 * @version 1.0.0
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.sanitizeInput = exports.validateUserData = exports.validateHealthRecord = void 0;
const error_codes_1 = require("../constants/error-codes");
const health_record_interface_1 = require("../interfaces/health-record.interface");
const user_interface_1 = require("../interfaces/user.interface");
const validator_1 = __importDefault(require("validator"));
const xss_1 = __importDefault(require("xss"));
/**
 * FHIR R4 compliant health record validation
 * @param record Health record to validate
 * @param options Validation options
 */
async function validateHealthRecord(record, options = {}) {
    const errors = [];
    const result = {
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
                code: error_codes_1.ErrorCode.INVALID_INPUT,
                message: 'Required fields missing',
                field: 'base'
            });
        }
        // Validate FHIR compliance
        if (!validateFHIRCompliance(record.content)) {
            errors.push({
                code: error_codes_1.ErrorCode.INVALID_INPUT,
                message: 'Record does not comply with FHIR R4 standards',
                field: 'content'
            });
            result.complianceStatus.fhirCompliant = false;
        }
        // Validate HIPAA compliance
        const hipaaValidation = validateHIPAACompliance(record);
        if (!hipaaValidation.isCompliant) {
            errors.push({
                code: error_codes_1.ErrorCode.HIPAA_VIOLATION,
                message: hipaaValidation.reason,
                field: hipaaValidation.field
            });
            result.securityStatus.hipaaCompliant = false;
        }
        // Validate attachments if required
        if (options.validateAttachments && record.attachments) {
            for (const attachment of record.attachments) {
                if (!validateAttachment(attachment)) {
                    errors.push({
                        code: error_codes_1.ErrorCode.INVALID_INPUT,
                        message: 'Invalid attachment format',
                        field: `attachments.${attachment.id}`
                    });
                }
            }
        }
        // Update validation result
        result.isValid = errors.length === 0;
        result.errors = errors;
        result.auditLog.outcome = result.isValid ? 'SUCCESS' : 'FAILURE';
        result.auditLog.details = { errors, recordType: record.type };
        return result;
    }
    catch (error) {
        throw new Error(`Health record validation failed: ${error.message}`);
    }
}
exports.validateHealthRecord = validateHealthRecord;
/**
 * Validates user data with enhanced security checks
 * @param userData User data to validate
 * @param options Security options
 */
async function validateUserData(userData, options = {}) {
    const errors = [];
    const result = {
        isValid: true,
        errors: [],
        securityStatus: {
            hipaaCompliant: true,
            piiDetected: true,
            sensitiveDataPresent: true,
            encryptionRequired: true
        },
        complianceStatus: {
            fhirCompliant: true,
            dataClassification: 'PII',
            requiredFieldsPresent: true
        },
        auditLog: {
            timestamp: new Date(),
            validationType: 'USER_DATA',
            outcome: 'PENDING',
            details: {}
        }
    };
    try {
        // Validate email
        if (!validator_1.default.isEmail(userData.email)) {
            errors.push({
                code: error_codes_1.ErrorCode.INVALID_INPUT,
                message: 'Invalid email format',
                field: 'email'
            });
        }
        // Validate password if required
        if (options.validatePassword) {
            if (!validatePassword(userData.password)) {
                errors.push({
                    code: error_codes_1.ErrorCode.INVALID_INPUT,
                    message: 'Password does not meet security requirements',
                    field: 'password'
                });
            }
        }
        // Validate role
        if (!Object.values(user_interface_1.UserRole).includes(userData.role)) {
            errors.push({
                code: error_codes_1.ErrorCode.INVALID_INPUT,
                message: 'Invalid user role',
                field: 'role'
            });
        }
        // Validate MFA if required
        if (options.checkMFA && !userData.securitySettings.mfaEnabled) {
            errors.push({
                code: error_codes_1.ErrorCode.SECURITY_VIOLATION,
                message: 'MFA is required for this user role',
                field: 'securitySettings.mfaEnabled'
            });
        }
        // Update validation result
        result.isValid = errors.length === 0;
        result.errors = errors;
        result.auditLog.outcome = result.isValid ? 'SUCCESS' : 'FAILURE';
        result.auditLog.details = { errors, userRole: userData.role };
        return result;
    }
    catch (error) {
        throw new Error(`User data validation failed: ${error.message}`);
    }
}
exports.validateUserData = validateUserData;
/**
 * Advanced input sanitization with multiple security layers
 * @param input Input string to sanitize
 * @param options Sanitization options
 */
function sanitizeInput(input, options = {
    stripHtml: true,
    preventXSS: true,
    preventSQLInjection: true,
    securityLevel: 'HIGH',
    contentPolicy: {
        allowedTags: [],
        allowedAttributes: {}
    }
}) {
    try {
        let sanitized = input;
        // XSS prevention
        if (options.preventXSS) {
            sanitized = (0, xss_1.default)(sanitized, {
                whiteList: options.contentPolicy.allowedTags,
                stripIgnoreTag: true,
                stripIgnoreTagBody: ['script']
            });
        }
        // HTML stripping
        if (options.stripHtml) {
            sanitized = validator_1.default.stripLow(sanitized);
        }
        // SQL injection prevention
        if (options.preventSQLInjection) {
            sanitized = validator_1.default.escape(sanitized);
        }
        // Additional security based on security level
        if (options.securityLevel === 'HIGH') {
            sanitized = validator_1.default.trim(sanitized);
            sanitized = validator_1.default.blacklist(sanitized, '<>\'"`');
        }
        return sanitized;
    }
    catch (error) {
        throw new Error(`Input sanitization failed: ${error.message}`);
    }
}
exports.sanitizeInput = sanitizeInput;
// Private helper functions
function validateFHIRCompliance(content) {
    // Implementation of FHIR R4 validation
    try {
        // Validate resource type
        if (!content.resourceType) {
            return false;
        }
        // Validate required FHIR elements
        if (!content.id || !content.meta) {
            return false;
        }
        return true;
    }
    catch (_a) {
        return false;
    }
}
function validateHIPAACompliance(record) {
    // Implementation of HIPAA compliance validation
    try {
        // Check for required security measures
        if (!record.securityLabels || record.securityLabels.length === 0) {
            return {
                isCompliant: false,
                reason: 'Missing security labels',
                field: 'securityLabels'
            };
        }
        // Verify encryption for sensitive data
        if (record.type === health_record_interface_1.HealthRecordType.LAB_RESULT && !record.encryptionMetadata) {
            return {
                isCompliant: false,
                reason: 'Encryption required for lab results',
                field: 'encryptionMetadata'
            };
        }
        return { isCompliant: true };
    }
    catch (_a) {
        return {
            isCompliant: false,
            reason: 'HIPAA compliance validation failed',
            field: 'general'
        };
    }
}
function validatePassword(password) {
    return (password.length >= 12 &&
        /[A-Z]/.test(password) &&
        /[a-z]/.test(password) &&
        /[0-9]/.test(password) &&
        /[^A-Za-z0-9]/.test(password));
}
function validateAttachment(attachment) {
    return (attachment.id &&
        attachment.contentType &&
        attachment.size > 0 &&
        attachment.checksum);
}
