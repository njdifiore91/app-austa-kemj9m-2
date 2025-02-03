"use strict";
/**
 * @fileoverview FHIR R4 compliant health record interfaces with enhanced security
 * Implements comprehensive data structures for medical records management
 * @version 1.0.0
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.EncryptionStatus = exports.HealthRecordStatus = exports.HealthRecordType = void 0;
/**
 * Comprehensive types of health records supported by the system
 */
var HealthRecordType;
(function (HealthRecordType) {
    HealthRecordType["CONSULTATION"] = "CONSULTATION";
    HealthRecordType["LAB_RESULT"] = "LAB_RESULT";
    HealthRecordType["PRESCRIPTION"] = "PRESCRIPTION";
    HealthRecordType["IMAGING"] = "IMAGING";
    HealthRecordType["VITAL_SIGNS"] = "VITAL_SIGNS";
    HealthRecordType["WEARABLE_DATA"] = "WEARABLE_DATA";
})(HealthRecordType = exports.HealthRecordType || (exports.HealthRecordType = {}));
/**
 * Status indicators for health records with encryption state
 */
var HealthRecordStatus;
(function (HealthRecordStatus) {
    HealthRecordStatus["DRAFT"] = "DRAFT";
    HealthRecordStatus["FINAL"] = "FINAL";
    HealthRecordStatus["AMENDED"] = "AMENDED";
    HealthRecordStatus["DELETED"] = "DELETED";
    HealthRecordStatus["ENCRYPTED"] = "ENCRYPTED";
})(HealthRecordStatus = exports.HealthRecordStatus || (exports.HealthRecordStatus = {}));
/**
 * Encryption status for attachments and content
 */
var EncryptionStatus;
(function (EncryptionStatus) {
    EncryptionStatus["UNENCRYPTED"] = "UNENCRYPTED";
    EncryptionStatus["ENCRYPTED"] = "ENCRYPTED";
    EncryptionStatus["PENDING"] = "PENDING";
    EncryptionStatus["FAILED"] = "FAILED";
})(EncryptionStatus = exports.EncryptionStatus || (exports.EncryptionStatus = {}));
