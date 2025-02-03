"use strict";
/**
 * @fileoverview User management interfaces for AUSTA SuperApp platform
 * @version 1.0.0
 * @license HIPAA-compliant
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.UserStatus = exports.UserRole = void 0;
/**
 * Enum defining comprehensive user roles for granular access control
 * Based on RBAC matrix specifications
 */
var UserRole;
(function (UserRole) {
    UserRole["PATIENT"] = "PATIENT";
    UserRole["PROVIDER"] = "PROVIDER";
    UserRole["ADMIN"] = "ADMIN";
    UserRole["INSURANCE"] = "INSURANCE";
    UserRole["SYSTEM"] = "SYSTEM";
})(UserRole = exports.UserRole || (exports.UserRole = {}));
/**
 * Enum defining all possible user account statuses with security states
 */
var UserStatus;
(function (UserStatus) {
    UserStatus["ACTIVE"] = "ACTIVE";
    UserStatus["INACTIVE"] = "INACTIVE";
    UserStatus["PENDING"] = "PENDING";
    UserStatus["SUSPENDED"] = "SUSPENDED";
    UserStatus["LOCKED"] = "LOCKED";
    UserStatus["DELETED"] = "DELETED";
})(UserStatus = exports.UserStatus || (exports.UserStatus = {}));
