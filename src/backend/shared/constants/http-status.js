"use strict";
/**
 * @fileoverview HTTP Status Code Constants and Utilities
 * Implements RFC 7231 compliant status codes with TypeScript enums for type safety
 * and provides utility functions for status code range validation.
 *
 * @version 1.0.0
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.isServerErrorStatus = exports.isClientErrorStatus = exports.HttpStatus = void 0;
/**
 * Enum containing standard HTTP status codes following RFC 7231 specification.
 * Used across AUSTA SuperApp microservices for consistent API responses.
 */
var HttpStatus;
(function (HttpStatus) {
    // 2xx Success
    HttpStatus[HttpStatus["OK"] = 200] = "OK";
    HttpStatus[HttpStatus["CREATED"] = 201] = "CREATED";
    HttpStatus[HttpStatus["ACCEPTED"] = 202] = "ACCEPTED";
    HttpStatus[HttpStatus["NO_CONTENT"] = 204] = "NO_CONTENT";
    // 4xx Client Errors
    HttpStatus[HttpStatus["BAD_REQUEST"] = 400] = "BAD_REQUEST";
    HttpStatus[HttpStatus["UNAUTHORIZED"] = 401] = "UNAUTHORIZED";
    HttpStatus[HttpStatus["FORBIDDEN"] = 403] = "FORBIDDEN";
    HttpStatus[HttpStatus["NOT_FOUND"] = 404] = "NOT_FOUND";
    HttpStatus[HttpStatus["METHOD_NOT_ALLOWED"] = 405] = "METHOD_NOT_ALLOWED";
    HttpStatus[HttpStatus["CONFLICT"] = 409] = "CONFLICT";
    HttpStatus[HttpStatus["UNPROCESSABLE_ENTITY"] = 422] = "UNPROCESSABLE_ENTITY";
    // 5xx Server Errors
    HttpStatus[HttpStatus["INTERNAL_SERVER_ERROR"] = 500] = "INTERNAL_SERVER_ERROR";
    HttpStatus[HttpStatus["SERVICE_UNAVAILABLE"] = 503] = "SERVICE_UNAVAILABLE";
    HttpStatus[HttpStatus["GATEWAY_TIMEOUT"] = 504] = "GATEWAY_TIMEOUT"; // Gateway timeout while waiting for response
})(HttpStatus = exports.HttpStatus || (exports.HttpStatus = {}));
/**
 * Checks if the provided HTTP status code is in the client error range (400-499).
 * Used for error handling and logging categorization.
 *
 * @param {number} status - The HTTP status code to check
 * @returns {boolean} True if status is a client error code (400-499), false otherwise
 */
function isClientErrorStatus(status) {
    return status >= HttpStatus.BAD_REQUEST && status < HttpStatus.INTERNAL_SERVER_ERROR;
}
exports.isClientErrorStatus = isClientErrorStatus;
/**
 * Checks if the provided HTTP status code is in the server error range (500-599).
 * Used for error handling and logging categorization.
 *
 * @param {number} status - The HTTP status code to check
 * @returns {boolean} True if status is a server error code (500-599), false otherwise
 */
function isServerErrorStatus(status) {
    return status >= HttpStatus.INTERNAL_SERVER_ERROR && status < 600;
}
exports.isServerErrorStatus = isServerErrorStatus;
