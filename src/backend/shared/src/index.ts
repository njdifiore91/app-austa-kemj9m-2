/**
 * @fileoverview Main entry point for AUSTA shared module
 * Exports all shared utilities, interfaces, types, and configurations
 * @version 1.0.0
 */

// Constants
export * from './constants/error-codes';
export * from './constants/http-status';

// Interfaces
export * from './interfaces/user.interface';
export * from './interfaces/health-record.interface';

// Types
export * from './types';

// Middleware
export * from './middleware/logger';
export * from './middleware/error-handler';

// Utils
export * from './utils/validation.utils';
export * from './utils/encryption.utils';

// Config
export * from './config'; 