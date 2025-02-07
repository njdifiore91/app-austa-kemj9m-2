/**
 * @fileoverview Common TypeScript types used across AUSTA services
 */

import { ErrorCode, ErrorCategory, ErrorSeverity } from '../constants/error-codes';
import { HttpStatusCode } from '../constants/http-status';

/**
 * Generic API Response type
 */
export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: {
    code: ErrorCode;
    message: string;
    category?: ErrorCategory;
    severity?: ErrorSeverity;
    details?: any;
  };
  meta?: {
    timestamp: string;
    requestId: string;
    statusCode: HttpStatusCode;
  };
}

/**
 * Pagination parameters
 */
export interface PaginationParams {
  page: number;
  limit: number;
  sort?: string;
  order?: 'asc' | 'desc';
}

/**
 * Paginated response
 */
export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  limit: number;
  totalPages: number;
  hasNext: boolean;
  hasPrev: boolean;
}

/**
 * Audit log entry
 */
export interface AuditLogEntry {
  timestamp: Date;
  userId: string;
  action: string;
  resource: string;
  details: any;
  ipAddress: string;
  userAgent: string;
  status: 'success' | 'failure';
}

/**
 * Security context for requests
 */
export interface SecurityContext {
  requestId: string;
  userId?: string;
  sessionId?: string;
  ipAddress: string;
  userAgent: string;
  timestamp: Date;
}

/**
 * Health check response
 */
export interface HealthCheckResponse {
  status: 'healthy' | 'unhealthy';
  timestamp: string;
  version: string;
  services: {
    [key: string]: {
      status: 'up' | 'down';
      latency: number;
      lastChecked: string;
    };
  };
} 