/**
 * @fileoverview Centralized API endpoint configuration for AUSTA SuperApp web application
 * Provides endpoint constants with versioned URIs and standardized path construction
 */

// Global constants for API configuration
const API_VERSION = 'v1';
const BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'https://api.austa.health';

/**
 * Constructs a complete API URL with proper versioning and path segments
 * @param {string} path - The API endpoint path to append
 * @returns {string} Fully constructed API endpoint URL
 */
const buildUrl = (path) => {
  // Remove leading/trailing slashes and sanitize path
  const sanitizedPath = path.replace(/^\/+|\/+$/g, '');
  return `${BASE_URL}/${API_VERSION}/${sanitizedPath}`;
};

/**
 * Authentication service endpoint constants
 * Provides comprehensive authentication flow endpoints
 */
const AuthEndpoints = {
  LOGIN: '/auth/login',
  REGISTER: '/auth/register',
  REFRESH_TOKEN: '/auth/refresh',
  VERIFY_TOKEN: '/auth/verify',
  VERIFY_BIOMETRIC: '/auth/verify-biometric',
  LOGOUT: '/auth/logout',
  RESET_PASSWORD: '/auth/reset-password',
  VERIFY_EMAIL: '/auth/verify-email'
};

/**
 * Health Records service endpoint constants
 * Supports FHIR-compliant health record management and sharing
 */
const HealthRecordEndpoints = {
  GET_RECORDS: '/health-records',
  GET_RECORD: '/health-records/:id',
  CREATE_RECORD: '/health-records',
  UPDATE_RECORD: '/health-records/:id',
  DELETE_RECORD: '/health-records/:id',
  UPLOAD_ATTACHMENT: '/health-records/:id/attachments',
  EXPORT_FHIR: '/health-records/:id/fhir',
  SHARE_RECORD: '/health-records/:id/share',
  REVOKE_ACCESS: '/health-records/:id/access/:userId'
};

/**
 * Virtual Care service endpoint constants
 * Manages telemedicine session endpoints and real-time features
 */
const VirtualCareEndpoints = {
  CREATE_SESSION: '/virtual-care/sessions',
  JOIN_SESSION: '/virtual-care/sessions/:id/join',
  END_SESSION: '/virtual-care/sessions/:id/end',
  GET_SESSION_TOKEN: '/virtual-care/sessions/:id/token',
  UPDATE_SESSION_STATUS: '/virtual-care/sessions/:id/status',
  SHARE_SCREEN: '/virtual-care/sessions/:id/screen-share',
  SEND_CHAT_MESSAGE: '/virtual-care/sessions/:id/chat'
};

/**
 * Insurance Claims service endpoint constants
 * Handles claim submission and document management
 */
const ClaimsEndpoints = {
  SUBMIT_CLAIM: '/claims',
  GET_CLAIMS: '/claims',
  GET_CLAIM: '/claims/:id',
  UPDATE_CLAIM: '/claims/:id',
  UPLOAD_DOCUMENTS: '/claims/:id/documents',
  CHECK_STATUS: '/claims/:id/status',
  CANCEL_CLAIM: '/claims/:id/cancel'
};

/**
 * Marketplace service endpoint constants
 * Manages digital health product catalog and recommendations
 */
const MarketplaceEndpoints = {
  GET_PRODUCTS: '/marketplace/products',
  GET_PRODUCT: '/marketplace/products/:id',
  PURCHASE_PRODUCT: '/marketplace/products/:id/purchase',
  GET_CATEGORIES: '/marketplace/categories',
  SEARCH_PRODUCTS: '/marketplace/products/search',
  GET_RECOMMENDATIONS: '/marketplace/recommendations'
};

/**
 * Replaces URL parameters in endpoint paths with actual values
 * @param {string} endpoint - The endpoint template with parameters
 * @param {Object} params - Object containing parameter values
 * @returns {string} Processed endpoint URL with replaced parameters
 */
const processEndpointParams = (endpoint, params) => {
  let processedEndpoint = endpoint;
  if (params) {
    Object.entries(params).forEach(([key, value]) => {
      processedEndpoint = processedEndpoint.replace(`:${key}`, value);
    });
  }
  return processedEndpoint;
};

module.exports = {
  API_VERSION,
  BASE_URL,
  buildUrl,
  AuthEndpoints,
  HealthRecordEndpoints,
  VirtualCareEndpoints,
  ClaimsEndpoints,
  MarketplaceEndpoints,
  processEndpointParams
}; 