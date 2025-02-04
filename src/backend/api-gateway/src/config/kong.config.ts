/**
 * @fileoverview Kong API Gateway Configuration
 * Implements enterprise-grade API management with healthcare-specific security controls
 * and HIPAA compliance measures for the AUSTA SuperApp platform.
 *
 * @version 1.0.0
 */

import { config } from "dotenv" // v16.3.1
import { HttpStatus } from "../../../shared/constants/http-status"

// Load environment variables
config()

// Global configuration constants
export const API_VERSION = process.env.API_VERSION || "v1"
export const KONG_ADMIN_URL = process.env.KONG_ADMIN_URL
export const KONG_PROXY_URL = process.env.KONG_PROXY_URL
export const ENVIRONMENT = process.env.NODE_ENV || "development"

// Kong configuration interface
export interface KongConfig {
  services: {
    [key: string]: {
      name: string
      url: string
      protocol: string
      connect_timeout: number
      write_timeout: number
      read_timeout: number
      retries: number
      health_checks: {
        active: {
          healthy: { interval: number; successes: number }
          unhealthy: {
            interval: number
            timeouts: number
            http_failures: number
          }
        }
      }
    }
  }
  routes: {
    [key: string]: {
      paths: string[]
      methods: string[]
      strip_path: boolean
      preserve_host: boolean
      protocols: string[]
      regex_priority: number
      https_redirect_status_code: number
    }
  }
  plugins: {
    cors: {
      name: string
      config: {
        origins: string[]
        methods: string[]
        headers: string[]
        exposed_headers: string[]
        credentials: boolean
        max_age: number
      }
    }
    oauth2: {
      name: string
      config: {
        scopes: string[]
        mandatory_scope: boolean
        token_expiration: number
        enable_authorization_code: boolean
        enable_client_credentials: boolean
        enable_password_grant: boolean
        accept_http_if_already_terminated: boolean
        global_credentials: boolean
        refresh_token_ttl: number
        provision_key: string
        auth_header_name: string
        hide_credentials: boolean
      }
    }
    rate_limiting: {
      name: string
      config: {
        minute: {
          patient: number
          provider: number
          admin: number
        }
        hour: {
          patient: number
          provider: number
          admin: number
        }
        policy: string
        fault_tolerant: boolean
        hide_client_headers: boolean
        redis_host: string
        redis_port: number
        redis_timeout: number
        redis_password: string
        redis_database: number
        redis_cluster_addresses: string[]
      }
    }
    [key: string]: {
      name: string
      config: any
    }
  }
  certificates?: {
    default: {
      cert: string
      key: string
      snis: string[]
    }
  }
}

/**
 * Validates Kong configuration for healthcare compliance and security requirements
 * @param config - Kong configuration object
 * @returns boolean indicating validation success
 */
export function validateConfig(config: KongConfig): boolean {
  try {
    // In development mode, don't require Kong URLs
    if (ENVIRONMENT === "development") {
      console.log("Running in development mode - Kong URL validation skipped")
      // Just validate the configuration structure
      if (!config.services || !config.routes || !config.plugins) {
        throw new Error("Missing required configuration sections")
      }
    } else {
      // In production, require Kong URLs
      if (!KONG_ADMIN_URL || !KONG_PROXY_URL) {
        throw new Error("Missing required Kong URLs")
      }

      // Validate required service configurations
      if (!config.services || !config.routes || !config.plugins) {
        throw new Error("Missing required configuration sections")
      }

      // Validate security plugin configurations
      if (!config.plugins.oauth2 || !config.plugins.rate_limiting) {
        throw new Error("Missing required security plugins")
      }

      // Validate HIPAA-required SSL settings
      if (
        !Object.values(config.routes).every((route) =>
          route.protocols.includes("https")
        )
      ) {
        throw new Error("HIPAA requires HTTPS for all production routes")
      }
    }

    return true
  } catch (error) {
    console.error("Configuration validation failed:", error)
    return false
  }
}

/**
 * Kong Gateway configuration with healthcare-specific settings
 */
export const kongConfig = {
  services: {
    // Authentication Service
    auth: {
      name: "auth-service",
      url: "http://auth-service:3000",
      protocol: "http",
      connect_timeout: 60000,
      write_timeout: 60000,
      read_timeout: 60000,
      retries: 5,
      health_checks: {
        active: {
          healthy: { interval: 5, successes: 2 },
          unhealthy: { interval: 5, timeouts: 3, http_failures: 2 },
        },
      },
    },

    // Virtual Care Service
    "virtual-care": {
      name: "virtual-care-service",
      url: "http://virtual-care-service:3000",
      protocol: "http",
      connect_timeout: 120000,
      write_timeout: 120000,
      read_timeout: 120000,
      retries: 3,
      health_checks: {
        active: {
          healthy: { interval: 5, successes: 2 },
          unhealthy: { interval: 5, timeouts: 3, http_failures: 2 },
        },
      },
    },

    // Health Records Service
    "health-records": {
      name: "health-records-service",
      url: "http://health-records-service:3000",
      protocol: "http",
      connect_timeout: 90000,
      write_timeout: 90000,
      read_timeout: 90000,
      retries: 3,
      health_checks: {
        active: {
          healthy: { interval: 5, successes: 2 },
          unhealthy: { interval: 5, timeouts: 3, http_failures: 2 },
        },
      },
    },

    // Insurance Claims Service
    claims: {
      name: "claims-service",
      url: "http://claims-service:3000",
      protocol: "http",
      connect_timeout: 60000,
      write_timeout: 60000,
      read_timeout: 60000,
      retries: 3,
      health_checks: {
        active: {
          healthy: { interval: 5, successes: 2 },
          unhealthy: { interval: 5, timeouts: 3, http_failures: 2 },
        },
      },
    },
  },

  routes: {
    // Authentication Routes
    auth: {
      paths: [`/api/${API_VERSION}/auth`],
      methods: ["GET", "POST", "PUT", "DELETE"],
      strip_path: true,
      preserve_host: false,
      protocols: ["https"],
      regex_priority: 100,
      https_redirect_status_code: 308,
    },

    // Virtual Care Routes
    "virtual-care": {
      paths: [`/api/${API_VERSION}/virtual-care`],
      methods: ["GET", "POST", "PUT", "DELETE"],
      strip_path: true,
      preserve_host: false,
      protocols: ["https", "wss"],
      regex_priority: 90,
      https_redirect_status_code: 308,
    },

    // Health Records Routes
    "health-records": {
      paths: [`/api/${API_VERSION}/health-records`],
      methods: ["GET", "POST", "PUT", "DELETE"],
      strip_path: true,
      preserve_host: false,
      protocols: ["https"],
      regex_priority: 80,
      https_redirect_status_code: 308,
    },

    // Insurance Claims Routes
    claims: {
      paths: [`/api/${API_VERSION}/claims`],
      methods: ["GET", "POST", "PUT", "DELETE"],
      strip_path: true,
      preserve_host: false,
      protocols: ["https"],
      regex_priority: 70,
      https_redirect_status_code: 308,
    },
  },

  plugins: {
    // CORS Configuration
    cors: {
      name: "cors",
      config: {
        origins: [
          "https://*.austa-health.com",
          "https://admin.austa-health.com",
          "capacitor://localhost",
          "http://localhost:3000",
        ],
        methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        headers: [
          "Authorization",
          "Content-Type",
          "X-Request-ID",
          "X-API-Key",
          "X-HIPAA-Audit-ID",
        ],
        exposed_headers: ["X-Auth-Token", "X-Request-ID", "X-HIPAA-Audit-ID"],
        credentials: true,
        max_age: 3600,
      },
    },

    // Rate Limiting Configuration
    rate_limiting: {
      name: "rate-limiting",
      config: {
        minute: {
          patient: 1000,
          provider: 2000,
          admin: 5000,
        },
        hour: {
          patient: 50000,
          provider: 100000,
          admin: 250000,
        },
        policy: "redis",
        fault_tolerant: true,
        hide_client_headers: false,
        redis_host: "redis",
        redis_port: 6379,
        redis_timeout: 2000,
        redis_password: "${REDIS_PASSWORD}",
        redis_database: 0,
        redis_cluster_addresses: [
          "redis-node-0:6379",
          "redis-node-1:6379",
          "redis-node-2:6379",
        ],
      },
    },

    // OAuth 2.0 Configuration
    oauth2: {
      name: "oauth2",
      config: {
        scopes: ["patient", "provider", "admin"],
        mandatory_scope: true,
        token_expiration: 7200,
        enable_authorization_code: true,
        enable_client_credentials: true,
        enable_password_grant: false,
        accept_http_if_already_terminated: true,
        global_credentials: false,
        refresh_token_ttl: 1209600,
        provision_key: "${OAUTH_PROVISION_KEY}",
        auth_header_name: "authorization",
        hide_credentials: true,
      },
    },

    // Request Termination for Security
    request_termination: {
      name: "request-termination",
      config: {
        status_code: HttpStatus.FORBIDDEN,
        message: "Access forbidden by security policy",
        trigger: {
          headers: {
            "X-HIPAA-Violation": ["true"],
          },
        },
      },
    },

    // IP Restriction for Admin Access
    ip_restriction: {
      name: "ip-restriction",
      config: {
        whitelist: process.env.ADMIN_IP_WHITELIST?.split(",") || [],
        message: "Access restricted by security policy",
      },
    },

    // Request Size Limiting
    request_size_limiting: {
      name: "request-size-limiting",
      config: {
        allowed_payload_size: 10,
        require_content_length: true,
      },
    },

    // Response Transformer for Security Headers
    response_transformer: {
      name: "response-transformer",
      config: {
        add: {
          headers: [
            "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            "X-Frame-Options: DENY",
            "X-Content-Type-Options: nosniff",
            "X-XSS-Protection: 1; mode=block",
            "Content-Security-Policy: default-src 'self'",
          ],
        },
      },
    },
  },

  // SSL Certificate Configuration
  certificates: {
    default: {
      cert: "${SSL_CERT}",
      key: "${SSL_KEY}",
      snis: ["*.austa-health.com"],
    },
  },
}

// Validate configuration on load
validateConfig(kongConfig)
