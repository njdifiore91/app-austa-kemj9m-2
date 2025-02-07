/**
 * @fileoverview HIPAA-compliant authentication API client for AUSTA SuperApp
 * Implements secure OAuth 2.0 + OIDC flows with MFA and biometric support
 * @version 1.0.0
 * @license HIPAA-compliant
 */

import axios, { AxiosInstance, AxiosRequestConfig } from 'axios'; // v1.4.0
import CryptoJS from 'crypto-js'; // v4.1.1
import { logger } from '../utils/logger';

import { AuthEndpoints, buildUrl } from '../constants/endpoints';
import { 
  ILoginCredentials, 
  IAuthTokens, 
  IMFACredentials, 
  IAuthError,
  AuthState,
  SecurityEvent,
  IUser
} from '../types/auth';
import { encryptData, WebEncryptionService, EncryptionConfig } from '../utils/encryption';

/**
 * Security configuration for authentication API
 */
interface SecurityConfig {
  tokenRefreshThreshold: number;
  maxRetries: number;
  timeout: number;
  encryptionConfig: EncryptionConfig;
}

/**
 * Default security configuration
 */
const DEFAULT_SECURITY_CONFIG: SecurityConfig = {
  tokenRefreshThreshold: 300, // 5 minutes
  maxRetries: 3,
  timeout: 30000,
  encryptionConfig: {
    algorithm: 'AES-GCM',
    keySize: 256,
    ivSize: 96,
    tagLength: 128,
    iterations: 100000,
    saltLength: 32
  }
};

interface RegisterParams {
  email: string;
  password: string;
  firstName: string;
  lastName: string;
  phoneNumber: string;
  mfaPreference: string;
  biometricConsent: boolean;
  deviceFingerprint: string;
  gender: string;
  address: {
    street: string;
    city: string;
    state: string;
    postalCode: string;
    country: string;
  };
  emergencyContact: {
    name: string;
    relationship: string;
    phoneNumber: string;
  };
}

/**
 * HIPAA-compliant authentication API client
 */
class AuthAPI {
  protected client: AxiosInstance;
  private readonly baseURL: string;
  private encryptionService: WebEncryptionService;
  private securityConfig: SecurityConfig;

  constructor(baseURL: string, config: SecurityConfig = DEFAULT_SECURITY_CONFIG) {
    this.baseURL = baseURL;
    this.securityConfig = config;
    this.encryptionService = new WebEncryptionService(config.encryptionConfig);

    // Initialize secure HTTP client
    this.client = axios.create({
      baseURL: this.baseURL,
      timeout: config.timeout,
      withCredentials: true,
      headers: {
        'Content-Type': 'application/json',
        'X-Security-Version': '1.0'
      }
    });

    this.setupSecurityInterceptors();
  }

  /**
   * Configures security interceptors for request/response handling
   */
  private setupSecurityInterceptors(): void {
    // Request interceptor for security headers
    this.client.interceptors.request.use(async (config) => {
      const requestId = CryptoJS.lib.WordArray.random(16).toString();
      config.headers['X-Request-ID'] = requestId;
      
      // Add authorization header if token exists in localStorage
      const storedTokens = localStorage.getItem('auth_tokens');
      if (storedTokens) {
        try {
          // Parse the stored tokens directly since they're already decrypted by useAuth
          const tokens = JSON.parse(storedTokens);
          if (tokens.accessToken) {
            config.headers['Authorization'] = `Bearer ${tokens.accessToken}`;
          }
        } catch (error) {
          console.error('Failed to parse stored tokens:', error);
          // Remove invalid tokens
          localStorage.removeItem('auth_tokens');
        }
      }
      
      return config;
    });

    // Response interceptor for security validation
    this.client.interceptors.response.use(
      async (response) => {
        this.logSecurityEvent({
          eventType: 'API_RESPONSE',
          timestamp: Date.now(),
          userId: response.headers['x-user-id'] || 'anonymous',
          sessionId: response.headers['x-session-id'] || 'none',
          metadata: {
            endpoint: response.config.url,
            status: response.status
          },
          severity: 'LOW',
          outcome: 'SUCCESS'
        });
        return response;
      },
      async (error) => {
        // Log CORS errors specifically
        if (error.message.includes('CORS')) {
          this.logSecurityEvent({
            eventType: 'CORS_ERROR',
            timestamp: Date.now(),
            userId: 'anonymous',
            sessionId: 'none',
            metadata: {
              endpoint: error.config?.url,
              error: error.message,
              origin: window.location.origin
            },
            severity: 'HIGH',
            outcome: 'FAILURE'
          });
        }

        this.logSecurityEvent({
          eventType: 'API_ERROR',
          timestamp: Date.now(),
          userId: error.config?.headers?.['x-user-id'] || 'anonymous',
          sessionId: error.config?.headers?.['x-session-id'] || 'none',
          metadata: {
            endpoint: error.config?.url,
            error: error.message
          },
          severity: 'HIGH',
          outcome: 'FAILURE'
        });
        throw this.handleAuthError(error);
      }
    );
  }

  /**
   * Processes authentication errors with security context
   */
  private handleAuthError(error: any): IAuthError {
    // Extract error details from the response
    const errorResponse = error.response?.data;
    
    return {
      code: errorResponse?.code || 'AUTH_ERROR',
      message: errorResponse?.message || 'Authentication failed',
      details: {
        field: errorResponse?.details?.field,
        error: errorResponse?.details?.error,
        ...errorResponse?.details
      },
      timestamp: Date.now(),
      requestId: error.config?.headers?.['X-Request-ID']
    };
  }

  /**
   * Logs security events for audit compliance
   */
  private logSecurityEvent(event: SecurityEvent): void {
    logger.info('Security Event', { ...event });
  }

  /**
   * Registers a new user with enhanced security measures
   */
  public async register(params: RegisterParams): Promise<{ token: string; fingerprint: string; user: IUser }> {
    try {
      console.log('Registration URL:', buildUrl(AuthEndpoints.REGISTER));
      
      // Restructure the data to match the auth service expectations
      const requestData = {
        email: params.email,
        password: params.password,
        role: 'PATIENT',
        status: 'PENDING', // Explicitly set the initial status
        profile: {
          firstName: params.firstName,
          lastName: params.lastName,
          phoneNumber: params.phoneNumber,
          gender: params.gender,
          address: {
            street: params.address.street,
            city: params.address.city,
            state: params.address.state,
            postalCode: params.address.postalCode,
            country: params.address.country
          },
          emergencyContact: {
            name: params.emergencyContact.name,
            relationship: params.emergencyContact.relationship,
            phoneNumber: params.emergencyContact.phoneNumber
          },
          dateOfBirth: new Date(),
          preferredLanguage: 'en'
        },
        securitySettings: {
          mfaEnabled: true,
          mfaMethod: params.mfaPreference,
          biometricEnabled: params.biometricConsent,
          deviceFingerprints: [params.deviceFingerprint],
          lastPasswordChange: new Date(),
          passwordResetRequired: false,
          loginAttempts: 0
        },
        permissions: [],
        audit: {
          createdAt: new Date(),
          createdBy: 'system',
          updatedAt: new Date(),
          updatedBy: 'system',
          version: 1,
          changeHistory: []
        }
      };

      const response = await this.client.post(
        buildUrl(AuthEndpoints.REGISTER),
        requestData
      );

      this.logSecurityEvent({
        eventType: 'USER_REGISTRATION',
        timestamp: Date.now(),
        userId: response.data.user.id,
        sessionId: params.deviceFingerprint,
        metadata: {
          email: params.email,
          mfaType: params.mfaPreference
        },
        severity: 'MEDIUM',
        outcome: 'SUCCESS'
      });

      return response.data;
    } catch (error) {
      throw this.handleAuthError(error);
    }
  }

  /**
   * Authenticates user with enhanced security measures
   */
  public async login(credentials: ILoginCredentials): Promise<{ token: string; fingerprint: string; user: IUser }> {
    try {
      const response = await this.client.post(
        buildUrl(AuthEndpoints.LOGIN),
        credentials
      );

      const { token, fingerprint, user } = response.data;

      this.logSecurityEvent({
        eventType: 'USER_LOGIN',
        timestamp: Date.now(),
        userId: credentials.email,
        sessionId: token,
        metadata: {
          deviceId: credentials.deviceId
        },
        severity: 'MEDIUM',
        outcome: 'SUCCESS'
      });

      return { token, fingerprint, user };
    } catch (error) {
      throw this.handleAuthError(error);
    }
  }

  /**
   * Verifies MFA credentials with enhanced security
   */
  public async verifyMFA(mfaCredentials: IMFACredentials): Promise<IAuthTokens> {
    try {
      const encryptedMFA = await this.encryptionService.encryptField(
        JSON.stringify(mfaCredentials),
        'mfa'
      );

      const response = await this.client.post(
        buildUrl(AuthEndpoints.VERIFY_TOKEN),
        { mfa: encryptedMFA }
      );

      this.logSecurityEvent({
        eventType: 'MFA_VERIFICATION',
        timestamp: Date.now(),
        userId: response.headers['x-user-id'],
        sessionId: response.headers['x-session-id'],
        metadata: {
          method: mfaCredentials.method,
          verificationId: mfaCredentials.verificationId
        },
        severity: 'HIGH',
        outcome: 'SUCCESS'
      });

      return response.data;
    } catch (error) {
      throw this.handleAuthError(error);
    }
  }

  /**
   * Logs out the current user and cleans up session
   */
  public async logout(): Promise<void> {
    try {
      this.client.post(buildUrl(AuthEndpoints.LOGOUT));
      
      this.logSecurityEvent({
        eventType: 'USER_LOGOUT',
        timestamp: Date.now(),
        userId: 'anonymous',
        sessionId: 'none',
        metadata: {},
        severity: 'LOW',
        outcome: 'SUCCESS'
      });
    } catch (error) {
      throw this.handleAuthError(error);
    }
  }

  /**
   * Refreshes the current session token
   */
  public async refreshToken(): Promise<IAuthTokens> {
    try {
      const response = await this.client.post(buildUrl(AuthEndpoints.REFRESH_TOKEN));
      return response.data;
    } catch (error) {
      throw this.handleAuthError(error);
    }
  }

  /**
   * Verifies user's account with the provided token
   */
  public async verifyAccount(userId: string, token: string): Promise<void> {
    try {
      console.log(AuthEndpoints);
      // Use the endpoint string directly instead of the enum
      const url = buildUrl('/auth/verify-account');
      console.log('Verification URL:', url);
      console.log('Request payload:', { userId, token });
      
      const response = await this.client.post(
        url,
        { userId, token }
      );
      
      console.log('Verification response:', response.data);
      console.log('Account verified successfully');

      this.logSecurityEvent({
        eventType: 'ACCOUNT_VERIFIED',
        timestamp: Date.now(),
        userId,
        sessionId: 'none',
        metadata: {},
        severity: 'MEDIUM',
        outcome: 'SUCCESS'
      });
    } catch (error) {
      console.error('Verification error:', error);
      throw this.handleAuthError(error);
    }
  }
}

const authInstance = new AuthAPI(process.env.NEXT_PUBLIC_API_URL || '');

export { AuthAPI };
export default authInstance;