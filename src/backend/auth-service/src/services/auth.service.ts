/**
 * @fileoverview HIPAA-compliant authentication service implementation
 * Provides secure user authentication, authorization, and session management
 * with comprehensive security features and audit logging
 * @version 1.0.0
 */

import { injectable, inject } from 'inversify';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt'; // v5.1.0
import { RedisClientType } from 'redis'; // v4.6.7
import { Auth0Client } from '@auth0/auth0-spa-js'; // v2.1.2
import { randomUUID, randomBytes as cryptoRandomBytes } from 'crypto';
import jwt from 'jsonwebtoken';
import * as qrcode from 'qrcode';

import User, { IUserDocument } from '../models/user.model';
import { generateToken, verifyToken, refreshToken, generateTokenFingerprint } from '../utils/token.utils';
import AUTH_CONFIG from '../config/auth.config';
import { 
  ErrorCode,
  ErrorMessage
} from '@shared/constants/error-codes';
import { HttpStatus } from '@shared/constants/http-status';
import { IUser, UserRole, UserStatus } from '@shared/interfaces/user.interface';
import { validateUserData } from '@shared/utils/validation.utils';

// Constants for security configuration
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_DURATION = 900; // 15 minutes in seconds
const TOKEN_BLACKLIST_PREFIX = 'bl:';
const DEVICE_FINGERPRINT_SALT = 'unique_salt_value';
const SESSION_TIMEOUT = 3600; // 1 hour in seconds
const MFA_CODE_EXPIRY = 300; // 5 minutes in seconds

/**
 * Interface for login credentials with enhanced security features
 */
interface ILoginCredentials {
  email: string;
  password: string;
  mfaCode?: string;
  deviceFingerprint: string;
  ipAddress: string;
}

/**
 * Interface defining authentication service methods
 */
interface IAuthService {
  login(credentials: ILoginCredentials): Promise<{ token: string; fingerprint: string; user: IUser }>;
  register(userData: IUser): Promise<{ token: string; fingerprint: string; user: IUser }>;
  refreshToken(token: string): Promise<{ token: string; fingerprint: string }>;
  logout(token: string): Promise<void>;
  validateToken(token: string): Promise<boolean>;
  validateMFA(userId: string, code: string): Promise<boolean>;
  validateDeviceFingerprint(userId: string, fingerprint: string): Promise<boolean>;
  trackSecurityMetrics(userId: string, event: string): Promise<void>;
  sendVerificationEmail(userId: string): Promise<void>;
  verifyAccount(userId: string, token: string): Promise<void>;
  setupMFA(userId: string, mfaMethod: string): Promise<{ secret?: string; qrCode?: string }>;
}

/**
 * HIPAA-compliant authentication service implementation
 */
@injectable()
class AuthService implements IAuthService {
  private userModel: Model<IUserDocument>;
  private redisClient: RedisClientType;
  private auth0Client: Auth0Client;
  private securityMetrics: any;

  constructor(
    @inject('UserModel') userModel: Model<IUserDocument>,
    @inject('RedisClient') redisClient: RedisClientType,
    @inject('Auth0Client') auth0Client: Auth0Client,
    @inject('SecurityMetrics') securityMetrics: any
  ) {
    this.userModel = userModel;
    this.redisClient = redisClient;
    this.auth0Client = auth0Client;
    this.securityMetrics = securityMetrics;
  }

  /**
   * Authenticates user with comprehensive security checks
   */
  public async login(credentials: ILoginCredentials): Promise<{ token: string; fingerprint: string; user: IUser }> {
    try {
      // Validate input credentials
      if (!credentials.email || !credentials.password) {
        throw new Error(ErrorCode.INVALID_INPUT);
      }

      // Check IP-based rate limiting
      await this.checkRateLimit(credentials.ipAddress);

      // Find user and validate status
      const user = await this.userModel.findOne({ email: credentials.email })
        .select('+password +securitySettings')
        .exec();

      if (!user) {
        throw new Error(ErrorCode.INVALID_CREDENTIALS);
      }

      // Check account status
      if (user.status !== UserStatus.ACTIVE) {
        throw new Error(ErrorCode.UNAUTHORIZED);
      }

      // Verify password
      const isValidPassword = await user.comparePassword(credentials.password);
      if (!isValidPassword) {
        await this.handleFailedLogin(user.id);
        throw new Error(ErrorCode.INVALID_CREDENTIALS);
      }

      // Validate MFA if enabled
      if (user.securitySettings.mfaEnabled) {
        const isMfaValid = await this.validateMFA(user.id, credentials.mfaCode || '');
        if (!isMfaValid) {
          throw new Error(ErrorCode.UNAUTHORIZED);
        }
      }

      // Validate device fingerprint
      const isValidDevice = await this.validateDeviceFingerprint(
        user.id,
        credentials.deviceFingerprint
      );

      if (!isValidDevice) {
        await this.trackSecurityMetrics(user.id, 'UNKNOWN_DEVICE_LOGIN');
      }

      // Generate token with fingerprint
      const tokenPayload = {
        userId: user.id,
        email: user.email,
        roles: [user.role],
        permissions: user.permissions,
        sessionId: crypto.randomUUID(),
        deviceId: credentials.deviceFingerprint,
        ipAddress: credentials.ipAddress,
        fingerprint: '',
        auditId: crypto.randomUUID()
      };

      const fingerprint = generateTokenFingerprint(tokenPayload);
      tokenPayload.fingerprint = fingerprint;

      const token = await generateToken(tokenPayload);

      // Store session in Redis
      await this.storeSession(user.id, tokenPayload);

      // Track successful login
      await this.trackSecurityMetrics(user.id, 'SUCCESSFUL_LOGIN');

      // Update user's last login
      user.securitySettings.lastLoginAt = new Date();
      user.securitySettings.lastLoginIP = credentials.ipAddress;
      await user.save();

      return { token, fingerprint, user };
    } catch (error) {
      await this.trackSecurityMetrics('unknown', 'FAILED_LOGIN');
      throw error;
    }
  }

  /**
   * Registers new user with security validation
   */
  public async register(userData: IUser): Promise<{ token: string; fingerprint: string; user: IUser }> {
    console.log('🔍 [AuthService] Register method called with user data:', {
      email: userData.email,
      firstName: userData.profile?.firstName,
      lastName: userData.profile?.lastName
    });

    try {
      // Validate user data
      console.log('⏳ [AuthService] Validating user data...');
      const validationResult = await validateUserData(userData, { validatePassword: true });
      if (!validationResult.isValid) {
        console.log('❌ [AuthService] User data validation failed:', validationResult.errors);
        throw new Error(ErrorCode.INVALID_INPUT);
      }
      console.log('✅ [AuthService] User data validation passed');

      // Create user with enhanced security settings
      console.log('⏳ [AuthService] Creating new user...');
      const user = new this.userModel({
        email: userData.email,
        password: userData.password,
        role: userData.role || UserRole.PATIENT,
        status: UserStatus.PENDING,
        profile: {
          firstName: userData.profile?.firstName || '',
          lastName: userData.profile?.lastName || '',
          dateOfBirth: userData.profile?.dateOfBirth || new Date(),
          gender: userData.profile?.gender || '',
          phoneNumber: userData.profile?.phoneNumber || '',
          address: {
            street: userData.profile?.address?.street || '',
            city: userData.profile?.address?.city || '',
            state: userData.profile?.address?.state || '',
            postalCode: userData.profile?.address?.postalCode || '',
            country: userData.profile?.address?.country || ''
          },
          emergencyContact: {
            name: userData.profile?.emergencyContact?.name || '',
            relationship: userData.profile?.emergencyContact?.relationship || '',
            phoneNumber: userData.profile?.emergencyContact?.phoneNumber || ''
          },
          preferredLanguage: userData.profile?.preferredLanguage || 'en'
        },
        securitySettings: {
          mfaEnabled: userData.securitySettings?.mfaEnabled || true,
          mfaMethod: userData.securitySettings?.mfaMethod || 'sms',
          lastPasswordChange: new Date(),
          passwordResetRequired: userData.securitySettings?.passwordResetRequired || false,
          loginAttempts: 0,
          deviceFingerprints: userData.securitySettings?.deviceFingerprints || []
        },
        permissions: userData.permissions || [],
        audit: {
          createdAt: new Date(),
          createdBy: 'system',
          updatedAt: new Date(),
          updatedBy: 'system',
          version: 1,
          changeHistory: []
        }
      });

      await user.save();
      console.log('✅ [AuthService] User created successfully:', { userId: user.id });

      const tokenPayload = {
        userId: user.id,
        email: user.email,
        roles: [user.role],
        permissions: user.permissions,
        sessionId: crypto.randomUUID(),
        deviceId: userData.securitySettings?.deviceFingerprints?.[0] || crypto.randomUUID(),
        ipAddress: '',
        fingerprint: '',
        auditId: crypto.randomUUID()
      };

      console.log('⏳ [AuthService] Generating token and fingerprint...');
      const fingerprint = generateTokenFingerprint(tokenPayload);
      tokenPayload.fingerprint = fingerprint;

      const token = await generateToken(tokenPayload);
      console.log('✅ [AuthService] Token generated successfully');

      try {
        await this.trackSecurityMetrics(user.id, 'USER_REGISTERED');
      } catch (error) {
        // Log but don't fail registration if metrics tracking fails
        console.error('Failed to track security metrics:', error);
      }

      // Setup MFA if specified
      if (userData.securitySettings?.mfaMethod) {
        await this.setupMFA(user.id, userData.securitySettings.mfaMethod);
      }

      // Send verification email
      await this.sendVerificationEmail(user.id);

      return { token, fingerprint, user };
    } catch (error) {
      console.error('❌ [AuthService] Registration error:', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined
      });
      try {
        await this.trackSecurityMetrics('unknown', 'REGISTRATION_FAILED');
      } catch (metricsError) {
        console.error('Failed to track security metrics:', metricsError);
      }
      throw error;
    }
  }

  /**
   * Refreshes token with security validation
   */
  public async refreshToken(oldToken: string): Promise<{ token: string; fingerprint: string }> {
    try {
      const decoded = await verifyToken(oldToken);
      const newToken = await refreshToken(oldToken);
      const fingerprint = decoded.fingerprint;

      await this.trackSecurityMetrics(decoded.userId, 'TOKEN_REFRESHED');

      return { token: newToken, fingerprint };
    } catch (error) {
      throw new Error(ErrorCode.UNAUTHORIZED);
    }
  }

  /**
   * Validates token and checks blacklist
   */
  public async validateToken(token: string): Promise<boolean> {
    try {
      const decoded = await verifyToken(token);
      const isBlacklisted = await this.redisClient.get(`${TOKEN_BLACKLIST_PREFIX}${decoded.userId}`);
      return !isBlacklisted;
    } catch (error) {
      return false;
    }
  }

  /**
   * Securely logs out user and invalidates session
   */
  public async logout(token: string): Promise<void> {
    try {
      const decoded = await verifyToken(token);
      
      // Invalidate session in Redis
      await this.redisClient.del(`session:${decoded.userId}`);
      
      // Add token to blacklist
      await this.redisClient.setEx(
        `${TOKEN_BLACKLIST_PREFIX}${decoded.userId}`,
        SESSION_TIMEOUT,
        token
      );

      await this.trackSecurityMetrics(decoded.userId, 'USER_LOGOUT');
    } catch (error) {
      throw new Error(ErrorCode.UNAUTHORIZED);
    }
  }

  // Private helper methods

  /**
   * Checks rate limiting for IP address
   */
  private async checkRateLimit(ipAddress: string): Promise<void> {
    const attempts = await this.redisClient.incr(`ratelimit:${ipAddress}`);
    if (attempts === 1) {
      await this.redisClient.expire(`ratelimit:${ipAddress}`, LOCKOUT_DURATION);
    }
    if (attempts > MAX_LOGIN_ATTEMPTS) {
      throw new Error(ErrorCode.RATE_LIMIT_EXCEEDED);
    }
  }

  /**
   * Handles failed login attempts
   */
  private async handleFailedLogin(userId: string): Promise<void> {
    const attempts = await this.redisClient.incr(`failedlogin:${userId}`);
    if (attempts === 1) {
      await this.redisClient.expire(`failedlogin:${userId}`, LOCKOUT_DURATION);
    }
    if (attempts >= MAX_LOGIN_ATTEMPTS) {
      const user = await this.userModel.findById(userId);
      if (user) {
        user.status = UserStatus.LOCKED;
        await user.save();
      }
    }
  }

  /**
   * Stores session data in Redis
   */
  private async storeSession(userId: string, sessionData: any): Promise<void> {
    await this.redisClient.setEx(
      `session:${userId}`,
      SESSION_TIMEOUT,
      JSON.stringify(sessionData)
    );
  }

  /**
   * Validates MFA code for a user
   */
  public async validateMFA(userId: string, code: string): Promise<boolean> {
    try {
      const user = await this.userModel.findById(userId).select('+securitySettings').exec();
      if (!user || !user.securitySettings.mfaEnabled) return false;

      // Validate MFA code using appropriate method (TOTP, SMS, etc.)
      const isValid = await this.validateMFACode(user, code);
      await this.trackSecurityMetrics(userId, isValid ? 'MFA_SUCCESS' : 'MFA_FAILED');
      return isValid;
    } catch (error) {
      await this.trackSecurityMetrics(userId, 'MFA_ERROR');
      return false;
    }
  }

  /**
   * Validates device fingerprint for enhanced security
   */
  public async validateDeviceFingerprint(userId: string, fingerprint: string): Promise<boolean> {
    try {
      const user = await this.userModel.findById(userId).select('+securitySettings').exec();
      if (!user) return false;

      // Check if device fingerprint is in user's trusted devices
      const isTrustedDevice = user.securitySettings.deviceFingerprints.includes(fingerprint);
      
      if (!isTrustedDevice) {
        // Store new device fingerprint if validation passes additional checks
        const isValidNewDevice = await this.validateNewDevice(userId, fingerprint);
        if (isValidNewDevice) {
          user.securitySettings.deviceFingerprints.push(fingerprint);
          await user.save();
        }
        return isValidNewDevice;
      }

      return true;
    } catch (error) {
      await this.trackSecurityMetrics(userId, 'DEVICE_VALIDATION_ERROR');
      return false;
    }
  }

  /**
   * Tracks security-related events for auditing and monitoring
   */
  public async trackSecurityMetrics(userId: string, event: string): Promise<void> {
    try {
      const timestamp = new Date().toISOString();
      const metricData = {
        userId,
        event,
        timestamp,
        metadata: {
          environment: process.env.NODE_ENV,
          service: 'auth-service',
          version: process.env.SERVICE_VERSION
        }
      };

      // Log metric to security monitoring system if available
      if (this.securityMetrics && typeof this.securityMetrics.logMetric === 'function') {
        await this.securityMetrics.logMetric(metricData);
      } else {
        // Fallback to console logging if metrics service is not available
        console.log('Security Metric:', metricData);
      }

      // Store in Redis for real-time monitoring if Redis is available
      if (this.redisClient) {
        try {
          const key = `security:metrics:${userId}:${timestamp}`;
          await this.redisClient.setEx(key, 86400, JSON.stringify(metricData)); // 24 hours TTL
        } catch (redisError) {
          console.error('Failed to store security metric in Redis:', redisError);
        }
      }
    } catch (error) {
      // Log error but don't throw to prevent disrupting the main flow
      console.error('Failed to track security metrics:', error);
    }
  }

  /**
   * Internal method to validate MFA code based on the configured method
   */
  private async validateMFACode(user: IUserDocument, code: string): Promise<boolean> {
    if (!user.securitySettings.mfaSecret) return false;

    switch (user.securitySettings.mfaMethod) {
      case 'authenticator':
        return this.validateTOTP(user.securitySettings.mfaSecret, code);
      case 'sms':
        return this.validateSMSCode(user._id.toString(), code);
      case 'email':
        return this.validateEmailCode(user._id.toString(), code);
      default:
        return false;
    }
  }

  /**
   * Validates TOTP (Time-based One-Time Password) for authenticator-based MFA
   */
  private validateTOTP(secret: string, token: string): boolean {
    // Simple TOTP validation (in production, use a proper TOTP library)
    const storedSecret = Buffer.from(secret, 'base64').toString('utf-8');
    const currentTime = Math.floor(Date.now() / 30000); // 30-second window
    return token === `${storedSecret}${currentTime}`; // Simplified for example
  }

  /**
   * Validates SMS-based MFA code
   */
  private async validateSMSCode(userId: string, code: string): Promise<boolean> {
    const cacheKey = `sms_mfa:${userId}`;
    const storedCode = await this.redisClient.get(cacheKey);
    return storedCode === code;
  }

  /**
   * Validates email-based MFA code
   */
  private async validateEmailCode(userId: string, code: string): Promise<boolean> {
    const cacheKey = `email_mfa:${userId}`;
    const storedCode = await this.redisClient.get(cacheKey);
    return storedCode === code;
  }

  /**
   * Validates new device registration
   */
  private async validateNewDevice(userId: string, fingerprint: string): Promise<boolean> {
    try {
      // Implement device validation logic (e.g., risk assessment, location check)
      const user = await this.userModel.findById(userId);
      if (!user) return false;

      // Check if device count exceeds limit
      const maxDevices = AUTH_CONFIG.security.maxDevicesPerUser || 5;
      if (user.securitySettings.deviceFingerprints.length >= maxDevices) {
        return false;
      }

      // Additional security checks can be implemented here
      // For example:
      // - Location-based validation
      // - Device reputation check
      // - Risk scoring
      
      return true;
    } catch (error) {
      await this.trackSecurityMetrics(userId, 'DEVICE_VALIDATION_ERROR');
      return false;
    }
  }

  /**
   * Generates and sends account verification token
   */
  public async sendVerificationEmail(userId: string): Promise<void> {
    try {
      const user = await this.userModel.findById(userId);
      if (!user) throw new Error(ErrorCode.USER_NOT_FOUND);

      // Generate verification token
      const verificationToken = crypto.randomUUID();
      
      // Store token in Redis with expiry
      await this.redisClient.setEx(
        `verification:${userId}`,
        86400, // 24 hours expiry
        verificationToken
      );

      // Construct verification link
      const baseUrl = process.env.FRONTEND_URL || 'http://localhost:3000';
      const verificationLink = `${baseUrl}/verify-account?userId=${userId}&token=${verificationToken}`;

      // TODO: Implement email sending logic
      console.log('Verification link:', verificationLink);
      console.log('This link will be valid for 24 hours');
      
      await this.trackSecurityMetrics(userId, 'VERIFICATION_EMAIL_SENT');
    } catch (error) {
      console.error('Failed to send verification email:', error);
      throw error;
    }
  }

  /**
   * Verifies user's account with the provided token
   */
  public async verifyAccount(userId: string, token: string): Promise<void> {
    try {
      // Verify token from Redis
      const storedToken = await this.redisClient.get(`verification:${userId}`);
      if (!storedToken || storedToken !== token) {
        throw new Error(ErrorCode.INVALID_VERIFICATION_TOKEN);
      }

      // Update user status to ACTIVE
      const user = await this.userModel.findById(userId);
      if (!user) throw new Error(ErrorCode.USER_NOT_FOUND);

      user.status = UserStatus.ACTIVE;
      await user.save();

      // Delete verification token
      await this.redisClient.del(`verification:${userId}`);
      
      await this.trackSecurityMetrics(userId, 'ACCOUNT_VERIFIED');
    } catch (error) {
      console.error('Account verification failed:', error);
      throw error;
    }
  }

  /**
   * Sets up MFA for a user during registration
   */
  public async setupMFA(userId: string, mfaMethod: string): Promise<{ secret?: string; qrCode?: string }> {
    try {
      const user = await this.userModel.findById(userId).select('+securitySettings');
      if (!user) throw new Error(ErrorCode.USER_NOT_FOUND);

      if (mfaMethod === 'none') {
        user.securitySettings.mfaEnabled = false;
        user.securitySettings.mfaMethod = 'none';
        await user.save();
        return {};
      }

      // Generate MFA secret
      const mfaSecret = cryptoRandomBytes(32).toString('base64');
      
      user.securitySettings.mfaEnabled = true;
      user.securitySettings.mfaMethod = mfaMethod;
      user.securitySettings.mfaSecret = mfaSecret;
      await user.save();

      let response: { secret?: string; qrCode?: string } = {};

      switch (mfaMethod) {
        case 'authenticator':
          // Generate QR code for authenticator app
          const qrCode = await this.generateAuthenticatorQRCode(user.email, mfaSecret);
          response = { secret: mfaSecret, qrCode };
          break;
        case 'sms':
        case 'email':
          // Store secret for later verification
          response = { secret: mfaSecret };
          break;
      }

      await this.trackSecurityMetrics(userId, 'MFA_SETUP_COMPLETED');
      return response;
    } catch (error) {
      console.error('MFA setup failed:', error);
      throw error;
    }
  }

  /**
   * Generates QR code for authenticator app
   */
  private async generateAuthenticatorQRCode(email: string, secret: string): Promise<string> {
    const otpauth = `otpauth://totp/${encodeURIComponent(email)}?secret=${secret}&issuer=YourApp`;
    return qrcode.toDataURL(otpauth);
  }
}

export default AuthService;