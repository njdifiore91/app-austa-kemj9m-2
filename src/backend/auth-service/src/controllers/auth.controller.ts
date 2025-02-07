/**
 * @fileoverview HIPAA-compliant authentication controller implementing OAuth2/OIDC
 * with comprehensive security features and audit logging
 * @version 1.0.0
 */

import { Request, Response, NextFunction } from 'express';
import rateLimit from 'express-rate-limit';
import { createClient, RedisClientType } from 'redis';
import User from '../models/user.model';
import AuthService from '../services/auth.service';
import { ErrorCode } from '@shared/constants/error-codes';
import { ErrorMessage } from '@shared/constants/error-codes';
import { HttpStatus } from '@shared/constants/http-status';
import { UserRole, UserStatus, IUser } from '@shared/interfaces/user.interface';
import winston from 'winston';
import { controller, hipaaCompliant, securityAudit, post, hipaaValidate, auditLog, rateLimit as rateLimitDecorator } from '../decorators';
import crypto from 'crypto';
import { Auth0Client } from '@auth0/auth0-spa-js';
import { AUTH_CONFIG } from '../config/auth.config';
import { getRedisClient } from '../utils/redis.utils';

// Rate limiting configurations
const LOGIN_LIMITER = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 5, // 5 requests per minute
  message: 'Too many login attempts, please try again later',
  standardHeaders: true,
  legacyHeaders: false
});

const REGISTRATION_LIMITER = rateLimit({
  windowMs: 60 * 1000,
  max: 3,
  message: 'Too many registration attempts, please try again later',
  standardHeaders: true,
  legacyHeaders: false
});

/**
 * Authentication controller with security features
 */
@controller('/auth')
@hipaaCompliant()
@securityAudit()
export class AuthController {
  private authService!: AuthService;
  private logger: winston.Logger;

  constructor() {
    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      ),
      defaultMeta: { service: 'auth-service' },
      transports: [
        new winston.transports.Console({
          format: winston.format.combine(
            winston.format.colorize(),
            winston.format.simple()
          )
        })
      ]
    });

    this.logger.info('Initializing AuthController...');

    // Initialize Auth0 client
    this.logger.info('Initializing Auth0 client...');
    const auth0Client = new Auth0Client({
      domain: process.env.AUTH0_DOMAIN || 'your-domain.auth0.com',
      clientId: process.env.OAUTH_CLIENT_ID || 'dummy-client-id'
    });

    // Initialize security metrics
    this.logger.info('Setting up security metrics...');
    const securityMetrics = {
      trackEvent: async (userId: string, event: string) => {
        this.logger.info('Security event tracked', { userId, event });
      }
    };

    // Initialize auth service
    this.logger.info('Initializing AuthService...');
    getRedisClient().then((redisClient: RedisClientType) => {
      this.authService = new AuthService(User, redisClient, auth0Client, securityMetrics);
    }).catch((error: Error) => {
      this.logger.error('Failed to initialize AuthService:', error);
      throw error;
    });

    // Bind methods to this instance
    this.logger.info('Binding controller methods...');
    this.login = this.login.bind(this);
    this.register = this.register.bind(this);
    this.refreshToken = this.refreshToken.bind(this);
    this.logout = this.logout.bind(this);

    this.logger.info('AuthController initialization complete');
  }

  /**
   * Handles user login
   */
  @post('/login')
  @hipaaValidate()
  @rateLimitDecorator(LOGIN_LIMITER)
  @auditLog()
  public async login(
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<Response> {
    try {
      const { email, password, mfaCode } = req.body;
      const ipAddress = req.ip || '';
      const deviceFingerprint = req.headers['x-device-fingerprint'] as string || crypto.randomUUID();

      // Validate request data
      if (!email || !password) {
        return res.status(HttpStatus.BAD_REQUEST).json({
          error: ErrorMessage[ErrorCode.INVALID_INPUT].message
        });
      }

      // Attempt authentication
      const loginResult = await this.authService.login({
        email,
        password,
        mfaCode,
        deviceFingerprint,
        ipAddress
      });

      // Log successful login
      this.logger.info('User logged in successfully', {
        userId: loginResult.user.id,
        ipAddress
      });

      return res.status(HttpStatus.OK).json({
        token: loginResult.token,
        fingerprint: loginResult.fingerprint,
        user: {
          id: loginResult.user.id,
          email: loginResult.user.email,
          role: loginResult.user.role
        }
      });
    } catch (error) {
      this.logger.error('Login failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
        ipAddress: req.ip
      });

      if (error instanceof Error && error.message === ErrorCode.INVALID_CREDENTIALS) {
        return res.status(HttpStatus.UNAUTHORIZED).json({
          error: ErrorMessage[ErrorCode.INVALID_CREDENTIALS].message
        });
      }

      throw error;
    }
  }

  /**
   * Handles user registration with comprehensive validation
   */
  @post('/register')
  @hipaaValidate()
  @rateLimitDecorator(REGISTRATION_LIMITER)
  @auditLog()
  public async register(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      console.log('🔍 [AuthController] Register endpoint hit:', {
        body: {
          ...req.body,
          password: '[REDACTED]'
        },
        headers: req.headers,
        path: req.path,
        method: req.method
      });

      // Validate request body
      if (!req.body) {
        res.status(HttpStatus.BAD_REQUEST).json({
          code: ErrorCode.INVALID_INPUT,
          message: ErrorMessage[ErrorCode.INVALID_INPUT].message
        });
        return;
      }

      console.log('✅ [AuthController] Register validation passed, proceeding with registration');

      const result = await this.authService.register(req.body);

      res.status(HttpStatus.CREATED).json(result);
    } catch (error) {
      console.error('❌ [AuthController] Registration failed:', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        ipAddress: req.ip
      });

      // Handle mongoose validation errors
      if (error instanceof Error && error.name === 'ValidationError') {
        res.status(HttpStatus.BAD_REQUEST).json({
          code: ErrorCode.DATA_VALIDATION_ERROR,
          message: error.message,
          details: error
        });
        return;
      }

      // Handle MongoDB duplicate key errors
      if (error instanceof Error && error.message.includes('E11000 duplicate key error')) {
        const field = error.message.includes('email_1') ? 'email' : 'unknown field';
        res.status(HttpStatus.CONFLICT).json({
          code: ErrorCode.DUPLICATE_ENTRY,
          message: `A user with this ${field} already exists`,
          details: {
            field,
            error: 'DUPLICATE_ENTRY'
          }
        });
        return;
      }

      // Handle token generation errors
      if (error instanceof Error && error.message === ErrorCode.TOKEN_GENERATION_FAILED) {
        res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
          code: ErrorCode.TOKEN_GENERATION_FAILED,
          message: 'Failed to complete registration due to a security error. Please try again.',
          details: {
            error: 'TOKEN_GENERATION_FAILED'
          }
        });
        return;
      }

      // Handle other known errors
      if (error instanceof Error && Object.values(ErrorCode).includes(error.message as ErrorCode)) {
        const errorCode = error.message as ErrorCode;
        res.status(HttpStatus.BAD_REQUEST).json({
          code: errorCode,
          message: ErrorMessage[errorCode].message
        });
        return;
      }

      // Handle unknown errors
      res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
        code: ErrorCode.INTERNAL_SERVER_ERROR,
        message: ErrorMessage[ErrorCode.INTERNAL_SERVER_ERROR].message
      });
    }
  }

  /**
   * Handles account verification
   */
  @post('/verify-account')
  @hipaaValidate()
  @auditLog()
  public async verifyAccount(
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<Response> {
    try {
      const { userId, token } = req.body;

      if (!userId || !token) {
        return res.status(HttpStatus.BAD_REQUEST).json({
          code: ErrorCode.INVALID_INPUT,
          message: 'User ID and token are required'
        });
      }

      await this.authService.verifyAccount(userId, token);

      return res.status(HttpStatus.OK).json({
        message: 'Account verified successfully'
      });
    } catch (error) {
      this.logger.error('Account verification failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
        ipAddress: req.ip
      });

      if (error instanceof Error && error.message === ErrorCode.INVALID_VERIFICATION_TOKEN) {
        return res.status(HttpStatus.BAD_REQUEST).json({
          code: ErrorCode.INVALID_VERIFICATION_TOKEN,
          message: ErrorMessage[ErrorCode.INVALID_VERIFICATION_TOKEN].message
        });
      }

      if (error instanceof Error && error.message === ErrorCode.USER_NOT_FOUND) {
        return res.status(HttpStatus.NOT_FOUND).json({
          code: ErrorCode.USER_NOT_FOUND,
          message: ErrorMessage[ErrorCode.USER_NOT_FOUND].message
        });
      }

      throw error;
    }
  }

  /**
   * Handles user logout
   */
  @post('/logout')
  @hipaaValidate()
  @auditLog()
  public async logout(
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<Response> {
    try {
      const token = req.headers.authorization?.split(' ')[1];
      if (!token) {
        return res.status(HttpStatus.BAD_REQUEST).json({
          error: 'No token provided'
        });
      }

      await this.authService.logout(token);

      return res.status(HttpStatus.OK).json({
        message: 'Logged out successfully'
      });
    } catch (error) {
      this.logger.error('Logout failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
        ipAddress: req.ip
      });

      throw error;
    }
  }

  /**
   * Handles token refresh with security validation
   */
  @post('/refresh-token')
  @hipaaValidate()
  @auditLog()
  public async refreshToken(
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<Response> {
    try {
      const { refreshToken } = req.body;

      if (!refreshToken) {
        return res.status(HttpStatus.BAD_REQUEST).json({
          error: ErrorMessage[ErrorCode.INVALID_INPUT].message
        });
      }

      // Validate and refresh token
      const refreshResult = await this.authService.refreshToken(refreshToken);

      return res.status(HttpStatus.OK).json({
        token: refreshResult.token,
        fingerprint: refreshResult.fingerprint
      });
    } catch (error) {
      this.logger.error('Token refresh failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
        ipAddress: req.ip
      });

      throw error;
    }
  }
}

export default AuthController;