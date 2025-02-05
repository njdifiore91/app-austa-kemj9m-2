/**
 * @fileoverview HIPAA-compliant authentication controller implementing OAuth2/OIDC
 * with comprehensive security features and audit logging
 * @version 1.0.0
 */

import { Request, Response, NextFunction } from "express" // v4.18.2
import { injectable, inject } from "inversify"
import { Controller, Post, Get } from "@decorators/express"
// import { Auth0Client } from "@auth0/auth0-spa-js" // v2.1.0
import rateLimit from "express-rate-limit" // v6.9.0
import { SecurityMetrics } from "@austa/shared/utils/security/security-metrics"
import { SessionManager } from "@austa/shared/utils/session/session-manager"
import {
  hipaaCompliant,
  securityAudit,
  hipaaValidate,
  auditLog,
  middleware,
} from "../decorators/hipaa.decorators"

import AuthService from "../services/auth.service"
import { ErrorCode, ErrorMessage } from "@austa/shared/constants/error-codes"
import { HttpStatus } from "@austa/shared/constants/http-status"
import { validateUserData } from "@austa/shared/utils/validation.utils"
import { IUser } from "@austa/shared/interfaces/user.interface"

// Extend Request type to include user property
interface AuthenticatedRequest extends Request {
  user?: {
    id: string
    email: string
    role: string
  }
}

// Rate limiting configurations
const LOGIN_LIMITER = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 5, // 5 requests per minute
  message: ErrorMessage[ErrorCode.RATE_LIMIT_EXCEEDED].message,
  standardHeaders: true,
  legacyHeaders: false,
})

const REGISTRATION_LIMITER = rateLimit({
  windowMs: 60 * 1000,
  max: 3,
  message: ErrorMessage[ErrorCode.RATE_LIMIT_EXCEEDED].message,
  standardHeaders: true,
  legacyHeaders: false,
})

/**
 * HIPAA-compliant authentication controller with comprehensive security features
 */
@injectable()
@Controller("/auth")
@hipaaCompliant()
@securityAudit()
export class AuthController {
  private authService: AuthService
  private sessionManager: SessionManager
  private securityMetrics: SecurityMetrics

  constructor(
    @inject("AuthService") authService: AuthService,
    @inject("SessionManager") sessionManager: SessionManager,
    @inject("SecurityMetrics") securityMetrics: SecurityMetrics
  ) {
    this.authService = authService
    this.sessionManager = sessionManager
    this.securityMetrics = securityMetrics
  }

  /**
   * Handles secure user login with MFA support
   */
  @Post("/login")
  @hipaaValidate()
  @middleware(LOGIN_LIMITER)
  @auditLog()
  public async login(
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
  ): Promise<Response | void> {
    try {
      // Extract and validate login credentials
      const { email, password, mfaCode, deviceFingerprint } = req.body
      const ipAddress = req.ip || ""

      // Validate request data
      if (!email || !password || !deviceFingerprint) {
        return res.status(HttpStatus.BAD_REQUEST).json({
          error: ErrorMessage[ErrorCode.INVALID_INPUT].message,
        })
      }

      // Attempt authentication
      const loginResult = await this.authService.login({
        email,
        password,
        mfaCode,
        deviceFingerprint,
        ipAddress,
      })

      // Create secure session
      await this.sessionManager.createSession(loginResult.user.id, {
        token: loginResult.token,
        fingerprint: loginResult.fingerprint,
        ipAddress,
      })

      // Track security metrics
      await this.securityMetrics.recordAuthAttempt(true, ipAddress)

      // Set secure cookie with session token
      res.cookie("session", loginResult.token, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 900000, // 15 minutes
      })

      return res.status(HttpStatus.OK).json({
        token: loginResult.token,
        fingerprint: loginResult.fingerprint,
        user: {
          id: loginResult.user.id,
          email: loginResult.user.email,
          role: loginResult.user.role,
        },
      })
    } catch (error) {
      await this.securityMetrics.recordAuthAttempt(false, req.ip || "")

      if (
        error instanceof Error &&
        error.message === ErrorCode.INVALID_CREDENTIALS
      ) {
        return res.status(HttpStatus.UNAUTHORIZED).json({
          error: ErrorMessage[ErrorCode.INVALID_CREDENTIALS].message,
        })
      }

      next(error)
      return
    }
  }

  /**
   * Handles secure user registration with enhanced validation
   */
  @Post("/register")
  @hipaaValidate()
  @middleware(REGISTRATION_LIMITER)
  @auditLog()
  public async register(
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
  ): Promise<Response | void> {
    try {
      const userData: IUser = req.body

      // Validate user data
      const validationResult = await validateUserData(userData, {
        validatePassword: true,
        checkMFA: true,
      })

      if (!validationResult.isValid) {
        return res.status(HttpStatus.BAD_REQUEST).json({
          error: ErrorMessage[ErrorCode.INVALID_INPUT].message,
          details: validationResult.errors,
        })
      }

      // Register user
      const registrationResult = await this.authService.register(userData)

      // Track registration metrics
      await this.securityMetrics.trackEvent({
        type: "USER_REGISTERED",
        userId: registrationResult.user.id,
        metadata: {
          ipAddress: req.ip,
        },
      })

      return res.status(HttpStatus.CREATED).json({
        token: registrationResult.token,
        fingerprint: registrationResult.fingerprint,
        user: {
          id: registrationResult.user.id,
          email: registrationResult.user.email,
          role: registrationResult.user.role,
        },
      })
    } catch (error) {
      await this.securityMetrics.trackEvent({
        type: "REGISTRATION_FAILURE",
        metadata: {
          error: error instanceof Error ? error.message : "Unknown error",
          ipAddress: req.ip,
        },
      })
      next(error)
      return
    }
  }

  /**
   * Handles secure token refresh with fingerprint validation
   */
  @Post("/refresh-token")
  @hipaaValidate()
  @auditLog()
  public async refreshToken(
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
  ): Promise<Response | void> {
    try {
      const { token } = req.body

      if (!token) {
        return res.status(HttpStatus.BAD_REQUEST).json({
          error: ErrorMessage[ErrorCode.INVALID_INPUT].message,
        })
      }

      const refreshResult = await this.authService.refreshToken(token)

      // Update session with new token
      await this.sessionManager.updateSession({
        token: refreshResult.token,
        fingerprint: refreshResult.fingerprint,
      })

      return res.status(HttpStatus.OK).json({
        token: refreshResult.token,
        fingerprint: refreshResult.fingerprint,
      })
    } catch (error) {
      next(error)
      return
    }
  }

  /**
   * Handles secure logout with session termination
   */
  @Post("/logout")
  @hipaaValidate()
  @auditLog()
  public async logout(
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
  ): Promise<Response | void> {
    try {
      const { token } = req.body

      if (!token) {
        return res.status(HttpStatus.BAD_REQUEST).json({
          error: ErrorMessage[ErrorCode.INVALID_INPUT].message,
        })
      }

      // Logout and invalidate session
      await this.authService.logout(token)
      await this.sessionManager.terminateSession(token)

      // Clear session cookie
      res.clearCookie("session")

      return res.status(HttpStatus.NO_CONTENT).send()
    } catch (error) {
      next(error)
      return
    }
  }

  @Get("/verify")
  @hipaaValidate()
  @auditLog()
  public async verifyToken(
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
  ): Promise<Response | void> {
    try {
      const token = req.headers.authorization?.split(" ")[1]

      if (!token) {
        return res.status(HttpStatus.BAD_REQUEST).json({
          error: ErrorMessage[ErrorCode.INVALID_INPUT].message,
        })
      }

      const isValid = await this.authService.validateToken(token)

      return res.status(HttpStatus.OK).json({ valid: isValid })
    } catch (error) {
      next(error)
      return
    }
  }
}

export default AuthController
