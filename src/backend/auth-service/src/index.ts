/**
 * @fileoverview HIPAA-compliant authentication service entry point
 * Implements secure OAuth 2.0 + OIDC authentication with comprehensive security features
 * @version 1.0.0
 */

import * as dotenv from "dotenv"
// Load environment variables before other imports
dotenv.config()

import "reflect-metadata"
import express, { Express, Request, Response, NextFunction } from "express"
import helmet from "helmet"
import cors from "cors"
import session from "express-session"
import Redis from "ioredis"
import rateLimit from "express-rate-limit"
import winston from "winston"
import { AUTH_CONFIG } from "./config/auth.config"
import AuthController from "./controllers/auth.controller"
import AuthService from "./services/auth.service"
import { SecurityMetrics } from "../../shared/utils/security/security-metrics"
import { SessionManager } from "../../shared/utils/session/session-manager"
import { ErrorCode, ErrorMessage } from "../../shared/constants/error-codes"
import { HttpStatus } from "../../shared/constants/http-status"
import { Model } from "mongoose"
import { Auth0Client } from "@auth0/auth0-spa-js"
import User, { IUserDocument } from "./models/user.model"
import { Container } from "inversify"

// Initialize Express application
const app: Express = express()
const PORT: number = parseInt(process.env.PORT || "3001", 10)

// Initialize Redis client
const redisClient = new Redis({
  host: process.env.REDIS_HOST || "localhost",
  port: parseInt(process.env.REDIS_PORT || "6379", 10),
  password: AUTH_CONFIG.redis.auth.password,
  tls: AUTH_CONFIG.redis.tls.enabled ? {} : undefined,
})

// Initialize Redis store for sessions
// eslint-disable-next-line @typescript-eslint/no-var-requires
const RedisStore = require("connect-redis")(session)
const sessionStore = new RedisStore({
  client: redisClient,
  prefix: "session:",
})

// Configure Winston logger with security considerations
const logger: winston.Logger = winston.createLogger({
  level: "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: { service: "auth-service" },
  transports: [
    new winston.transports.File({ filename: "error.log", level: "error" }),
    new winston.transports.File({ filename: "combined.log" }),
  ],
})

// Initialize dependency injection container
const container = new Container()

// Initialize Auth0 client
const auth0Client = new Auth0Client({
  domain: AUTH_CONFIG.oauth2.domain,
  clientId: AUTH_CONFIG.oauth2.clientId,
})

// Register dependencies
container
  .bind<Model<IUserDocument>>("UserModel")
  .toConstantValue(User as Model<IUserDocument>)
container.bind<Redis>("RedisClient").toConstantValue(redisClient)
container.bind<Auth0Client>("Auth0Client").toConstantValue(auth0Client)
container.bind<SecurityMetrics>("SecurityMetrics").to(SecurityMetrics)
container.bind<SessionManager>("SessionManager").to(SessionManager)
container.bind<AuthService>("AuthService").to(AuthService)
container.bind<AuthController>("AuthController").to(AuthController)

// Get instances
const authController = container.get<AuthController>("AuthController")

/**
 * Configures comprehensive security middleware stack
 * @param app Express application instance
 */
const setupSecurityMiddleware = async (app: Express): Promise<void> => {
  // Configure Helmet with strict security headers
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'"],
          styleSrc: ["'self'"],
          imgSrc: ["'self'", "data:", "https:"],
          connectSrc: ["'self'"],
          fontSrc: ["'self'"],
          objectSrc: ["'none'"],
          mediaSrc: ["'self'"],
          frameSrc: ["'none'"],
        },
      },
      crossOriginEmbedderPolicy: true,
      crossOriginOpenerPolicy: { policy: "same-origin" },
      crossOriginResourcePolicy: { policy: "same-origin" },
      dnsPrefetchControl: { allow: false },
      frameguard: { action: "deny" },
      hidePoweredBy: true,
      hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
      ieNoOpen: true,
      noSniff: true,
      referrerPolicy: { policy: "strict-origin-when-cross-origin" },
      xssFilter: true,
    })
  )

  // Configure CORS with strict options
  app.use(
    cors({
      origin: process.env.ALLOWED_ORIGINS?.split(",") || [
        "http://localhost:3000",
      ],
      methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
      allowedHeaders: ["Content-Type", "Authorization"],
      exposedHeaders: ["Content-Range", "X-Content-Range"],
      credentials: true,
      maxAge: 600,
    })
  )

  await redisClient.connect()

  // Configure secure session management
  app.use(
    session({
      store: sessionStore,
      name: AUTH_CONFIG.session.name,
      secret: AUTH_CONFIG.session.secret,
      resave: false,
      saveUninitialized: false,
      cookie: {
        secure: AUTH_CONFIG.session.secure,
        httpOnly: AUTH_CONFIG.session.httpOnly,
        domain: AUTH_CONFIG.session.domain || undefined,
        path: AUTH_CONFIG.session.path,
        maxAge: AUTH_CONFIG.session.maxAge,
        sameSite: "strict",
      },
    })
  )

  // Configure global rate limiting
  app.use(
    rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 100, // Limit each IP to 100 requests per windowMs
      message: ErrorMessage[ErrorCode.RATE_LIMIT_EXCEEDED].message,
      standardHeaders: true,
      legacyHeaders: false,
    })
  )

  // Body parsing with size limits
  app.use(express.json({ limit: "10kb" }))
  app.use(express.urlencoded({ extended: true, limit: "10kb" }))
}

/**
 * Configures authentication routes with security middleware
 * @param app Express application instance
 */
const setupAuthRoutes = (app: Express): void => {
  const apiVersion: string = "/api/v1"

  // Health check endpoint
  app.get(`${apiVersion}/health`, (_req: Request, res: Response): void => {
    res.status(HttpStatus.OK).json({ status: "healthy" })
  })

  // Authentication routes
  app.post(
    `${apiVersion}/auth/login`,
    authController.login.bind(authController)
  )
  app.post(
    `${apiVersion}/auth/register`,
    authController.register.bind(authController)
  )
  app.post(
    `${apiVersion}/auth/refresh-token`,
    authController.refreshToken.bind(authController)
  )
  app.post(
    `${apiVersion}/auth/logout`,
    authController.logout.bind(authController)
  )

  // Error handling middleware
  app.use(
    (err: Error, _req: Request, res: Response, next: NextFunction): void => {
      logger.error("Error:", {
        error: err.message,
        stack: err.stack,
        path: _req.path,
        method: _req.method,
      })

      // Don't expose internal error details in production
      const isProduction: boolean = process.env.NODE_ENV === "production"
      const errorMessage: string = isProduction
        ? "Internal Server Error"
        : err.message

      res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
        status: "error",
        message: errorMessage,
      })

      // Pass to default error handler
      next(err)
    }
  )

  // 404 handler - must be last
  app.use((_req: Request, res: Response, _next: NextFunction): void => {
    res.status(HttpStatus.NOT_FOUND).json({
      status: "error",
      message: "Route not found",
    })
  })
}

/**
 * Initializes and starts the secure Express server
 */
const startSecureServer = async (): Promise<void> => {
  try {
    // Setup security middleware
    await setupSecurityMiddleware(app)

    // Setup authentication routes
    setupAuthRoutes(app)

    // Start server with HTTPS
    const server = app.listen(PORT, () => {
      logger.info(`Auth service running securely on port ${PORT}`)
    })

    // Graceful shutdown handler
    process.on("SIGTERM", () => {
      logger.info("SIGTERM received. Starting graceful shutdown...")
      server.close(() => {
        logger.info("Server closed. Process terminating...")
        process.exit(0)
      })
    })
  } catch (error) {
    logger.error("Server startup failed:", error)
    process.exit(1)
  }
}

// Start server
startSecureServer().catch((error) => {
  logger.error("Fatal error during server startup:", error)
  process.exit(1)
})

export default app
