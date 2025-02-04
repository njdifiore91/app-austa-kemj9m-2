/**
 * @fileoverview Main entry point for AUSTA SuperApp API Gateway
 * Implements enterprise-grade API Gateway with HIPAA compliance, enhanced security,
 * comprehensive monitoring, and intelligent routing for microservices.
 *
 * @version 1.0.0
 */

import express from "express"
import morgan from "morgan"
import dotenv from "dotenv"
import { register, collectDefaultMetrics } from "prom-client"
import winston from "winston"
import { requestLogger, globalLogger } from "../../shared/middleware/logger"
import { EncryptionService } from "../../shared/utils/encryption.utils"
import { HttpStatus } from "../../shared/constants/http-status"
import { ErrorCode, ErrorMessage } from "../../shared/constants/error-codes"
import { kongConfig } from "./config/kong.config"
import corsMiddleware from "./middleware/cors"
import createRateLimiter from "./middleware/rate-limiter"
import securityMiddleware from "./middleware/security"

// Load environment variables
dotenv.config()

// Global constants
const PORT = process.env.PORT || 3000
const NODE_ENV = process.env.NODE_ENV || "development"
const API_VERSION = process.env.API_VERSION || "v1"

/**
 * Initializes Express server with enhanced security and monitoring
 */
async function initializeServer(): Promise<express.Express> {
  const app = express()

  // Initialize metrics collection
  collectDefaultMetrics()

  await setupMiddleware(app)
  await setupRoutes(app)

  return app
}

/**
 * Configures comprehensive middleware chain
 */
async function setupMiddleware(app: express.Express): Promise<void> {
  // Basic middleware
  app.use(express.json({ limit: "10mb" }))
  app.use(express.urlencoded({ extended: true, limit: "10mb" }))

  // Request logging with audit trail
  app.use(requestLogger)
  app.use(
    morgan("combined", {
      stream: { write: (message) => globalLogger.log("info", message) },
    })
  )

  // Security middleware chain
  app.use(securityMiddleware)
  app.use(corsMiddleware(NODE_ENV))
  app.use(
    createRateLimiter({
      redis: {
        nodes:
          kongConfig.plugins.rate_limiting.config.redis_cluster_addresses.map(
            (addr) => {
              const [host, port] = addr.split(":")
              return { host, port: parseInt(port) }
            }
          ),
        options: {
          clusterRetryStrategy: (times) => Math.min(times * 100, 3000),
          enableReadyCheck: true,
          maxRedirections: 16,
        },
      },
      limits: {
        standard: kongConfig.plugins.rate_limiting.config.minute.patient,
        premium: kongConfig.plugins.rate_limiting.config.minute.provider,
      },
      windowMs: 60000,
      fallbackStrategy: "STRICT",
      circuitBreaker: {
        timeout: 5000,
        resetTimeout: 30000,
        errorThreshold: 50,
      },
    })
  )
}

/**
 * Configures API routes with security and validation
 */
async function setupRoutes(app: express.Express): Promise<void> {
  // Health check endpoint
  app.get("/health", async (_req, res) => {
    res.status(HttpStatus.OK).json({ status: "ok" })
  })

  // Metrics endpoint
  app.get("/metrics", async (_req, res) => {
    res.set("Content-Type", register.contentType)
    res.end(await register.metrics())
  })

  // API version prefix
  const apiRouter = express.Router()
  app.use(`/api/${API_VERSION}`, apiRouter)

  // Configure service routes
  Object.entries(kongConfig.routes).forEach(([service, config]) => {
    const serviceRouter = express.Router()

    // Apply service-specific middleware
    if (service === "health-records" || service === "claims") {
      serviceRouter.use((req, res, next) => {
        const winstonLogger = winston.createLogger({
          level: "info",
          format: winston.format.json(),
          transports: [new winston.transports.Console()],
        })

        const encryptionService = new EncryptionService(
          {
            region: process.env.AWS_REGION!,
            keyId: process.env.KMS_KEY_ID!,
            endpoint: process.env.KMS_ENDPOINT!,
            keyRotationInterval: 86400000,
            cacheTimeout: 3600,
          },
          winstonLogger
        )

        // Check if the request body is encrypted
        encryptionService
          .encryptField(JSON.stringify(req.body), service)
          .then(() => next())
          .catch(() =>
            res.status(HttpStatus.FORBIDDEN).json({
              error: ErrorCode.HIPAA_VIOLATION,
              message: ErrorMessage[ErrorCode.HIPAA_VIOLATION].message,
            })
          )
      })
    }

    // Mount service routes
    apiRouter.use(config.paths[0], serviceRouter)
  })

  // Error handling
  app.use(
    (
      _req: express.Request,
      res: express.Response,
      _next: express.NextFunction
    ) => {
      res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
        error: ErrorCode.INTERNAL_SERVER_ERROR,
        message: ErrorMessage[ErrorCode.INTERNAL_SERVER_ERROR].message,
      })
    }
  )
}

/**
 * Starts the server with comprehensive monitoring
 */
async function startServer(app: express.Express): Promise<void> {
  try {
    const server = app.listen(PORT, () => {
      globalLogger.log("info", `API Gateway started`, {
        port: PORT,
        environment: NODE_ENV,
        apiVersion: API_VERSION,
      })
    })

    // Graceful shutdown
    process.on("SIGTERM", () => {
      globalLogger.log(
        "info",
        "Received SIGTERM signal, initiating graceful shutdown"
      )
      server.close(() => {
        globalLogger.log("info", "Server shutdown completed")
        process.exit(0)
      })
    })
  } catch (error) {
    globalLogger.log("error", "Failed to start server", { error })
    process.exit(1)
  }
}

// Initialize and start server
;(async () => {
  try {
    const app = await initializeServer()
    await startServer(app)
  } catch (error) {
    globalLogger.log("error", "Failed to start server", { error })
    process.exit(1)
  }
})()

export default initializeServer
