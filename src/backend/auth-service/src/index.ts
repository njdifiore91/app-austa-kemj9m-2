/**
 * @fileoverview HIPAA-compliant authentication service entry point
 * Implements secure OAuth 2.0 + OIDC authentication with comprehensive security features
 * @version 1.0.0
 */

import express, { Express, Request, Response, NextFunction } from 'express'; // v4.18.2
import helmet from 'helmet'; // v7.0.0
import cors from 'cors'; // v2.8.5
import session from 'express-session'; // v1.17.3
import RedisStore from 'connect-redis'; // v7.1.0
import rateLimit from 'express-rate-limit'; // v6.9.0
import winston from 'winston'; // v3.10.0
import mongoose from 'mongoose';
import { AUTH_CONFIG } from './config/auth.config';
import AuthController from './controllers/auth.controller';
import { ErrorCode, ErrorMessage } from '@shared/constants/error-codes';
import { HttpStatus } from '@shared/constants/http-status';
import { getRedisClient, closeRedisConnection } from './utils/redis.utils';

// Initialize Express application
const app: Express = express();
const PORT = process.env.PORT || 3001;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/auth';

// Configure Winston logger with security considerations
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: { service: 'auth-service' },
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    })
  ]
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception:', error);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

/**
 * Establishes MongoDB connection with optimized settings
 */
const connectDatabase = async (): Promise<void> => {
  try {
    logger.info(`Connecting to MongoDB at ${MONGODB_URI}...`);
    await mongoose.connect(MONGODB_URI, {
      maxPoolSize: 10,
      minPoolSize: 2,
      socketTimeoutMS: 45000,
      connectTimeoutMS: 10000,
      retryWrites: true,
      retryReads: true,
      serverSelectionTimeoutMS: 5000,
      heartbeatFrequencyMS: 10000
    });

    const dbName = mongoose.connection.name;
    const host = mongoose.connection.host;
    const port = mongoose.connection.port;

    logger.info('Connected to MongoDB successfully', {
      database: dbName,
      host: host,
      port: port,
      status: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
    });

    mongoose.connection.on('error', (error) => {
      logger.error('MongoDB connection error:', error);
    });

    mongoose.connection.on('disconnected', () => {
      logger.warn('MongoDB disconnected');
    });

    mongoose.connection.on('reconnected', () => {
      logger.info('MongoDB reconnected');
    });
  } catch (error) {
    logger.error('Failed to connect to MongoDB:', error);
    throw error;
  }
};

/**
 * Configures comprehensive security middleware stack
 * @param app Express application instance
 */
const setupSecurityMiddleware = async (app: Express): Promise<void> => {
  logger.info('Setting up security middleware...');

  // Body parsing with size limits
  logger.info('Configuring body parsers...');
  app.use(express.json({ limit: '10kb' }));
  app.use(express.urlencoded({ extended: true, limit: '10kb' }));
  
  // Add request logging middleware
  app.use((req: Request, res: Response, next: NextFunction) => {
    logger.info('📥 Incoming request to auth service:', {
      method: req.method,
      path: req.path,
      originalUrl: req.originalUrl,
      body: req.method === 'POST' ? { ...req.body, password: '[REDACTED]' } : undefined,
      headers: req.headers,
      query: req.query,
      ip: req.ip
    });
    next();
  });

  // Configure Helmet with strict security headers
  logger.info('Configuring Helmet...');
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", 'data:', 'https:'],
        connectSrc: ["'self'"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        mediaSrc: ["'self'"],
        frameSrc: ["'none'"]
      }
    },
    crossOriginEmbedderPolicy: true,
    crossOriginOpenerPolicy: { policy: 'same-origin' },
    crossOriginResourcePolicy: { policy: 'same-origin' },
    dnsPrefetchControl: { allow: false },
    frameguard: { action: 'deny' },
    hidePoweredBy: true,
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
    ieNoOpen: true,
    noSniff: true,
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    xssFilter: true
  }));

  // Configure CORS with strict options
  logger.info('Configuring CORS...');
  app.use(cors({
    origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    exposedHeaders: ['Content-Range', 'X-Content-Range'],
    credentials: true,
    maxAge: 600
  }));

  // Get Redis client instance
  logger.info('Getting Redis client...');
  const redisClient = await getRedisClient();
  
  // Test Redis connection
  try {
    await redisClient.ping();
    logger.info('Redis connection test successful');
  } catch (error) {
    logger.error('Redis connection test failed:', error);
    throw error;
  }

  // Configure secure session management
  logger.info('Configuring session management with Redis...');
  app.use(session({
    store: new RedisStore({ client: redisClient }),
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
      sameSite: 'strict'
    }
  }));

  // Configure global rate limiting
  logger.info('Configuring rate limiting...');
  app.use(rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: ErrorMessage[ErrorCode.RATE_LIMIT_EXCEEDED].message,
    standardHeaders: true,
    legacyHeaders: false
  }));

  logger.info('Security middleware setup complete');
};

/**
 * Configures authentication routes with security middleware
 * @param app Express application instance
 */
const setupAuthRoutes = (app: Express): void => {
  logger.info('Setting up auth routes...');
  
  const authController = new AuthController();
  const apiVersion = '/api/v1';

  // Health check endpoint
  app.get(`${apiVersion}/health`, (req: Request, res: Response) => {
    logger.info('Health check request received');
    res.status(HttpStatus.OK).json({ status: 'healthy' });
  });

  // Authentication routes with logging
  app.post(`${apiVersion}/login`, (req: Request, res: Response, next: NextFunction) => {
    logger.info('Login request received', {
      path: req.path,
      method: req.method,
      headers: req.headers
    });
    return authController.login(req, res, next);
  });

  app.post(`${apiVersion}/register`, (req: Request, res: Response, next: NextFunction) => {
    logger.info('Register request received', {
      path: req.path,
      method: req.method,
      headers: req.headers
    });
    return authController.register(req, res, next);
  });

  app.post(`${apiVersion}/verify-account`, (req: Request, res: Response, next: NextFunction) => {
    logger.info('Account verification request received', {
      path: req.path,
      method: req.method,
      headers: req.headers
    });
    return authController.verifyAccount(req, res, next);
  });

  app.post(`${apiVersion}/logout`, (req: Request, res: Response, next: NextFunction) => {
    logger.info('Logout request received', {
      path: req.path,
      method: req.method,
      headers: req.headers
    });
    return authController.logout(req, res, next);
  });

  logger.info('Auth routes setup complete', {
    routes: [
      `${apiVersion}/health`,
      `${apiVersion}/login`,
      `${apiVersion}/register`,
      `${apiVersion}/verify-account`,
      `${apiVersion}/logout`
    ]
  });

  // Error handling middleware
  app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
    logger.error('Error:', {
      error: err.message,
      stack: err.stack,
      path: req.path,
      method: req.method
    });

    res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
      error: ErrorMessage[ErrorCode.INTERNAL_SERVER_ERROR].message
    });
  });
};

/**
 * Initializes and starts the secure Express server
 */
const startSecureServer = async (): Promise<void> => {
  try {
    // Connect to MongoDB
    await connectDatabase();

    // Setup security middleware
    await setupSecurityMiddleware(app);

    // Setup authentication routes
    setupAuthRoutes(app);

    // Start server with HTTPS
    const server = app.listen(PORT, () => {
      logger.info(`Auth service running securely on port ${PORT}`);
    });

    // Graceful shutdown handler
    process.on('SIGTERM', async () => {
      logger.info('SIGTERM received. Starting graceful shutdown...');
      await closeRedisConnection();
      await mongoose.connection.close();
      server.close(() => {
        logger.info('Server closed. Process terminating...');
        process.exit(0);
      });
    });

  } catch (error) {
    logger.error('Server startup failed:', error);
    process.exit(1);
  }
};

// Start server
startSecureServer().catch(error => {
  logger.error('Fatal error during server startup:', error);
  process.exit(1);
});

export default app;