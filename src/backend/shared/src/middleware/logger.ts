/**
 * @fileoverview Enhanced logging middleware with HIPAA compliance, security features, and performance monitoring
 * @version 1.0.0
 */

import winston from 'winston';
import { Request, Response, NextFunction } from 'express';
import morgan from 'morgan';
import { AsyncLocalStorage } from 'async_hooks';
import { v4 as uuidv4 } from 'uuid';

// Security patterns for PHI/PII detection and masking
const PHI_PATTERNS = new Map([
  ['SSN', /\b\d{3}[-]?\d{2}[-]?\d{4}\b/g],
  ['MRN', /\b\d{8}\b/g],
  ['EMAIL', /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g],
  ['PHONE', /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g],
  ['DOB', /\b\d{2}[-/]\d{2}[-/]\d{4}\b/g]
]);

// Logger configuration interface
interface LoggerOptions {
  level: string;
  format?: winston.Logform.Format;
  transports?: winston.transport[];
  securityOptions: {
    enablePHIMasking: boolean;
    enableAuditLog: boolean;
    encryptionKey?: string;
  };
}

// Context metadata interface
interface LogContext {
  correlationId: string;
  requestId?: string;
  userId?: string;
  sessionId?: string;
  timestamp: number;
  source: string;
}

/**
 * Enhanced Logger class with security and monitoring features
 */
export class Logger {
  private readonly logger: winston.Logger;
  private readonly asyncLocalStorage: AsyncLocalStorage<string>;
  private readonly sensitiveFields: Set<string>;
  private readonly options: LoggerOptions;

  constructor(options?: Partial<LoggerOptions>) {
    this.options = {
      level: options?.level || 'info',
      format: options?.format,
      transports: options?.transports,
      securityOptions: {
        enablePHIMasking: options?.securityOptions?.enablePHIMasking ?? true,
        enableAuditLog: options?.securityOptions?.enableAuditLog ?? true,
        encryptionKey: options?.securityOptions?.encryptionKey
      }
    };

    this.logger = winston.createLogger({
      level: this.options.level,
      format: this.options.format || winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      ),
      defaultMeta: {
        service: 'austa-superapp'
      },
      transports: this.options.transports || [
        new winston.transports.Console({
          format: winston.format.combine(
            winston.format.colorize(),
            winston.format.simple()
          )
        }),
        new winston.transports.File({
          filename: 'error.log',
          level: 'error'
        }),
        new winston.transports.File({
          filename: 'combined.log'
        })
      ]
    });

    this.asyncLocalStorage = new AsyncLocalStorage<string>();
    this.sensitiveFields = new Set([
      'password',
      'token',
      'apiKey',
      'secret',
      'ssn',
      'creditCard',
      'phoneNumber',
      'email'
    ]);
  }

  /**
   * Masks sensitive data in objects
   */
  private maskSensitiveData(data: any): any {
    if (!data || !this.options.securityOptions.enablePHIMasking) return data;

    if (typeof data === 'object') {
      const maskedData: Record<string, any> = Array.isArray(data) ? [] : {};

      for (const [key, value] of Object.entries(data)) {
        if (this.sensitiveFields.has(key.toLowerCase())) {
          maskedData[key] = '********';
        } else if (typeof value === 'string') {
          let maskedValue = value;
          PHI_PATTERNS.forEach((pattern, type) => {
            maskedValue = maskedValue.replace(pattern, `[REDACTED ${type}]`);
          });
          maskedData[key] = maskedValue;
        } else if (typeof value === 'object') {
          maskedData[key] = this.maskSensitiveData(value);
        } else {
          maskedData[key] = value;
        }
      }

      return maskedData;
    }

    return data;
  }

  /**
   * Gets the current request ID from the async local storage
   */
  private getRequestId(): string {
    return this.asyncLocalStorage.getStore() || uuidv4();
  }

  /**
   * Creates log context for the current request
   */
  private createLogContext(meta?: Record<string, any>): LogContext {
    return {
      correlationId: this.getRequestId(),
      requestId: meta?.requestId,
      userId: meta?.userId,
      sessionId: meta?.sessionId,
      timestamp: Date.now(),
      source: meta?.source || 'application'
    };
  }

  /**
   * Logs an info message
   */
  public info(message: string, meta?: Record<string, any>): void {
    const context = this.createLogContext(meta);
    this.logger.info(message, {
      ...this.maskSensitiveData(meta),
      context
    });
  }

  /**
   * Logs a warning message
   */
  public warn(message: string, meta?: Record<string, any>): void {
    const context = this.createLogContext(meta);
    this.logger.warn(message, {
      ...this.maskSensitiveData(meta),
      context
    });
  }

  /**
   * Logs an error message
   */
  public error(message: string, meta?: Record<string, any>): void {
    const context = this.createLogContext(meta);
    this.logger.error(message, {
      ...this.maskSensitiveData(meta),
      context
    });
  }

  /**
   * Creates a request logging middleware
   */
  public createRequestLogger(): (req: Request & { id?: string; user?: { id: string }; session?: { id: string } }, res: Response, next: NextFunction) => void {
    return (req, res, next) => {
      const requestId = uuidv4();
      req.id = requestId;

      this.asyncLocalStorage.run(requestId, () => {
        const startTime = process.hrtime();

        // Log request
        this.info('Incoming request', {
          request: {
            id: requestId,
            method: req.method,
            url: req.url,
            userId: req.user?.id,
            sessionId: req.session?.id,
            ip: req.ip,
            userAgent: req.get('user-agent'),
            headers: this.maskSensitiveData(req.headers),
            query: this.maskSensitiveData(req.query),
            body: this.maskSensitiveData(req.body)
          }
        });

        // Log response
        res.on('finish', () => {
          const [seconds, nanoseconds] = process.hrtime(startTime);
          const duration = seconds * 1000 + nanoseconds / 1000000;

          this.info('Request completed', {
            response: {
              statusCode: res.statusCode,
              duration: `${duration.toFixed(2)}ms`
            },
            request: {
              id: requestId,
              method: req.method,
              url: req.url
            }
          });
        });

        next();
      });
    };
  }

  /**
   * Creates a Morgan HTTP request logger
   */
  public createHttpLogger() {
    return morgan((tokens, req, res) => {
      const requestId = this.getRequestId();
      const duration = tokens['response-time']?.(req, res);
      const message = [
        tokens.method?.(req, res),
        tokens.url?.(req, res),
        tokens.status?.(req, res),
        duration ? `${duration}ms` : '',
        `requestId=${requestId}`
      ].filter(Boolean).join(' ');

      this.info(message, {
        requestId,
        method: tokens.method?.(req, res),
        url: tokens.url?.(req, res),
        status: tokens.status?.(req, res),
        duration
      });

      return message;
    });
  }
}

// Export singleton instance
export const globalLogger = new Logger({
  securityOptions: {
    enablePHIMasking: true,
    enableAuditLog: true
  }
});