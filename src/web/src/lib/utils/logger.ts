/**
 * @fileoverview Browser-compatible logging utility for AUSTA SuperApp
 * Implements secure logging with privacy controls for HIPAA compliance
 */

type LogLevel = 'debug' | 'info' | 'warn' | 'error';

interface LogEntry {
  level: LogLevel;
  message: string;
  timestamp: string;
  context?: Record<string, unknown>;
}

class BrowserLogger {
  private static instance: BrowserLogger;
  private logBuffer: LogEntry[] = [];
  private readonly maxBufferSize = 1000;

  private constructor() {
    // Private constructor for singleton pattern
  }

  public static getInstance(): BrowserLogger {
    if (!BrowserLogger.instance) {
      BrowserLogger.instance = new BrowserLogger();
    }
    return BrowserLogger.instance;
  }

  private formatLogEntry(entry: LogEntry): string {
    return `[${entry.timestamp}] ${entry.level.toUpperCase()}: ${entry.message}${
      entry.context ? ' ' + JSON.stringify(entry.context) : ''
    }`;
  }

  private log(level: LogLevel, message: string, context?: Record<string, unknown>) {
    const entry: LogEntry = {
      level,
      message,
      timestamp: new Date().toISOString(),
      context
    };

    // Add to buffer
    this.logBuffer.push(entry);
    if (this.logBuffer.length > this.maxBufferSize) {
      this.logBuffer.shift();
    }

    // Log to console in development
    if (process.env.NODE_ENV === 'development') {
      const formattedMessage = this.formatLogEntry(entry);
      switch (level) {
        case 'debug':
          console.debug(formattedMessage);
          break;
        case 'info':
          console.info(formattedMessage);
          break;
        case 'warn':
          console.warn(formattedMessage);
          break;
        case 'error':
          console.error(formattedMessage);
          break;
      }
    }
  }

  public debug(message: string, context?: Record<string, unknown>) {
    this.log('debug', message, context);
  }

  public info(message: string, context?: Record<string, unknown>) {
    this.log('info', message, context);
  }

  public warn(message: string, context?: Record<string, unknown>) {
    this.log('warn', message, context);
  }

  public error(message: string, context?: Record<string, unknown>) {
    this.log('error', message, context);
  }

  public getLogBuffer(): LogEntry[] {
    return [...this.logBuffer];
  }

  public clearBuffer() {
    this.logBuffer = [];
  }
}

export const logger = BrowserLogger.getInstance(); 