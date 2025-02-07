import { createClient, RedisClientType } from 'redis';
import { AUTH_CONFIG } from '../config/auth.config';
import winston from 'winston';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: { service: 'auth-service:redis' },
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    })
  ]
});

let redisClient: RedisClientType | null = null;

export const getRedisClient = async (): Promise<RedisClientType> => {
  if (redisClient) {
    return redisClient;
  }

  logger.info('Initializing Redis client...');
  
  const redisUrl = process.env.REDIS_URL || 'redis://localhost:6379';
  const redisPassword = process.env.REDIS_PASSWORD || 'redis-password';
  const redisUsername = process.env.REDIS_USERNAME || 'default';
  
  logger.info(`Connecting to Redis at ${redisUrl} with username ${redisUsername}`);
  
  redisClient = createClient({
    url: redisUrl,
    username: redisUsername,
    password: redisPassword,
    socket: {
      reconnectStrategy: (retries) => {
        logger.info(`Reconnecting to Redis (attempt ${retries})...`);
        return Math.min(retries * 100, 3000);
      },
      connectTimeout: 10000,
    },
    ...(process.env.NODE_ENV === 'production' ? {
      socket: {
        tls: AUTH_CONFIG.redis.tls.enabled,
        rejectUnauthorized: true
      }
    } : {})
  });

  redisClient.on('error', (err) => {
    logger.error('Redis connection error:', err);
  });

  redisClient.on('connect', () => {
    logger.info('Redis client connecting...');
  });

  redisClient.on('ready', () => {
    logger.info('Redis client ready');
  });

  redisClient.on('reconnecting', () => {
    logger.info('Redis client reconnecting...');
  });

  redisClient.on('end', () => {
    logger.info('Redis client connection ended');
  });

  try {
    logger.info('Attempting to connect to Redis...');
    await redisClient.connect();
    
    // Test the connection
    await redisClient.ping();
    logger.info('Connected to Redis successfully');
    
    return redisClient;
  } catch (error) {
    logger.error('Failed to connect to Redis:', error);
    if (redisClient) {
      await redisClient.quit().catch(() => {});
      redisClient = null;
    }
    throw error;
  }
};

export const closeRedisConnection = async (): Promise<void> => {
  if (redisClient) {
    try {
      await redisClient.quit();
      redisClient = null;
      logger.info('Redis connection closed');
    } catch (error) {
      logger.error('Error closing Redis connection:', error);
      throw error;
    }
  }
}; 