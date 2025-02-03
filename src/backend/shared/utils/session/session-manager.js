"use strict";
/**
 * @fileoverview Session management utility with security features
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.SessionManager = void 0;
const ioredis_1 = __importDefault(require("ioredis"));
class SessionManager {
    constructor() {
        this.redisClient = new ioredis_1.default({
            host: process.env.REDIS_HOST || "localhost",
            port: parseInt(process.env.REDIS_PORT || "6379", 10),
            password: process.env.REDIS_PASSWORD,
            tls: process.env.REDIS_TLS === "true" ? {} : undefined,
        });
    }
    /**
     * Create a new session
     * @param userId User ID
     * @param metadata Session metadata
     */
    async createSession(userId, metadata) {
        const sessionId = `session:${userId}:${Date.now()}`;
        await this.redisClient.hmset(sessionId, {
            userId,
            ...metadata,
            createdAt: Date.now(),
        });
        await this.redisClient.expire(sessionId, 3600); // 1 hour expiry
        return sessionId;
    }
    /**
     * Validate session
     * @param sessionId Session ID
     */
    async validateSession(sessionId) {
        return (await this.redisClient.exists(sessionId)) === 1;
    }
    /**
     * Invalidate session
     * @param sessionId Session ID
     */
    async invalidateSession(sessionId) {
        await this.redisClient.del(sessionId);
    }
    /**
     * Update session metadata
     * @param sessionId Session ID
     * @param metadata New metadata
     */
    async updateSessionMetadata(sessionId, metadata) {
        await this.redisClient.hmset(sessionId, metadata);
    }
}
exports.SessionManager = SessionManager;
