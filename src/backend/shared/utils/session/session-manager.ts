/**
 * @fileoverview Session management utility with security features
 */

import { Session } from "express-session"
import Redis from "ioredis"

export class SessionManager {
  private redisClient: Redis

  constructor() {
    this.redisClient = new Redis({
      host: process.env.REDIS_HOST || "localhost",
      port: parseInt(process.env.REDIS_PORT || "6379", 10),
      password: process.env.REDIS_PASSWORD,
      tls: process.env.REDIS_TLS === "true" ? {} : undefined,
    })
  }

  /**
   * Create a new session
   * @param userId User ID
   * @param metadata Session metadata
   */
  async createSession(
    userId: string,
    metadata: Record<string, unknown>
  ): Promise<string> {
    const sessionId = `session:${userId}:${Date.now()}`
    await this.redisClient.hmset(sessionId, {
      userId,
      ...metadata,
      createdAt: Date.now(),
    })
    await this.redisClient.expire(sessionId, 3600) // 1 hour expiry
    return sessionId
  }

  /**
   * Validate session
   * @param sessionId Session ID
   */
  async validateSession(sessionId: string): Promise<boolean> {
    return (await this.redisClient.exists(sessionId)) === 1
  }

  /**
   * Invalidate session
   * @param sessionId Session ID
   */
  async invalidateSession(sessionId: string): Promise<void> {
    await this.redisClient.del(sessionId)
  }

  /**
   * Update session metadata
   * @param sessionId Session ID
   * @param metadata New metadata
   */
  async updateSessionMetadata(
    sessionId: string,
    metadata: Record<string, unknown>
  ): Promise<void> {
    await this.redisClient.hmset(sessionId, metadata)
  }
}
