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
   * @param metadata New metadata
   */
  async updateSession(metadata: Record<string, unknown>): Promise<void> {
    const token = metadata.token as string
    if (!token) {
      throw new Error("Token is required for session update")
    }
    const sessionId = await this.getSessionIdFromToken(token)
    if (sessionId) {
      await this.redisClient.hmset(sessionId, metadata)
    }
  }

  /**
   * Terminate session by token
   * @param token Session token
   */
  async terminateSession(token: string): Promise<void> {
    const sessionId = await this.getSessionIdFromToken(token)
    if (sessionId) {
      await this.invalidateSession(sessionId)
    }
  }

  /**
   * Get session ID from token
   * @param token Session token
   */
  private async getSessionIdFromToken(token: string): Promise<string | null> {
    // Implementation would depend on how you store the token-to-session mapping
    // This is a placeholder implementation
    const sessions = await this.redisClient.keys("session:*")
    for (const sessionId of sessions) {
      const sessionToken = await this.redisClient.hget(sessionId, "token")
      if (sessionToken === token) {
        return sessionId
      }
    }
    return null
  }
}
