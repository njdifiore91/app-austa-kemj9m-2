declare module '@austa/session-manager' {
  export interface SessionData {
    userId: string;
    token: string;
    fingerprint: string;
    ipAddress?: string;
  }

  export class SessionManager {
    createSession(data: SessionData): Promise<void>;
    updateSession(data: Partial<SessionData>): Promise<void>;
    destroySession(token: string): Promise<void>;
  }
} 