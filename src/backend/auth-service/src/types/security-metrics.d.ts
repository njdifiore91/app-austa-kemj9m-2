declare module '@austa/security-metrics' {
  export interface SecurityEvent {
    type: string;
    userId?: string;
    metadata?: Record<string, any>;
  }

  export class SecurityMetrics {
    trackEvent(event: SecurityEvent): Promise<void>;
  }
} 