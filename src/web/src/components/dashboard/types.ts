export enum AccessLevel {
  READ = 'read',
  WRITE = 'write',
  ADMIN = 'admin'
}

export enum ThemePreference {
  LIGHT = 'light',
  DARK = 'dark',
  HIGH_CONTRAST = 'high-contrast'
}

export interface HealthMetricsProps {
  patientId: string;
  refreshInterval?: number;
  showHistory?: boolean;
  encryptionKey: string;
  accessLevel: AccessLevel;
  theme: ThemePreference;
} 