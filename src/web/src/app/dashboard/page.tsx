'use client';

import React, { useEffect, useState, useCallback } from 'react';
import { Grid, Container, Typography, Skeleton } from '@mui/material'; // v5.0.0
import { useAuthContext } from '../../contexts/AuthContext';
import { ErrorBoundary } from 'react-error-boundary'; // v4.0.0
import { Analytics } from '../../lib/utils/analytics';
import { AccessLevel, ThemePreference } from '../../components/dashboard/types';
import { UserRole, UserStatus } from '../../lib/types/user';
import { AuthState } from '../../lib/types/auth';

// Internal components
import HealthMetrics from '../../components/dashboard/HealthMetrics';
import AppointmentCard from '../../components/dashboard/AppointmentCard';
import QuickActions from '../../components/dashboard/QuickActions';

// Hooks
import useAnalytics from '../../hooks/useAnalytics';

// Types
import { HealthRecordType, SecurityClassification } from '../../lib/types/healthRecord';
import { 
  IConsultation, 
  ConnectionQuality, 
  ConsultationType,
  ConsultationStatus 
} from '../../lib/types/consultation';
import { IUser } from '../../lib/types/auth';

// Constants for refresh intervals and security
const METRICS_REFRESH_INTERVAL = 30000; // 30 seconds
const APPOINTMENTS_REFRESH_INTERVAL = 60000; // 1 minute
const MAX_APPOINTMENTS_DISPLAY = 3;

// Mock data for development
const MOCK_METRICS = {
  vitals: {
    heartRate: { value: 75, unit: 'bpm', isNormal: true },
    bloodPressure: { systolic: 120, diastolic: 80, unit: 'mmHg', isNormal: true },
    temperature: { value: 98.6, unit: '°F', isNormal: true },
    oxygenSaturation: { value: 98, unit: '%', isNormal: true }
  },
  activity: {
    steps: 8432,
    caloriesBurned: 1250,
    activeMinutes: 45
  },
  medications: {
    adherenceRate: 95,
    nextDue: new Date(Date.now() + 3600000).toISOString(),
    missedDoses: 1
  },
  trends: {
    sleepQuality: [
      { date: '2024-03-01', value: 85 },
      { date: '2024-03-02', value: 90 },
      { date: '2024-03-03', value: 88 }
    ],
    stressLevel: [
      { date: '2024-03-01', value: 3 },
      { date: '2024-03-02', value: 2 },
      { date: '2024-03-03', value: 1 }
    ]
  }
};

const MOCK_APPOINTMENTS: IConsultation[] = [
  {
    id: '1',
    type: ConsultationType.VIDEO,
    patientId: 'patient123',
    providerId: 'provider1',
    scheduledStartTime: new Date(Date.now() + 86400000), // Tomorrow
    actualStartTime: null,
    endTime: null,
    status: ConsultationStatus.SCHEDULED,
    participants: [],
    healthRecordId: null,
    roomSid: null,
    metadata: {
      providerName: 'Dr. Sarah Johnson',
      providerSpecialty: 'Cardiologist',
      providerImageUrl: 'https://example.com/doctor1.jpg',
      notes: 'Regular checkup',
      location: 'Virtual'
    },
    securityMetadata: {},
    auditLog: [],
    isEmergency: false
  },
  {
    id: '2',
    type: ConsultationType.VIDEO,
    patientId: 'patient123',
    providerId: 'provider2',
    scheduledStartTime: new Date(Date.now() + 172800000), // Day after tomorrow
    actualStartTime: null,
    endTime: null,
    status: ConsultationStatus.SCHEDULED,
    participants: [],
    healthRecordId: null,
    roomSid: null,
    metadata: {
      providerName: 'Dr. Michael Chen',
      providerSpecialty: 'General Physician',
      providerImageUrl: 'https://example.com/doctor2.jpg',
      notes: 'Follow-up appointment',
      location: 'Main Clinic'
    },
    securityMetadata: {},
    auditLog: [],
    isEmergency: false
  },
  {
    id: '3',
    type: ConsultationType.VIDEO,
    patientId: 'patient123',
    providerId: 'provider3',
    scheduledStartTime: new Date(Date.now() + 259200000), // 3 days from now
    actualStartTime: null,
    endTime: null,
    status: ConsultationStatus.SCHEDULED,
    participants: [],
    healthRecordId: null,
    roomSid: null,
    metadata: {
      providerName: 'Dr. Emily Brown',
      providerSpecialty: 'Dermatologist',
      providerImageUrl: 'https://example.com/doctor3.jpg',
      notes: 'Skin condition review',
      location: 'Virtual'
    },
    securityMetadata: {},
    auditLog: [],
    isEmergency: false
  }
];

/**
 * Error Fallback component for graceful error handling
 */
const ErrorFallback: React.FC<{ error: Error }> = ({ error }) => (
  <Container>
    <Typography variant="h6" color="error" role="alert">
      An error occurred while loading the dashboard. Please try refreshing the page.
    </Typography>
  </Container>
);

/**
 * Main Dashboard Page Component
 * Implements HIPAA-compliant interface with role-based access control
 */
const DashboardPage: React.FC = () => {
  const { user, tokens } = useAuthContext();
  const { logEvent, logError } = useAnalytics();
  const [metrics, setMetrics] = useState<any>(MOCK_METRICS);
  const [appointments, setAppointments] = useState<IConsultation[]>(MOCK_APPOINTMENTS);
  const [loading, setLoading] = useState(true);
  const [refreshKey, setRefreshKey] = useState(0);

  // Security context for analytics and audit logging
  const securityContext = {
    sessionId: tokens?.accessToken || '',
    authToken: tokens?.accessToken || '',
    ipAddress: '[REDACTED]',
    deviceId: window.navigator.userAgent
  };

  /**
   * Fetches user metrics with security logging
   */
  const fetchUserMetrics = useCallback(async () => {
    // Simulating API call with mock data
    setMetrics(MOCK_METRICS);
    /* Commented out actual API call
    if (!user || !user._id) return;
    try {
      const response = await fetch(`/api/metrics/${user._id}`);
      if (!response.ok) {
        throw new Error('Failed to fetch metrics');
      }
      const data = await response.json();
      setMetrics(data);
    } catch (error) {
      logEvent({
        name: 'fetch_metrics_error',
        category: Analytics.AnalyticsCategory.ERROR,
        properties: {
          message: 'Failed to fetch user metrics',
          userId: user._id,
          error: error instanceof Error ? error.message : 'Unknown error'
        },
        timestamp: Date.now(),
        userConsent: true,
        privacyLevel: Analytics.PrivacyLevel.INTERNAL,
        auditInfo: {
          eventId: crypto.randomUUID(),
          timestamp: Date.now(),
          userId: user._id,
          ipAddress: '',
          actionType: 'API_ERROR'
        }
      });
    }
    */
  }, []);

  /**
   * Fetches user appointments with security logging
   */
  const fetchAppointments = useCallback(async () => {
    // Simulating API call with mock data
    setAppointments(MOCK_APPOINTMENTS);
    /* Commented out actual API call
    if (!user || !user._id) return;
    try {
      const response = await fetch(`/api/appointments/${user._id}`);
      if (!response.ok) {
        throw new Error('Failed to fetch appointments');
      }
      const data = await response.json();
      setAppointments(data);
    } catch (error) {
      logEvent({
        name: 'fetch_appointments_error',
        category: Analytics.AnalyticsCategory.ERROR,
        properties: {
          message: 'Failed to fetch appointments',
          userId: user._id,
          error: error instanceof Error ? error.message : 'Unknown error'
        },
        timestamp: Date.now(),
        userConsent: true,
        privacyLevel: Analytics.PrivacyLevel.INTERNAL,
        auditInfo: {
          eventId: crypto.randomUUID(),
          timestamp: Date.now(),
          userId: user._id,
          ipAddress: '',
          actionType: 'API_ERROR'
        }
      });
    }
    */
  }, []);

  /**
   * Handles secure data refresh with error boundary
   */
  const handleRefresh = useCallback(async () => {
    try {
      setRefreshKey(prev => prev + 1);
      await Promise.all([
        fetchUserMetrics(),
        fetchAppointments()
      ]);
      
      await logEvent({
        name: 'dashboard_refresh',
        category: Analytics.AnalyticsCategory.USER_INTERACTION,
        properties: {
          userId: user?._id,
          timestamp: Date.now()
        },
        timestamp: Date.now(),
        userConsent: true,
        privacyLevel: Analytics.PrivacyLevel.INTERNAL,
        auditInfo: {
          eventId: crypto.randomUUID(),
          timestamp: Date.now(),
          userId: user?._id || 'anonymous',
          ipAddress: '[REDACTED]',
          actionType: 'dashboard_refresh'
        }
      });
    } catch (error) {
      await logError(error as Error, {
        context: 'dashboard_refresh',
        userId: user?._id
      }, Analytics.PrivacyLevel.INTERNAL);
    }
  }, [user, logEvent, logError, fetchUserMetrics, fetchAppointments]);

  /**
   * Handles appointment updates with security logging
   */
  const handleAppointmentUpdate = async (appointment: IConsultation) => {
    // Simulating API call with local state update
    const updatedAppointments = appointments.map(app => 
      app.id === appointment.id ? appointment : app
    );
    setAppointments(updatedAppointments);
    /* Commented out actual API call
    if (!user || !user._id) return;
    try {
      const response = await fetch(`/api/appointments/${appointment.id}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${tokens?.accessToken}`
        },
        body: JSON.stringify(appointment)
      });

      if (!response.ok) {
        throw new Error('Failed to update appointment');
      }

      await fetchAppointments();
    } catch (error) {
      logEvent({
        name: 'update_appointment_error',
        category: Analytics.AnalyticsCategory.ERROR,
        properties: {
          message: 'Failed to update appointment',
          userId: user._id,
          appointmentId: appointment.id,
          error: error instanceof Error ? error.message : 'Unknown error'
        },
        timestamp: Date.now(),
        userConsent: true,
        privacyLevel: Analytics.PrivacyLevel.INTERNAL,
        auditInfo: {
          eventId: crypto.randomUUID(),
          timestamp: Date.now(),
          userId: user._id,
          ipAddress: '',
          actionType: 'API_ERROR'
        }
      });
    }
    */
  };

  // Track initial dashboard load
  useEffect(() => {
    const trackPageView = async () => {
      try {
        await Promise.all([
          fetchUserMetrics(),
          fetchAppointments()
        ]);

        await logEvent({
          name: 'dashboard_view',
          category: Analytics.AnalyticsCategory.USER_INTERACTION,
          properties: {
            userId: user?._id,
            userRole: user?.role,
            timestamp: Date.now()
          },
          timestamp: Date.now(),
          userConsent: true,
          privacyLevel: Analytics.PrivacyLevel.INTERNAL,
          auditInfo: {
            eventId: crypto.randomUUID(),
            timestamp: Date.now(),
            userId: user?._id || 'anonymous',
            ipAddress: '[REDACTED]',
            actionType: 'page_view'
          }
        });
        setLoading(false);
      } catch (error) {
        await logError(error as Error, {
          context: 'dashboard_view',
          userId: user?._id
        }, Analytics.PrivacyLevel.INTERNAL);
      }
    };

    // Simulate initial load delay
    setTimeout(() => {
      trackPageView();
    }, 1000);
  }, [user, logEvent, logError, fetchUserMetrics, fetchAppointments]);

  // Setup automatic refresh intervals
  useEffect(() => {
    const metricsInterval = setInterval(handleRefresh, METRICS_REFRESH_INTERVAL);
    const appointmentsInterval = setInterval(handleRefresh, APPOINTMENTS_REFRESH_INTERVAL);

    return () => {
      clearInterval(metricsInterval);
      clearInterval(appointmentsInterval);
    };
  }, [handleRefresh]);

  // Show loading state
  if (loading) {
    return (
      <Container>
        <Grid container spacing={3}>
          <Grid item xs={12}>
            <Skeleton variant="rectangular" height={200} />
          </Grid>
          <Grid item xs={12} md={6}>
            <Skeleton variant="rectangular" height={300} />
          </Grid>
          <Grid item xs={12} md={6}>
            <Skeleton variant="rectangular" height={300} />
          </Grid>
        </Grid>
      </Container>
    );
  }

  return (
    <ErrorBoundary FallbackComponent={ErrorFallback}>
      <Container>
        <Grid container spacing={3}>
          <Grid item xs={12}>
            <Typography variant="h4" component="h1" gutterBottom>
              Welcome back, {user?.profile?.firstName} {user?.profile?.lastName}
            </Typography>
          </Grid>
          
          <Grid item xs={12} md={8}>
            <HealthMetrics 
              patientId={user?._id || ''}
              refreshInterval={METRICS_REFRESH_INTERVAL}
              showHistory={true}
              encryptionKey={tokens?.accessToken || ''}
              accessLevel={AccessLevel.READ}
              theme={ThemePreference.LIGHT}
            />
          </Grid>
          
          <Grid item xs={12} md={4}>
            <QuickActions 
              userRole={user?.role as UserRole}
              securityContext={securityContext}
            />
          </Grid>
          
          <Grid item xs={12}>
            <Typography variant="h6" gutterBottom>
              Upcoming Appointments
            </Typography>
            <Grid container spacing={2}>
              {appointments.slice(0, MAX_APPOINTMENTS_DISPLAY).map(appointment => {
                // Extract provider info from metadata
                const providerName = appointment.metadata?.providerName as string || '';
                const [title, firstName, ...lastNameParts] = providerName.split(' ');
                const lastName = lastNameParts.join(' ');

                return (
                  <Grid item xs={12} md={4} key={appointment.id}>
                    <AppointmentCard
                      appointment={appointment}
                      provider={{
                        id: appointment.providerId,
                        email: `${firstName.toLowerCase()}.${lastName.toLowerCase()}@example.com`,
                        role: UserRole.PROVIDER,
                        profile: {
                          firstName,
                          lastName,
                          dateOfBirth: new Date('1980-01-01'),
                          gender: 'NOT_SPECIFIED',
                          phoneNumber: '+1234567890',
                          address: {
                            street: '123 Medical Center Dr',
                            city: 'Healthcare City',
                            state: 'HC',
                            country: 'USA',
                            addressType: 'WORK',
                            isVerified: true,
                            zipCode: '12345'
                          },
                          emergencyContact: {
                            name: 'Emergency Contact',
                            relationship: 'Professional',
                            phoneNumber: '+1987654321',
                            email: 'emergency@example.com',
                            isVerified: true,
                            lastVerifiedAt: new Date()
                          },
                          preferredLanguage: 'en',
                          communicationPreferences: ['EMAIL', 'SMS'],
                          profileCompleteness: 100
                        },
                        status: UserStatus.ACTIVE,
                        createdAt: new Date(),
                        updatedAt: new Date(),
                        lastAuditAt: new Date(),
                        consentHistory: [],
                        securitySettings: {
                          mfaEnabled: true,
                          mfaMethod: 'APP',
                          lastPasswordChange: new Date(),
                          passwordResetRequired: false,
                          loginAttempts: 0,
                          lastLoginAt: new Date(),
                          securityQuestions: [],
                          deviceTrust: [],
                          ipWhitelist: []
                        }
                      }}
                      onJoin={async (appointmentId) => {
                        console.log('Joining appointment:', appointmentId);
                      }}
                      onCancel={async (appointmentId) => {
                        console.log('Cancelling appointment:', appointmentId);
                      }}
                      onReschedule={async (appointmentId) => {
                        console.log('Rescheduling appointment:', appointmentId);
                      }}
                      connectionConfig={{
                        minQuality: ConnectionQuality.FAIR,
                        checkInterval: 10000
                      }}
                    />
                  </Grid>
                );
              })}
            </Grid>
          </Grid>
        </Grid>
      </Container>
    </ErrorBoundary>
  );
};

export default DashboardPage;