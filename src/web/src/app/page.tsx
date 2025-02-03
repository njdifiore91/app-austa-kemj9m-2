'use client';

import React, { useEffect, Suspense } from 'react';
import { useRouter } from 'next/navigation';
import { Grid, Container, Typography } from '@mui/material';
import Analytics from '@vercel/analytics';
import { useAuthContext } from '../contexts/AuthContext';
import HealthMetrics from '../components/dashboard/HealthMetrics';
import { AccessLevel, ThemePreference } from '../components/dashboard/types';
import QuickActions from '../components/dashboard/QuickActions';
import { UserRole } from '../lib/types/user';

// Constants
const REFRESH_INTERVAL = 30000; // 30 seconds

export default function HomePage() {
  const auth = useAuthContext();
  const router = useRouter();

  useEffect(() => {
    if (!auth.state || auth.state === 'UNAUTHENTICATED') {
      router.push('/auth/login');
      return;
    }

    // Track secure page view
    Analytics.track('page_view', {
      page: 'dashboard',
      userRole: auth.user?.role || 'UNAUTHENTICATED',
      timestamp: Date.now(),
      isAuthenticated: auth.state === 'AUTHENTICATED'
    });
  }, [auth.state, auth.user?.role, router]);

  // Security context for components
  const securityContext = {
    sessionId: auth.user?.id || '',
    authToken: auth.user?.securitySettings?.lastLoginAt.toString() || '',
    ipAddress: 'masked',
    deviceId: auth.user?.securitySettings?.deviceTrust?.[0]?.deviceId || ''
  };

  if (!auth.user?.role) {
    return null;
  }

  return (
    <Container maxWidth="xl" role="main">
      <Grid 
        container 
        spacing={3} 
        sx={{ mt: 3 }}
        role="region"
        aria-label="Dashboard content"
      >
        {/* Welcome Section */}
        <Grid item xs={12}>
          <Typography 
            variant="h1" 
            component="h1"
            gutterBottom
            aria-label="Welcome message"
          >
            Welcome, {auth.user.profile.firstName}
          </Typography>
        </Grid>

        {/* Quick Actions Section */}
        <Grid item xs={12}>
          <Suspense fallback={<div>Loading actions...</div>}>
            <QuickActions
              userRole={auth.user.role}
              securityContext={securityContext}
            />
          </Suspense>
        </Grid>

        {/* Health Metrics Section - Only for patients and providers */}
        {(auth.user.role === UserRole.PATIENT || auth.user.role === UserRole.PROVIDER) && (
          <Grid item xs={12}>
            <Suspense fallback={<div>Loading health metrics...</div>}>
              <HealthMetrics
                patientId={auth.user.id}
                refreshInterval={REFRESH_INTERVAL}
                showHistory={true}
                encryptionKey={auth.user.securitySettings?.lastLoginAt.toString() || ''}
                accessLevel={AccessLevel.READ}
                theme={ThemePreference.LIGHT}
              />
            </Suspense>
          </Grid>
        )}

        {/* Role-specific Content */}
        <Grid item xs={12}>
          {auth.user.role === UserRole.ADMIN && (
            <Typography variant="h2" component="h2">
              System Overview
            </Typography>
          )}
          {auth.user.role === UserRole.INSURANCE && (
            <Typography variant="h2" component="h2">
              Claims Dashboard
            </Typography>
          )}
        </Grid>
      </Grid>
    </Container>
  );
}