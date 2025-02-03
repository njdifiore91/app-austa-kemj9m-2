'use client';

import React from 'react';
import { ThemeProvider } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import { ErrorBoundary } from 'react-error-boundary';
import { AuthProvider } from '../../contexts/AuthContext';
import theme from '../../styles/theme';

interface ClientProvidersProps {
  children: React.ReactNode;
}

const ErrorFallbackComponent: React.FC<{ error: Error }> = ({ error }) => (
  <div role="alert">
    <h1>Critical System Error</h1>
    <p>Please contact emergency support immediately.</p>
    <p>Error Reference: {error.message}</p>
  </div>
);

export const ClientProviders: React.FC<ClientProvidersProps> = ({ children }) => {
  return (
    <ErrorBoundary FallbackComponent={ErrorFallbackComponent}>
      <ThemeProvider theme={theme}>
        <CssBaseline />
        <AuthProvider>
          {children}
        </AuthProvider>
      </ThemeProvider>
    </ErrorBoundary>
  );
};

export default ClientProviders; 