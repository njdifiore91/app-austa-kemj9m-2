'use client';

import React from 'react'; // ^18.2.0
import styled from '@emotion/styled'; // ^11.11.0
import { Alert, Button, Typography, Box, Theme } from '@mui/material'; // ^5.0.0
import { Analytics } from '../../lib/utils/analytics';
import { theme } from '../../styles/theme';
import Loader from './Loader';

// Styled components for error UI
const ErrorContainer = styled(Box)`
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: ${theme.spacing(3)};
  text-align: center;
  min-height: 200px;
  width: 100%;
`;

const ErrorMessage = styled(Typography)`
  margin: ${theme.spacing(2, 0)};
`;

// Interface definitions
interface ErrorBoundaryProps {
  children: React.ReactNode;
  fallback?: React.ReactNode;
  onError?: (error: Error, errorInfo: React.ErrorInfo, context: Record<string, unknown>) => void;
  retryAttempts?: number;
  recoveryInterval?: number;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
  errorInfo: React.ErrorInfo | null;
  retryCount: number;
  isRecovering: boolean;
}

class ErrorBoundary extends React.Component<ErrorBoundaryProps, ErrorBoundaryState> {
  private recoveryTimeout: NodeJS.Timeout | null = null;
  private errorContext: Record<string, unknown> = {};

  static defaultProps = {
    retryAttempts: 3,
    recoveryInterval: 1000,
  };

  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null,
      retryCount: 0,
      isRecovering: false,
    };
  }

  static getDerivedStateFromError(error: Error): Partial<ErrorBoundaryState> {
    return {
      hasError: true,
      error,
    };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    // Track error with sanitized data
    Analytics.track('error_boundary', {
      name: 'error_boundary',
      category: Analytics.AnalyticsCategory.ERROR,
      properties: {
        errorName: error.name,
        errorMessage: error.message,
        ...this.errorContext
      },
      timestamp: Date.now(),
      userConsent: true,
      privacyLevel: Analytics.PrivacyLevel.INTERNAL
    });

    // Call optional error handler
    this.props.onError?.(error, errorInfo, this.errorContext);

    // Update state
    this.setState({
      hasError: true,
      error,
      errorInfo,
      isRecovering: false
    });
  }

  componentWillUnmount(): void {
    if (this.recoveryTimeout) {
      clearTimeout(this.recoveryTimeout);
    }
    this.errorContext = {};
  }

  render(): React.ReactNode {
    const { hasError, error, isRecovering } = this.state;
    const { children, fallback } = this.props;

    if (isRecovering) {
      return (
        <ErrorContainer>
          <Loader 
            size="medium"
            color="primary"
          />
          <ErrorMessage variant="body1">
            Attempting to recover...
          </ErrorMessage>
        </ErrorContainer>
      );
    }

    if (hasError) {
      if (fallback) {
        return fallback;
      }

      return (
        <ErrorContainer role="alert" aria-live="polite">
          <Alert severity="error" sx={{ mb: 2 }}>
            {error?.message || 'An unexpected error occurred'}
          </Alert>
          <ErrorMessage variant="body1">
            Please try again or contact support if the problem persists.
          </ErrorMessage>
          <Button
            variant="contained"
            color="primary"
            onClick={this.handleRetry}
            sx={{ mt: 2 }}
          >
            Try Again
          </Button>
        </ErrorContainer>
      );
    }

    return children;
  }

  private handleRetry = () => {
    const { retryAttempts = 3 } = this.props;
    const { retryCount } = this.state;

    if (retryCount < retryAttempts) {
      this.setState({ isRecovering: true });

      // Track recovery attempt
      Analytics.track('error_recovery_attempt', {
        name: 'error_recovery_attempt',
        category: Analytics.AnalyticsCategory.PERFORMANCE,
        properties: {
          retryCount: retryCount + 1,
          error: this.state.error?.message,
          component: this.constructor.name
        },
        timestamp: Date.now(),
        userConsent: true,
        privacyLevel: Analytics.PrivacyLevel.INTERNAL
      });

      // Attempt recovery
      this.recoveryTimeout = setTimeout(() => {
        this.setState(prevState => ({
          hasError: false,
          error: null,
          errorInfo: null,
          retryCount: prevState.retryCount + 1,
          isRecovering: false
        }));
      }, this.props.recoveryInterval);
    }
  };
}

export default ErrorBoundary;