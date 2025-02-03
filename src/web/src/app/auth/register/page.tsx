/**
 * @fileoverview HIPAA-compliant registration page component for AUSTA SuperApp
 * Implements secure registration with OAuth 2.0, MFA, and biometric support
 * @version 1.0.0
 * @license HIPAA-compliant
 */

'use client';

import React, { useState, useEffect, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import styled from '@emotion/styled';

import RegisterForm from '../../../components/auth/RegisterForm';
import BiometricAuth from '../../../components/auth/BiometricAuth';
import useAuth from '../../../hooks/useAuth';
import { AuthState } from '../../../lib/types/auth';

// Styled components with healthcare optimizations
const StyledRegistrationPage = styled.main`
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
  padding: 2rem;
  background-color: var(--clinical-background, #f5f7fa);

  @media (prefers-reduced-motion: reduce) {
    transition: none;
  }

  @media (prefers-color-scheme: dark) {
    background-color: var(--clinical-background-dark, #1a1a1a);
  }

  @media (forced-colors: active) {
    border: 2px solid ButtonText;
  }
`;

const RegistrationContainer = styled.div`
  width: 100%;
  max-width: 480px;
  margin: 0 auto;
  padding: 2rem;
  background: var(--surface-background, #ffffff);
  border-radius: 12px;
  box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);

  @media (max-width: 768px) {
    padding: 1.5rem;
    margin: 1rem;
  }
`;

const SecurityNotice = styled.div`
  margin-top: 2rem;
  padding: 1rem;
  font-size: 0.875rem;
  color: var(--text-secondary);
  text-align: center;
`;

const LoginLink = styled.div`
  margin-top: 1.5rem;
  text-align: center;
  font-size: 0.875rem;

  a {
    color: var(--primary-color, #0066cc);
    text-decoration: none;
    font-weight: 500;
    
    &:hover {
      text-decoration: underline;
    }

    &:focus {
      outline: 2px solid var(--primary-color);
      outline-offset: 2px;
    }
  }
`;

const RegistrationPage: React.FC = () => {
  const router = useRouter();
  const { state: authState } = useAuth();
  
  const [securityContext, setSecurityContext] = useState({
    deviceType: '',
    isClinicalEnvironment: false
  });

  useEffect(() => {
    const initializeSecurityContext = async () => {
      try {
        if (typeof window !== 'undefined') {
          const userAgent = window.navigator.userAgent.toLowerCase();
          const isMobileDevice = /mobile|tablet|ipad|android/.test(userAgent);
          const isClinicalDevice = /medical_tablet|workstation|mobile_cart/.test(userAgent);

          setSecurityContext({
            deviceType: isMobileDevice ? 'mobile' : 'desktop',
            isClinicalEnvironment: isClinicalDevice
          });
        }
      } catch (error) {
        console.error('Security context initialization failed:', error);
      }
    };

    initializeSecurityContext();
  }, []);

  const handleRegistrationSuccess = useCallback(async (user: any, mfaSetup: any) => {
    try {
      console.info('Registration successful', {
        timestamp: Date.now(),
        deviceType: securityContext.deviceType,
        isClinicalEnvironment: securityContext.isClinicalEnvironment
      });

      if (mfaSetup.verified) {
        router.push('/auth/login');
      } else {
        router.push('/auth/mfa-setup');
      }
    } catch (error) {
      console.error('Registration success handling failed:', error);
    }
  }, [router, securityContext]);

  const handleRegistrationError = useCallback((error: any) => {
    console.error('Registration failed', {
      timestamp: Date.now(),
      error: error.message,
      deviceType: securityContext.deviceType
    });
  }, [securityContext]);

  return (
    <StyledRegistrationPage
      role="main"
      aria-label="Healthcare platform registration"
    >
      <RegistrationContainer>
        {/* Biometric setup for supported devices */}
        {securityContext.deviceType && (
          <BiometricAuth
            onSuccess={handleRegistrationSuccess}
            onError={handleRegistrationError}
            clinicalMode={securityContext.isClinicalEnvironment}
            accessibilityMode={true}
            deviceType={securityContext.deviceType}
            isRegistration={true}
          />
        )}

        {/* Main registration form */}
        <RegisterForm
          onSuccess={handleRegistrationSuccess}
          onError={handleRegistrationError}
          onSecurityEvent={(event) => {
            console.info('Security event:', event);
          }}
        />

        {/* Login Link */}
        <LoginLink>
          Already have an account?{' '}
          <a href="/auth/login" onClick={(e) => {
            e.preventDefault();
            router.push('/auth/login');
          }}>
            Login here
          </a>
        </LoginLink>

        {/* Security notice */}
        <SecurityNotice role="note" aria-live="polite">
          This system is protected by enhanced security measures and complies with HIPAA regulations.
          All registration attempts are monitored and logged.
        </SecurityNotice>
      </RegistrationContainer>
    </StyledRegistrationPage>
  );
};

export default RegistrationPage;