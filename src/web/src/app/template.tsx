'use client';

import React, { useState, useEffect } from 'react';
import styled from '@emotion/styled';
import Header from '../components/layout/Header';
import Footer from '../components/layout/Footer';
import theme from '../styles/theme';

// Constants
const MAIN_CONTENT_MIN_HEIGHT = 'calc(100vh - var(--header-height) - var(--footer-height))';

// Styled Components
const SkipLink = styled.a`
  position: absolute;
  left: -9999px;
  top: 20px;
  z-index: 9999;
  padding: 1rem;
  background: ${theme.palette.primary.main};
  color: ${theme.palette.primary.contrastText};
  text-decoration: none;
  border-radius: ${theme.shape.borderRadius}px;

  &:focus {
    left: 20px;
  }
`;

const MainContent = styled.main<{ clinicalMode?: boolean }>`
  min-height: ${MAIN_CONTENT_MIN_HEIGHT};
  background-color: ${({ clinicalMode }) =>
    clinicalMode ? '#F8FBFF' : theme.palette.background.default};
  padding-top: var(--header-height);
  transition: background-color 0.3s ease;

  @media print {
    padding-top: 0;
    min-height: auto;
  }
`;

export default function Template({ children }: { children: React.ReactNode }) {
  const [isEmergencyMode, setIsEmergencyMode] = useState(false);
  const [clinicalMode, setClinicalMode] = useState(false);

  // Handle emergency mode keyboard shortcuts
  useEffect(() => {
    const handleKeyPress = (event: KeyboardEvent) => {
      if (
        event.ctrlKey &&
        event.shiftKey &&
        event.key.toLowerCase() === 'e'
      ) {
        setIsEmergencyMode(prev => !prev);
      }
    };

    window.addEventListener('keydown', handleKeyPress);
    return () => window.removeEventListener('keydown', handleKeyPress);
  }, []);

  // Set CSS custom properties
  useEffect(() => {
    document.documentElement.style.setProperty('--header-height', '64px');
    document.documentElement.style.setProperty('--footer-height', '80px');
  }, []);

  return (
    <>
      {/* Accessibility skip link */}
      <SkipLink href="#main-content">
        Skip to main content
      </SkipLink>

      {/* Header with clinical and emergency mode support */}
      <Header
        transparent={false}
        emergencyMode={isEmergencyMode}
        clinicalEnvironment={clinicalMode ? 'CLINIC' : 'STANDARD'}
      />

      {/* Main content area */}
      <MainContent
        id="main-content"
        role="main"
        clinicalMode={clinicalMode}
        aria-live={isEmergencyMode ? 'assertive' : 'polite'}
      >
        {children}
      </MainContent>

      {/* Footer with emergency contacts */}
      <Footer />
    </>
  );
} 