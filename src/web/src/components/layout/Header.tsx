'use client';

import React, { useState, useEffect, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import Image from 'next/image';
import { css } from '@emotion/react';
import styled from '@emotion/styled';
import { useAuthContext } from '../../contexts/AuthContext';
import useAuth from '../../hooks/useAuth';

// Internal imports
import { 
  AUTH_ROUTES,
  DASHBOARD_ROUTES,
  VIRTUAL_CARE_ROUTES,
  HEALTH_RECORDS_ROUTES,
  CLAIMS_ROUTES,
  MARKETPLACE_ROUTES,
  EMERGENCY_ROUTES 
} from '../../lib/constants/routes';

// Constants
const MOBILE_BREAKPOINT = 768;
const HEADER_HEIGHT = 64;
const EMERGENCY_TIMEOUT = 300000; // 5 minutes
const CLINICAL_TOUCH_TARGET = 44;

// Types
type ClinicalEnvironmentType = 'STANDARD' | 'OPERATING_ROOM' | 'EMERGENCY' | 'CLINIC';
type EmergencyPriority = 'HIGH' | 'MEDIUM' | 'LOW';

interface HeaderProps {
  transparent?: boolean;
  className?: string;
  emergencyMode?: boolean;
  clinicalEnvironment?: ClinicalEnvironmentType;
}

// Base styles
const headerStyles = {
  base: css`
    height: ${HEADER_HEIGHT}px;
    width: 100%;
    position: fixed;
    top: 0;
    left: 0;
    z-index: 1000;
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0 24px;
    transition: all 0.3s ease;
    background: var(--color-surface-primary);
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);

    @media (max-width: ${MOBILE_BREAKPOINT}px) {
      padding: 0 16px;
    }
  `,
  transparent: css`
    background: transparent;
    box-shadow: none;
  `,
  emergency: css`
    background: var(--color-error-100);
  `,
  operatingRoom: css`
    background: var(--color-surface-sterile);
  `,
  emergencyRoom: css`
    background: var(--color-surface-emergency);
  `
};

// Styled Components
const StyledHeader = styled.header<{
  transparent?: boolean;
  emergencyMode?: boolean;
  clinicalEnvironment: ClinicalEnvironmentType;
}>`
  ${headerStyles.base};
  ${({ transparent }) => transparent && headerStyles.transparent};
  ${({ emergencyMode }) => emergencyMode && headerStyles.emergency};
  ${({ clinicalEnvironment }) => {
    switch (clinicalEnvironment) {
      case 'OPERATING_ROOM':
        return headerStyles.operatingRoom;
      case 'EMERGENCY':
        return headerStyles.emergencyRoom;
      default:
        return '';
    }
  }}
`;

const Logo = styled.div`
  min-width: 120px;
  height: ${CLINICAL_TOUCH_TARGET}px;
  display: flex;
  align-items: center;
  cursor: pointer;
  user-select: none;
`;

const Navigation = styled.nav`
  display: flex;
  align-items: center;
  gap: 32px;

  @media (max-width: ${MOBILE_BREAKPOINT}px) {
    display: none;
  }
`;

const NavItem = styled.a<{ active?: boolean }>`
  height: ${CLINICAL_TOUCH_TARGET}px;
  display: flex;
  align-items: center;
  padding: 0 16px;
  color: var(--color-text-primary);
  font-size: 16px;
  font-weight: ${({ active }) => (active ? '600' : '400')};
  cursor: pointer;
  transition: all 0.2s ease;
  border-radius: 8px;
  text-decoration: none;

  &:hover {
    background: var(--color-surface-hover);
  }
`;

const UserSection = styled.div`
  display: flex;
  align-items: center;
  gap: 16px;
`;

const EmergencyButton = styled.button`
  height: ${CLINICAL_TOUCH_TARGET}px;
  padding: 0 24px;
  background: var(--color-error-500);
  color: white;
  border: none;
  border-radius: 8px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s ease;

  &:hover {
    background: var(--color-error-600);
  }
`;

const AuthSection = styled.div`
  display: flex;
  align-items: center;
  gap: 16px;
`;

const Header: React.FC<HeaderProps> = ({
  transparent = false,
  className,
  emergencyMode = false,
  clinicalEnvironment = 'STANDARD'
}) => {
  const router = useRouter();
  const auth = useAuthContext();
  const { logout } = useAuth();
  const [isScrolled, setIsScrolled] = useState(false);

  // Handle scroll transparency
  useEffect(() => {
    const handleScroll = () => {
      setIsScrolled(window.scrollY > 0);
    };

    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  // Handle secure logout with audit logging
  const handleLogout = useCallback(async () => {
    try {
      await logout();
      router.push(AUTH_ROUTES.LOGIN);
    } catch (error) {
      console.error('Logout failed:', error);
    }
  }, [logout, router]);

  // Handle emergency navigation with priority
  const handleEmergencyNavigation = useCallback((route: string, priority: EmergencyPriority) => {
    router.push(route + `?priority=${priority}&timestamp=${Date.now()}`);
  }, [router]);

  // Session timeout warning
  useEffect(() => {
    const sessionTimeoutWarning = setTimeout(() => {
      if (auth.state === 'AUTHENTICATED') {
        // Show warning notification
      }
    }, EMERGENCY_TIMEOUT);

    return () => clearTimeout(sessionTimeoutWarning);
  }, [auth.state]);

  const isActive = (path: string) => {
    try {
      // Use window.location for client-side path checking
      return window.location.pathname.startsWith(path);
    } catch {
      return false;
    }
  };

  return (
    <StyledHeader
      transparent={transparent && !isScrolled}
      emergencyMode={emergencyMode}
      clinicalEnvironment={clinicalEnvironment}
      className={className}
      role="banner"
      aria-label="Main header"
      suppressHydrationWarning
    >
      <Logo onClick={() => router.push('/')} suppressHydrationWarning>
        <Image 
          src="/logo.svg"
          alt="AUSTA SuperApp"
          width={120}
          height={32}
          priority
        />
      </Logo>

      {auth.state === 'AUTHENTICATED' ? (
        <>
          <Navigation role="navigation">
            <NavItem 
              href={DASHBOARD_ROUTES.HOME}
              active={isActive('/dashboard')}
            >
              Dashboard
            </NavItem>
            <NavItem 
              href={VIRTUAL_CARE_ROUTES.HOME}
              active={isActive('/virtual-care')}
            >
              Virtual Care
            </NavItem>
            <NavItem 
              href={HEALTH_RECORDS_ROUTES.HOME}
              active={isActive('/health-records')}
            >
              Health Records
            </NavItem>
            <NavItem 
              href={CLAIMS_ROUTES.HOME}
              active={isActive('/claims')}
            >
              Claims
            </NavItem>
            <NavItem 
              href={MARKETPLACE_ROUTES.HOME}
              active={isActive('/marketplace')}
            >
              Marketplace
            </NavItem>
          </Navigation>

          <UserSection>
            {emergencyMode && (
              <EmergencyButton
                onClick={() => handleEmergencyNavigation(EMERGENCY_ROUTES.HOME, 'HIGH')}
                aria-label="Emergency access"
              >
                Emergency Mode
              </EmergencyButton>
            )}
            
            {auth.user && (
              <>
                <NavItem 
                  href={DASHBOARD_ROUTES.PROFILE}
                  aria-label="User profile"
                >
                  {auth.user.profile.firstName} {auth.user.profile.lastName}
                </NavItem>
                <NavItem 
                  onClick={handleLogout}
                  role="button"
                  aria-label="Logout"
                >
                  Logout
                </NavItem>
              </>
            )}
          </UserSection>
        </>
      ) : (
        <AuthSection>
          <NavItem 
            href={AUTH_ROUTES.LOGIN}
            active={isActive('/auth/login')}
          >
            Login
          </NavItem>
          <NavItem 
            href={AUTH_ROUTES.REGISTER}
            active={isActive('/auth/register')}
          >
            Register
          </NavItem>
        </AuthSection>
      )}
    </StyledHeader>
  );
};

export default Header;