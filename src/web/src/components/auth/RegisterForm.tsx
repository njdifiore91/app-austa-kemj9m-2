/**
 * @fileoverview HIPAA-compliant registration form component
 * Implements comprehensive security measures and Material Design 3.0 principles
 * @version 1.0.0
 * @license HIPAA-compliant
 */

'use client';

import React, { useState, useCallback, useEffect } from 'react';
import * as yup from 'yup';
import { startRegistration } from '@simplewebauthn/browser';
import CryptoJS from 'crypto-js';
import * as FingerprintJS from '@fingerprintjs/fingerprintjs';
import { styled } from '@mui/material/styles';
import {
  TextField,
  Button,
  FormControlLabel,
  Checkbox,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  FormHelperText,
  CircularProgress,
  Alert,
  Box,
  Typography,
  SelectChangeEvent,
  IconButton,
  InputAdornment
} from '@mui/material';
import { Visibility, VisibilityOff } from '@mui/icons-material';
import { logger } from '../../lib/utils/logger';
import authAPI from '../../lib/api/auth';
import { useRouter, usePathname, useSearchParams } from 'next/navigation';

// Internal imports
import { ILoginCredentials, SecurityEvent, IUser, IAuthError } from '../../lib/types/auth';
import { validateForm, ValidationError } from '../../lib/utils/validation';
import { ErrorCode, ErrorTracker } from '../../lib/constants/errorCodes';

// Initialize fingerprint service
const fpPromise = FingerprintJS.load();

// HIPAA-compliant validation schema
const registrationSchema = yup.object().shape({
  // Step 1: Basic Information
  email: yup
    .string()
    .email('Please enter a valid email address')
    .required('Email is required')
    .test('domain', 'Healthcare email required', (value) => {
      return value ? /^[^@]+@(?:\w+\.)?(?:healthcare|medical|hospital|clinic)\.\w+$/.test(value) : false;
    }),
  password: yup
    .string()
    .required('Password is required')
    .min(12, 'Password must be at least 12 characters')
    .matches(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .matches(/[a-z]/, 'Password must contain at least one lowercase letter')
    .matches(/[0-9]/, 'Password must contain at least one number')
    .matches(/[^A-Za-z0-9]/, 'Password must contain at least one special character'),
  confirmPassword: yup
    .string()
    .required('Please confirm your password')
    .oneOf([yup.ref('password')], 'Passwords must match'),
  firstName: yup.string().required('First name is required').min(2, 'First name is too short'),
  lastName: yup.string().required('Last name is required').min(2, 'Last name is too short'),
  phoneNumber: yup
    .string()
    .required('Phone number is required')
    .matches(/^\+?[1-9]\d{1,14}$/, 'Please enter a valid phone number'),

  // Step 2: Additional Information
  gender: yup.string().required('Gender is required'),
  address: yup.object().shape({
    street: yup.string().required('Street address is required'),
    city: yup.string().required('City is required'),
    state: yup.string().required('State is required'),
    postalCode: yup.string().required('Postal code is required'),
    country: yup.string().required('Country is required')
  }),

  // Step 3: Emergency Contact
  emergencyContact: yup.object().shape({
    name: yup.string().required('Emergency contact name is required'),
    relationship: yup.string().required('Relationship is required'),
    phoneNumber: yup
      .string()
      .required('Emergency contact phone number is required')
      .matches(/^\+?[1-9]\d{1,14}$/, 'Please enter a valid phone number')
  }),

  // Step 4: Security Settings
  acceptTerms: yup
    .boolean()
    .oneOf([true], 'You must accept the terms and conditions'),
  mfaPreference: yup
    .string()
    .oneOf(['none', 'sms', 'email', 'authenticator', 'biometric'], 'Please select an MFA method')
    .required('MFA setup is required'),
  biometricConsent: yup
    .boolean()
    .required('Please indicate biometric consent'),
  deviceFingerprint: yup.string().required('Device verification failed')
});

// Basic validation schema for step 1
const basicSchema = yup.object().shape({
  email: yup
    .string()
    .email('Please enter a valid email address')
    .required('Email is required')
    .test('domain', 'Healthcare email required', (value) => {
      return value ? /^[^@]+@(?:\w+\.)?(?:healthcare|medical|hospital|clinic)\.\w+$/.test(value) : false;
    }),
  password: yup
    .string()
    .required('Password is required')
    .min(12, 'Password must be at least 12 characters')
    .matches(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .matches(/[a-z]/, 'Password must contain at least one lowercase letter')
    .matches(/[0-9]/, 'Password must contain at least one number')
    .matches(/[^A-Za-z0-9]/, 'Password must contain at least one special character'),
  confirmPassword: yup
    .string()
    .required('Please confirm your password')
    .oneOf([yup.ref('password')], 'Passwords must match'),
  firstName: yup.string().required('First name is required').min(2, 'First name is too short'),
  lastName: yup.string().required('Last name is required').min(2, 'Last name is too short'),
  phoneNumber: yup
    .string()
    .required('Phone number is required')
    .matches(/^\+?[1-9]\d{1,14}$/, 'Please enter a valid phone number')
});

// Interface definitions
interface RegisterFormProps {
  onSuccess: (user: IUser, mfaSetup: { type: string; verified: boolean }) => void;
  onError: (error: IAuthError) => void;
  onSecurityEvent: (event: SecurityEvent) => void;
}

interface FormState {
  // Step 1: Basic Information
  email: string;
  password: string;
  confirmPassword: string;
  firstName: string;
  lastName: string;
  phoneNumber: string;

  // Step 2: Additional Information
  gender: string;
  address: {
    street: string;
    city: string;
    state: string;
    postalCode: string;
    country: string;
  };

  // Step 3: Emergency Contact
  emergencyContact: {
    name: string;
    relationship: string;
    phoneNumber: string;
  };

  // Step 4: Security Settings
  acceptTerms: boolean;
  mfaPreference: string;
  biometricConsent: boolean;

  // Form state
  currentStep: number;
  errors: Record<string, string>;
  loading: boolean;
  successMessage?: string;
}

// Styled components
const StyledForm = styled('form')(({ theme }) => ({
  display: 'flex',
  flexDirection: 'column',
  gap: '1.5rem',
  width: '100%',
  maxWidth: '400px',
  padding: '2rem',
  background: 'var(--surface-background)',
  borderRadius: '8px',
  boxShadow: '0 4px 6px rgba(0, 0, 0, 0.1)',
  margin: '0 auto',
  position: 'relative',

  '& .MuiTextField-root': {
    width: '100%',
  },
  '& .MuiFormControl-root': {
    width: '100%',
  },

  '@media (prefers-reduced-motion: reduce)': {
    transition: 'none',
  },

  '@media (forced-colors: active)': {
    border: '2px solid ButtonText',
  }
}));

const FormSection = styled(Box)(({ theme }) => ({
  display: 'flex',
  flexDirection: 'column',
  gap: '1.5rem',
}));

const LoadingOverlay = styled(Box)({
  position: 'absolute',
  top: 0,
  left: 0,
  right: 0,
  bottom: 0,
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  background: 'rgba(255, 255, 255, 0.8)',
  backdropFilter: 'blur(4px)',
  zIndex: 1000,
  borderRadius: '8px',
});

const RegisterForm: React.FC<RegisterFormProps> = ({
  onSuccess,
  onError,
  onSecurityEvent
}): JSX.Element => {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const [mounted, setMounted] = useState(false);
  const [formData, setFormData] = useState<FormState>({
    // Step 1: Basic Information
    email: '',
    password: '',
    confirmPassword: '',
    firstName: '',
    lastName: '',
    phoneNumber: '',

    // Step 2: Additional Information
    gender: '',
    address: {
      street: '',
      city: '',
      state: '',
      postalCode: '',
      country: ''
    },

    // Step 3: Emergency Contact
    emergencyContact: {
      name: '',
      relationship: '',
      phoneNumber: ''
    },

    // Step 4: Security Settings
    acceptTerms: false,
    mfaPreference: '',
    biometricConsent: false,

    // Form state
    currentStep: 1,
    errors: {},
    loading: false
  });

  const [showPassword, setShowPassword] = useState({
    password: false,
    confirmPassword: false
  });

  // Handle component mounting
  useEffect(() => {
    setMounted(true);
  }, []);

  // Memoize form validation to prevent unnecessary re-renders
  const validateStepFields = useCallback(async (fields: string[]) => {
    const errors: Record<string, string> = {};

    for (const field of fields) {
      try {
        await registrationSchema.validateAt(field, formData);
      } catch (err) {
        if (err instanceof yup.ValidationError && err.path) {
          errors[err.path] = err.message;
        }
      }
    }

    if (Object.keys(errors).length > 0) {
      setFormData(prev => ({
        ...prev,
        errors
      }));
      return false;
    }

    return true;
  }, [formData]);

  // Memoize form submission handler
  const handleSubmit = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    if (!mounted) return;

    setFormData(prev => ({ ...prev, loading: true, errors: {} }));

    try {
      // Get device fingerprint
      const fp = await fpPromise;
      const result = await fp.get();
      const deviceFingerprint = result.visitorId;

      // Validate all form data
      await registrationSchema.validate({
        ...formData,
        deviceFingerprint
      }, { abortEarly: false });

      // Make API call to register using auth API client
      const { token, fingerprint, user } = await authAPI.register({
        email: formData.email,
        password: formData.password,
        firstName: formData.firstName,
        lastName: formData.lastName,
        phoneNumber: formData.phoneNumber,
        gender: formData.gender,
        address: formData.address,
        emergencyContact: formData.emergencyContact,
        mfaPreference: formData.mfaPreference,
        biometricConsent: formData.biometricConsent,
        deviceFingerprint
      });

      // Store tokens - backend sends single token and fingerprint
      localStorage.setItem('accessToken', token);
      localStorage.setItem('tokenFingerprint', fingerprint);

      onSuccess(user, { type: formData.mfaPreference, verified: false });
      
      // Log security event
      onSecurityEvent({
        eventType: 'REGISTRATION_SUCCESS',
        timestamp: Date.now(),
        userId: user._id,
        sessionId: deviceFingerprint,
        metadata: {
          email: formData.email,
          mfaType: formData.mfaPreference
        },
        severity: 'LOW',
        outcome: 'SUCCESS'
      });

      // Only redirect if component is mounted
      if (mounted) {
        await router.push('/verify-email-required');
      }
      
    } catch (error: any) {
      console.error('Registration error:', error);
      
      // Handle backend validation errors
      if (error.code === 'DATA_VALIDATION_ERROR') {
        const validationErrors: Record<string, string> = {};
        if (error.details?.errors) {
          error.details.errors.forEach((err: { field: string; message: string }) => {
            validationErrors[err.field] = err.message;
          });
        } else {
          validationErrors.submit = error.message;
        }
        setFormData(prev => ({
          ...prev,
          errors: validationErrors,
          loading: false
        }));
      }
      // Handle duplicate entry errors
      else if (error.code === 'DUPLICATE_ENTRY') {
        setFormData(prev => ({
          ...prev,
          errors: {
            [error.details?.field || 'email']: error.message || 'A user with this email already exists'
          },
          loading: false
        }));
      }
      // Handle other known errors
      else if (error.code) {
        setFormData(prev => ({
          ...prev,
          errors: {
            submit: error.message || 'Registration failed'
          },
          loading: false
        }));
      }
      // Handle unknown errors
      else {
        setFormData(prev => ({
          ...prev,
          errors: {
            submit: 'An unexpected error occurred during registration'
          },
          loading: false
        }));
      }

      // Log error event
      onError({
        code: error.code || 'REGISTRATION_FAILED',
        message: error.message || 'Registration failed',
        details: error.details || {},
        timestamp: Date.now(),
        requestId: crypto.randomUUID()
      });
    }
  }, [formData, mounted, onSuccess, onSecurityEvent, router]);

  // Memoize input change handler
  const handleInputChange = useCallback((
    event: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement> | SelectChangeEvent<string>
  ) => {
    if (!mounted) return;
    
    const target = event.target;
    const fieldName = target.name;
    const fieldValue = (target as HTMLInputElement).type === 'checkbox'
      ? (target as HTMLInputElement).checked
      : target.value;

    setFormData(prev => ({
      ...prev,
      [fieldName]: fieldValue,
      errors: {
        ...prev.errors,
        [fieldName]: ''
      }
    }));
  }, [mounted]);

  // Memoize step navigation handlers
  const handleNext = useCallback(async (e: React.MouseEvent) => {
    e.preventDefault();
    if (!mounted) return;
    
    try {
      // Clear previous errors
      setFormData(prev => ({
        ...prev,
        errors: {}
      }));

      // For step 1, validate basic fields
      if (formData.currentStep === 1) {
        const stepData = {
          email: formData.email,
          password: formData.password,
          confirmPassword: formData.confirmPassword,
          firstName: formData.firstName,
          lastName: formData.lastName,
          phoneNumber: formData.phoneNumber
        };

        try {
          await basicSchema.validate(stepData, { abortEarly: false });
        } catch (validationError) {
          if (validationError instanceof yup.ValidationError) {
            const errors: Record<string, string> = {};
            validationError.inner.forEach((err) => {
              if (err.path) {
                errors[err.path] = err.message;
              }
            });
            setFormData(prev => ({
              ...prev,
              errors
            }));
            return;
          }
          throw validationError;
        }
      }
      
      // If validation passes, move to next step
      setFormData(prev => ({
        ...prev,
        currentStep: prev.currentStep + 1,
        errors: {}
      }));
    } catch (error) {
      console.error('Validation failed:', error);
    }
  }, [formData, mounted]);

  const handleBack = useCallback(() => {
    if (!mounted) return;
    
    setFormData(prev => ({
      ...prev,
      currentStep: prev.currentStep - 1,
      errors: {}
    }));
  }, [mounted]);

  const getFieldsForStep = (step: number) => {
    switch (step) {
      case 1:
        return ['email', 'password', 'confirmPassword', 'firstName', 'lastName', 'phoneNumber'];
      case 2:
        return ['gender', 'address.street', 'address.city', 'address.state', 'address.postalCode', 'address.country'];
      case 3:
        return ['emergencyContact.name', 'emergencyContact.relationship', 'emergencyContact.phoneNumber'];
      case 4:
        return ['acceptTerms', 'mfaPreference', 'biometricConsent'];
      default:
        return [];
    }
  };

  const handleValidationErrors = (error: unknown) => {
    // Handle Yup validation errors
    if (error instanceof yup.ValidationError) {
      const validationErrors: Record<string, string> = {};
      error.inner?.forEach((err) => {
        if (err.path) {
          validationErrors[err.path] = err.message;
        }
      });
      setFormData(prev => ({ 
        ...prev, 
        errors: validationErrors,
        loading: false
      }));
    } else {
      // Handle API errors
      const errorMessage = error instanceof Error ? error.message : 'Registration failed';
      setFormData(prev => ({
        ...prev,
        errors: {
          ...prev.errors,
          submit: errorMessage
        },
        loading: false
      }));
      
      onError({
        code: 'REGISTRATION_FAILED',
        message: errorMessage,
        details: { error: String(error) },
        timestamp: Date.now(),
        requestId: crypto.randomUUID()
      });
    }
  };

  // Helper function to check if there are actual errors
  const hasErrors = useCallback(() => {
    return Object.values(formData.errors).some(error => error !== '');
  }, [formData.errors]);

  const handleClickShowPassword = (field: 'password' | 'confirmPassword') => {
    setShowPassword(prev => ({
      ...prev,
      [field]: !prev[field]
    }));
  };

  const handleMouseDownPassword = (event: React.MouseEvent<HTMLButtonElement>) => {
    event.preventDefault();
  };

  const renderStep = () => {
    switch (formData.currentStep) {
      case 1:
        return (
          <FormSection>
            <Typography variant="h6">Basic Information</Typography>
            <TextField
              label="Email"
              type="email"
              value={formData.email}
              onChange={(e) => setFormData(prev => ({ ...prev, email: e.target.value }))}
              error={!!formData.errors.email}
              helperText={formData.errors.email}
              required
            />
            <TextField
              label="Password"
              type={showPassword.password ? 'text' : 'password'}
              value={formData.password}
              onChange={(e) => setFormData(prev => ({ ...prev, password: e.target.value }))}
              error={!!formData.errors.password}
              helperText={formData.errors.password}
              required
              InputProps={{
                endAdornment: (
                  <InputAdornment position="end">
                    <IconButton
                      onClick={() => setShowPassword(prev => ({ ...prev, password: !prev.password }))}
                      onMouseDown={(e) => e.preventDefault()}
                      edge="end"
                    >
                      {showPassword.password ? <VisibilityOff /> : <Visibility />}
                    </IconButton>
                  </InputAdornment>
                ),
              }}
            />
            <TextField
              label="Confirm Password"
              type={showPassword.confirmPassword ? 'text' : 'password'}
              value={formData.confirmPassword}
              onChange={(e) => setFormData(prev => ({ ...prev, confirmPassword: e.target.value }))}
              error={!!formData.errors.confirmPassword}
              helperText={formData.errors.confirmPassword}
              required
              InputProps={{
                endAdornment: (
                  <InputAdornment position="end">
                    <IconButton
                      onClick={() => setShowPassword(prev => ({ ...prev, confirmPassword: !prev.confirmPassword }))}
                      onMouseDown={(e) => e.preventDefault()}
                      edge="end"
                    >
                      {showPassword.confirmPassword ? <VisibilityOff /> : <Visibility />}
                    </IconButton>
                  </InputAdornment>
                ),
              }}
            />
            <TextField
              label="First Name"
              value={formData.firstName}
              onChange={(e) => setFormData(prev => ({ ...prev, firstName: e.target.value }))}
              error={!!formData.errors.firstName}
              helperText={formData.errors.firstName}
              required
            />
            <TextField
              label="Last Name"
              value={formData.lastName}
              onChange={(e) => setFormData(prev => ({ ...prev, lastName: e.target.value }))}
              error={!!formData.errors.lastName}
              helperText={formData.errors.lastName}
              required
            />
            <TextField
              label="Phone Number"
              value={formData.phoneNumber}
              onChange={(e) => setFormData(prev => ({ ...prev, phoneNumber: e.target.value }))}
              error={!!formData.errors.phoneNumber}
              helperText={formData.errors.phoneNumber}
              required
            />
          </FormSection>
        );

      case 2:
        return (
          <FormSection>
            <Typography variant="h6">Additional Information</Typography>
            <FormControl fullWidth required error={!!formData.errors.gender}>
              <InputLabel>Gender</InputLabel>
              <Select
                value={formData.gender}
                onChange={(e) => setFormData(prev => ({ ...prev, gender: e.target.value }))}
                label="Gender"
              >
                <MenuItem value="male">Male</MenuItem>
                <MenuItem value="female">Female</MenuItem>
                <MenuItem value="other">Other</MenuItem>
                <MenuItem value="prefer_not_to_say">Prefer not to say</MenuItem>
              </Select>
              {formData.errors.gender && (
                <FormHelperText>{formData.errors.gender}</FormHelperText>
              )}
            </FormControl>
            <TextField
              label="Street Address"
              value={formData.address.street}
              onChange={(e) => setFormData(prev => ({
                ...prev,
                address: { ...prev.address, street: e.target.value }
              }))}
              error={!!formData.errors['address.street']}
              helperText={formData.errors['address.street']}
              required
            />
            <TextField
              label="City"
              value={formData.address.city}
              onChange={(e) => setFormData(prev => ({
                ...prev,
                address: { ...prev.address, city: e.target.value }
              }))}
              error={!!formData.errors['address.city']}
              helperText={formData.errors['address.city']}
              required
            />
            <TextField
              label="State"
              value={formData.address.state}
              onChange={(e) => setFormData(prev => ({
                ...prev,
                address: { ...prev.address, state: e.target.value }
              }))}
              error={!!formData.errors['address.state']}
              helperText={formData.errors['address.state']}
              required
            />
            <TextField
              label="Postal Code"
              value={formData.address.postalCode}
              onChange={(e) => setFormData(prev => ({
                ...prev,
                address: { ...prev.address, postalCode: e.target.value }
              }))}
              error={!!formData.errors['address.postalCode']}
              helperText={formData.errors['address.postalCode']}
              required
            />
            <TextField
              label="Country"
              value={formData.address.country}
              onChange={(e) => setFormData(prev => ({
                ...prev,
                address: { ...prev.address, country: e.target.value }
              }))}
              error={!!formData.errors['address.country']}
              helperText={formData.errors['address.country']}
              required
            />
          </FormSection>
        );

      case 3:
        return (
          <FormSection>
            <Typography variant="h6">Emergency Contact</Typography>
            <TextField
              label="Emergency Contact Name"
              value={formData.emergencyContact.name}
              onChange={(e) => setFormData(prev => ({
                ...prev,
                emergencyContact: { ...prev.emergencyContact, name: e.target.value }
              }))}
              error={!!formData.errors['emergencyContact.name']}
              helperText={formData.errors['emergencyContact.name']}
              required
            />
            <TextField
              label="Relationship"
              value={formData.emergencyContact.relationship}
              onChange={(e) => setFormData(prev => ({
                ...prev,
                emergencyContact: { ...prev.emergencyContact, relationship: e.target.value }
              }))}
              error={!!formData.errors['emergencyContact.relationship']}
              helperText={formData.errors['emergencyContact.relationship']}
              required
            />
            <TextField
              label="Emergency Contact Phone"
              value={formData.emergencyContact.phoneNumber}
              onChange={(e) => setFormData(prev => ({
                ...prev,
                emergencyContact: { ...prev.emergencyContact, phoneNumber: e.target.value }
              }))}
              error={!!formData.errors['emergencyContact.phoneNumber']}
              helperText={formData.errors['emergencyContact.phoneNumber']}
              required
            />
          </FormSection>
        );

      case 4:
        return (
          <FormSection>
            <Typography variant="h6">Security Settings</Typography>
            <FormControl fullWidth required error={!!formData.errors.mfaPreference}>
              <InputLabel>MFA Preference</InputLabel>
              <Select
                value={formData.mfaPreference}
                onChange={(e) => setFormData(prev => ({ ...prev, mfaPreference: e.target.value }))}
                label="MFA Preference"
              >
                <MenuItem value="none">None</MenuItem>
                <MenuItem value="email">Email</MenuItem>
                <MenuItem value="sms">SMS</MenuItem>
                <MenuItem value="authenticator">Authenticator App</MenuItem>
                <MenuItem value="biometric">Biometric</MenuItem>
              </Select>
              {formData.errors.mfaPreference && (
                <FormHelperText>{formData.errors.mfaPreference}</FormHelperText>
              )}
            </FormControl>
            <FormControlLabel
              control={
                <Checkbox
                  checked={formData.biometricConsent}
                  onChange={(e) => setFormData(prev => ({ ...prev, biometricConsent: e.target.checked }))}
                />
              }
              label="I consent to biometric authentication"
            />
            <FormControlLabel
              control={
                <Checkbox
                  checked={formData.acceptTerms}
                  onChange={(e) => setFormData(prev => ({ ...prev, acceptTerms: e.target.checked }))}
                />
              }
              label="I accept the terms and conditions"
            />
            {formData.errors.acceptTerms && (
              <FormHelperText error>{formData.errors.acceptTerms}</FormHelperText>
            )}
          </FormSection>
        );

      default:
        return null;
    }
  };

  // Prevent any state updates during SSR
  if (!mounted) {
    return <LoadingOverlay><CircularProgress /></LoadingOverlay>;
  }

  return (
    <StyledForm onSubmit={handleSubmit}>
      {formData.errors.submit && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {formData.errors.submit}
        </Alert>
      )}

      {formData.successMessage && (
        <Alert severity="success" sx={{ mb: 2 }}>
          {formData.successMessage}
        </Alert>
      )}

      {renderStep()}

      <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 2 }}>
        {formData.currentStep > 1 && (
          <Button
            type="button"
            variant="outlined"
            onClick={handleBack}
            disabled={formData.loading}
          >
            Back
          </Button>
        )}
        {formData.currentStep < 4 ? (
          <Button
            type="button"
            variant="contained"
            onClick={handleNext}
            disabled={formData.loading}
          >
            Next
          </Button>
        ) : (
          <Button
            type="submit"
            variant="contained"
            color="primary"
            disabled={formData.loading}
          >
            Register
          </Button>
        )}
      </Box>

      {formData.loading && (
        <LoadingOverlay>
          <CircularProgress />
        </LoadingOverlay>
      )}
    </StyledForm>
  );
};

export default RegisterForm;