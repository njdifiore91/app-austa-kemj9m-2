import React, { useEffect, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { 
  Box, 
  Typography, 
  CircularProgress, 
  Alert,
  Container,
  Paper
} from '@mui/material';
import authAPI from '../lib/api/auth';

const VerifyAccount: React.FC = () => {
  const searchParams = useSearchParams();
  const router = useRouter();
  const [status, setStatus] = useState<'verifying' | 'success' | 'error'>('verifying');
  const [errorMessage, setErrorMessage] = useState<string>('');

  useEffect(() => {
    const verifyAccount = async () => {
      try {
        if (!searchParams) {
          setStatus('error');
          setErrorMessage('Invalid verification link');
          return;
        }

        const userId = searchParams.get('userId');
        const token = searchParams.get('token');

        if (!userId || !token) {
          setStatus('error');
          setErrorMessage('Invalid verification link');
          return;
        }

        console.log('Verifying account:', { userId, token });
        // Call the verify endpoint
        await authAPI.verifyAccount(userId, token);
        setStatus('success');

        console.log('Account verified successfully');

        // Redirect to login after 3 seconds
        setTimeout(() => {
          router.push('/auth/login');
        }, 3000);

      } catch (error: any) {
        setStatus('error');
        setErrorMessage(error.message || 'Verification failed. Please try again.');
      }
    };

    verifyAccount();
  }, [searchParams, router]);

  return (
    <Container maxWidth="sm">
      <Box sx={{ mt: 8 }}>
        <Paper 
          elevation={3} 
          sx={{ 
            p: 4, 
            display: 'flex', 
            flexDirection: 'column', 
            alignItems: 'center' 
          }}
        >
          {status === 'verifying' && (
            <>
              <CircularProgress />
              <Typography variant="h6" sx={{ mt: 2 }}>
                Verifying your account...
              </Typography>
            </>
          )}

          {status === 'success' && (
            <Alert severity="success" sx={{ width: '100%' }}>
              <Typography variant="body1">
                Account verified successfully! Redirecting to login...
              </Typography>
            </Alert>
          )}

          {status === 'error' && (
            <Alert severity="error" sx={{ width: '100%' }}>
              <Typography variant="body1">
                {errorMessage}
              </Typography>
            </Alert>
          )}
        </Paper>
      </Box>
    </Container>
  );
};

export default VerifyAccount; 