import React from 'react';
import { 
  Box, 
  Typography, 
  Container, 
  Paper, 
  Alert,
  AlertTitle,
  Button
} from '@mui/material';
import { Email as EmailIcon } from '@mui/icons-material';
import { useRouter } from 'next/navigation';

const VerifyEmailRequired: React.FC = () => {
  const router = useRouter();

  const handleResendEmail = async () => {
    try {
      // TODO: Implement resend verification email functionality
      // await authAPI.resendVerificationEmail();
      alert('Verification email has been resent. Please check your inbox.');
    } catch (error) {
      console.error('Failed to resend verification email:', error);
      alert('Failed to resend verification email. Please try again later.');
    }
  };

  return (
    <Container maxWidth="sm">
      <Box sx={{ 
        mt: 8, 
        display: 'flex', 
        flexDirection: 'column', 
        alignItems: 'center' 
      }}>
        <Paper 
          elevation={3} 
          sx={{ 
            p: 4, 
            width: '100%',
            display: 'flex', 
            flexDirection: 'column', 
            alignItems: 'center',
            gap: 3
          }}
        >
          <EmailIcon sx={{ fontSize: 64, color: 'primary.main' }} />
          
          <Typography variant="h4" component="h1" align="center" gutterBottom>
            Verify Your Email
          </Typography>

          <Alert severity="info" sx={{ width: '100%' }}>
            <AlertTitle>Registration Successful!</AlertTitle>
            We've sent a verification link to your email address. Please check your inbox and click the link to verify your account.
          </Alert>

          <Typography variant="body1" color="text.secondary" align="center">
            You won't be able to access your account until you verify your email address. 
            The verification link will expire in 24 hours.
          </Typography>

          <Box sx={{ 
            display: 'flex', 
            flexDirection: 'column',
            gap: 2,
            width: '100%',
            mt: 2 
          }}>
            <Button
              variant="outlined"
              fullWidth
              onClick={handleResendEmail}
            >
              Resend Verification Email
            </Button>

            <Button
              variant="text"
              fullWidth
              onClick={() => router.push('/auth/login')}
            >
              Return to Login
            </Button>
          </Box>

          <Typography variant="body2" color="text.secondary" align="center">
            Didn't receive the email? Check your spam folder or click the resend button above.
          </Typography>
        </Paper>
      </Box>
    </Container>
  );
};

export default VerifyEmailRequired; 