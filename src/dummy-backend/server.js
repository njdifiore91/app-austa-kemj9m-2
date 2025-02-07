const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
const PORT = 3001;

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Request logging middleware
app.use((req, res, next) => {
  console.log(`${req.method} ${req.path}`, {
    body: req.body,
    headers: req.headers
  });
  next();
});

// Mock user database
const users = [
  {
    id: '1',
    email: 'test@hospital.com',
    password: 'abcdE@123456', // In a real app, this would be hashed
    name: 'Test User'
  },
  {
    id: '2',
    email: 'doctor@hospital.com',
    password: 'Doctor@123',
    name: 'Dr. Smith'
  },
  {
    id: '3',
    email: 'nurse@hospital.com',
    password: 'Nurse@123',
    name: 'Nurse Johnson'
  }
];

// Mock tokens
const mockTokens = {
  accessToken: 'mock_access_token',
  refreshToken: 'mock_refresh_token',
  idToken: 'mock_id_token'
};

// Helper function to handle login logic
const handleLogin = (req, res) => {
  console.log('=== Login Request Details ===');
  console.log('Headers:', req.headers);
  console.log('Body:', JSON.stringify(req.body, null, 2));
  console.log('Path:', req.path);
  console.log('Method:', req.method);
  
  try {
    let credentials;
    
    // Handle encrypted credentials from frontend
    if (req.body.credentials) {
      try {
        // In a real app, we would decrypt this
        // For now, just parse it if it's a string
        credentials = typeof req.body.credentials === 'string' 
          ? JSON.parse(req.body.credentials)
          : req.body.credentials;
      } catch (e) {
        console.log('Failed to parse encrypted credentials:', e);
        return res.status(400).json({ 
          code: 'INVALID_CREDENTIALS_FORMAT',
          error: 'Invalid credentials format',
          message: 'Could not process the provided credentials'
        });
      }
    } else {
      credentials = req.body;
    }

    const { email, password } = credentials;

    // Log the extracted credentials
    console.log('Processed credentials:', { 
      email, 
      hasPassword: !!password
    });

    // Validate required fields
    if (!email || !password) {
      console.log('Missing credentials:', { email: !!email, password: !!password });
      return res.status(401).json({ 
        code: 'MISSING_CREDENTIALS',
        error: 'Invalid credentials',
        message: 'Email and password are required'
      });
    }

    // Find user in mock database
    const user = users.find(u => u.email === email && u.password === password);
    
    if (!user) {
      console.log('Login failed - Invalid credentials for:', email);
      return res.status(401).json({ 
        code: 'INVALID_CREDENTIALS',
        error: 'Invalid credentials',
        message: 'The email or password you entered is incorrect'
      });
    }

    console.log('Login successful for user:', {
      id: user.id,
      email: user.email,
      name: user.name
    });

    // Return successful response with user data and tokens
    return res.json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        name: user.name
      },
      ...mockTokens
    });
  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({
      code: 'SERVER_ERROR',
      error: 'Server error',
      message: 'An unexpected error occurred'
    });
  }
};

// Helper function to handle register logic
const handleRegister = (req, res) => {
  const { email, password, name } = req.body;
  
  if (users.some(u => u.email === email)) {
    return res.status(400).json({ error: 'User already exists' });
  }

  const newUser = {
    id: String(users.length + 1),
    email,
    password,
    name
  };

  users.push(newUser);

  res.status(201).json({
    user: {
      id: newUser.id,
      email: newUser.email,
      name: newUser.name
    },
    ...mockTokens
  });
};

// Helper function to handle token verification
const handleVerify = (req, res) => {
  const { token } = req.body;
  
  if (token === mockTokens.accessToken) {
    res.json({ valid: true });
  } else {
    res.status(401).json({ valid: false });
  }
};

// Helper function to handle token refresh
const handleRefresh = (req, res) => {
  const { refreshToken } = req.body;
  
  if (refreshToken === mockTokens.refreshToken) {
    res.json(mockTokens);
  } else {
    res.status(401).json({ error: 'Invalid refresh token' });
  }
};

// Routes with /v1 prefix
app.post('/v1/auth/login', handleLogin);
app.post('/v1/auth/register', handleRegister);
app.post('/v1/auth/verify', handleVerify);
app.post('/v1/auth/refresh', handleRefresh);

// Routes without /v1 prefix
app.post('/auth/login', handleLogin);
app.post('/auth/register', handleRegister);
app.post('/auth/verify', handleVerify);
app.post('/auth/refresh', handleRefresh);

// Handle device fingerprint validation
app.post('/', (req, res) => {
  res.json({ valid: true });
});

app.listen(PORT, () => {
  console.log(`Dummy auth server running on http://localhost:${PORT}`);
}); 