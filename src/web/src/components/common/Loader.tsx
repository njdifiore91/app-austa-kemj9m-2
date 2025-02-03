'use client';

import React from 'react';
import { CircularProgress } from '@mui/material';

interface LoaderProps {
  size?: 'small' | 'medium' | 'large';
  color?: 'primary' | 'secondary' | 'inherit' | 'error' | 'info' | 'success' | 'warning';
}

const sizeMap = {
  small: 24,
  medium: 40,
  large: 56
};

const Loader: React.FC<LoaderProps> = ({ 
  size = 'medium',
  color = 'primary'
}) => {
  return (
    <div className="flex items-center justify-center p-4">
      <CircularProgress 
        size={sizeMap[size]} 
        color={color}
        aria-label="Loading..."
      />
    </div>
  );
};

export default Loader;