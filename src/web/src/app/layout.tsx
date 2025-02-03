import React from 'react';
import { Metadata } from 'next';
import Providers from './providers';

// Types
export interface RootLayoutProps {
  children: React.ReactNode;
}

export const metadata: Metadata = {
  title: 'AUSTA SuperApp',
  description: 'HIPAA-compliant healthcare platform',
};

export default function RootLayout({ children }: RootLayoutProps) {
  return (
    <html lang="en">
      <body>
        <Providers>
          {children}
        </Providers>
      </body>
    </html>
  );
}