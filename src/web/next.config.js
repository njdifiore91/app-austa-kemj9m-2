/**
 * @fileoverview Next.js configuration for AUSTA SuperApp web application
 * Implements comprehensive security, PWA capabilities, and performance optimizations
 * with HIPAA compliance considerations
 */

const { BASE_URL, API_VERSION } = require('./src/lib/constants/endpoints.js');
const withBundleAnalyzer = require('@next/bundle-analyzer');
const withPWA = require('next-pwa')({
  dest: 'public',
  register: true,
  skipWaiting: true,
  disable: process.env.NODE_ENV === 'development',
  runtimeCaching: [
    {
      urlPattern: new RegExp(`^${BASE_URL}/${API_VERSION}/.*`),
      handler: 'NetworkFirst',
      options: {
        cacheName: 'api-cache',
        expiration: {
          maxEntries: 200,
          maxAgeSeconds: 3600,
        },
        cacheableResponse: {
          statuses: [0, 200],
        },
      },
    },
    {
      urlPattern: /^https:\/\/cdn\.austa\.health\/.*/,
      handler: 'CacheFirst',
      options: {
        cacheName: 'static-cache',
        expiration: {
          maxEntries: 100,
          maxAgeSeconds: 86400,
        },
      },
    },
  ],
});
const { withSentryConfig } = require('@sentry/nextjs');

/**
 * Content Security Policy configuration
 * Implements strict CSP rules for HIPAA compliance
 */
const ContentSecurityPolicy = `
  default-src 'self';
  script-src 'self' 'unsafe-eval' 'unsafe-inline';
  style-src 'self' 'unsafe-inline';
  img-src 'self' data: https:;
  font-src 'self' data:;
  connect-src 'self' ${BASE_URL} https://sentry.io;
  frame-ancestors 'none';
  media-src 'self' blob:;
  worker-src 'self' blob:;
  manifest-src 'self';
`.replace(/\s{2,}/g, ' ').trim();

// Create the base configuration
const nextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  env: {
    NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL ?? '',
    NEXT_PUBLIC_SENTRY_DSN: process.env.NEXT_PUBLIC_SENTRY_DSN ?? '',
  },
  headers: async () => {
    return [
      {
        source: '/:path*',
        headers: [
          {
            key: 'X-DNS-Prefetch-Control',
            value: 'on',
          },
          {
            key: 'Strict-Transport-Security',
            value: 'max-age=63072000; includeSubDomains; preload',
          },
          {
            key: 'X-Frame-Options',
            value: 'DENY',
          },
          {
            key: 'X-Content-Type-Options',
            value: 'nosniff',
          },
          {
            key: 'Referrer-Policy',
            value: 'strict-origin-when-cross-origin',
          },
          {
            key: 'Permissions-Policy',
            value: 'camera=(), microphone=(), geolocation=()',
          },
          {
            key: 'Content-Security-Policy',
            value: ContentSecurityPolicy,
          },
          {
            key: 'X-XSS-Protection',
            value: '1; mode=block',
          },
        ],
      },
    ];
  },
  images: {
    domains: ['cdn.austa.health', 'storage.austa.health'],
    deviceSizes: [640, 750, 828, 1080, 1200, 1920, 2048, 3840],
    imageSizes: [16, 32, 48, 64, 96, 128, 256, 384],
    formats: ['image/avif', 'image/webp'],
  },
  webpack: (config, { dev, isServer }) => {
    // Optimize bundle splitting
    config.optimization = {
      ...config.optimization,
      moduleIds: 'deterministic',
      runtimeChunk: 'single',
      splitChunks: {
        chunks: 'all',
        minSize: 20000,
        cacheGroups: {
          vendor: {
            test: /[\\/]node_modules[\\/]/,
            name: 'vendors',
            chunks: 'all',
          },
        },
      },
    };
    return config;
  },
};

// Export the final configuration with all wrappers
const finalConfig = () => {
  let config = withPWA(nextConfig);

  if (process.env.ANALYZE === 'true') {
    config = withBundleAnalyzer({
      enabled: true,
      openAnalyzer: true,
    })(config);
  }

  if (process.env.NODE_ENV === 'production') {
    config = withSentryConfig(config, {
      silent: process.env.NODE_ENV === 'development',
      hideSourceMaps: true,
      widenClientFileUpload: true,
    });
  }

  return config;
};

module.exports = finalConfig();