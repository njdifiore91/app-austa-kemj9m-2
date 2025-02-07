/**
 * Generate secure metadata for the dashboard pages
 */
export async function generateMetadata() {
  return {
    title: 'Dashboard | AUSTA SuperApp',
    description: 'Secure healthcare dashboard with real-time monitoring',
    robots: 'noindex, nofollow',
    headers: {
      'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none';",
      'X-Frame-Options': 'DENY',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      'Permissions-Policy': 'camera=(), microphone=(), geolocation=()'
    }
  };
} 