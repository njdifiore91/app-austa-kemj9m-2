/**
 * @fileoverview Test setup for shared module
 */

// Add custom matchers
expect.extend({
  toBeValidError(received: any) {
    const pass = received &&
      typeof received.code === 'string' &&
      typeof received.message === 'string';

    return {
      message: () =>
        `expected ${received} to be a valid error with code and message properties`,
      pass,
    };
  },
});

// Global test setup
beforeAll(() => {
  // Add any global setup here
});

// Global test teardown
afterAll(() => {
  // Add any global cleanup here
});

// Reset mocks between tests
beforeEach(() => {
  jest.resetAllMocks();
}); 