// Jest globals are automatically available through @types/jest
// Mock external dependencies
jest.mock('@agenda-bella/shared', () => ({
  logger: {
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
    debug: jest.fn(),
    child: jest.fn(() => ({
      info: jest.fn(),
      error: jest.fn(),
    })),
  },
}));

// Type definitions for Express-like mock objects
interface MockRequest {
  headers: Record<string, string>;
  socket: {
    remoteAddress: string;
  };
  sessionID: string;
}

interface MockResponse {
  status: jest.MockedFunction<(code: number) => MockResponse>;
  json: jest.MockedFunction<(data: unknown) => MockResponse>;
}

type MockNext = jest.MockedFunction<() => void>;

// Export typed mock utilities for use in tests
export const mockRequest: MockRequest = {
  headers: {},
  socket: { remoteAddress: '127.0.0.1' },
  sessionID: 'test-session',
};

export const mockResponse: MockResponse = {
  status: jest.fn().mockReturnThis() as jest.MockedFunction<(code: number) => MockResponse>,
  json: jest.fn().mockReturnThis() as jest.MockedFunction<(data: unknown) => MockResponse>,
};

export const mockNext: MockNext = jest.fn();
