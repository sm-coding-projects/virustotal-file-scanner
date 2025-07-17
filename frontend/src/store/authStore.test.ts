import { act, renderHook } from '@testing-library/react';
import { useAuthStore } from './authStore';

// Mock the persist middleware
jest.mock('zustand/middleware', () => ({
  persist: (config) => (set, get, api) => config(set, get, api),
}));

describe('Auth Store', () => {
  beforeEach(() => {
    // Clear the store before each test
    act(() => {
      useAuthStore.getState().logout();
    });
  });

  test('should initialize with default values', () => {
    const { result } = renderHook(() => useAuthStore());
    
    expect(result.current.user).toBeNull();
    expect(result.current.token).toBeNull();
    expect(result.current.isAuthenticated).toBe(false);
  });

  test('should update state on login', () => {
    const { result } = renderHook(() => useAuthStore());
    
    const mockUser = { id: '123', username: 'testuser', email: 'test@example.com' };
    const mockToken = 'test-token';
    
    act(() => {
      result.current.login(mockUser, mockToken);
    });
    
    expect(result.current.user).toEqual(mockUser);
    expect(result.current.token).toBe(mockToken);
    expect(result.current.isAuthenticated).toBe(true);
  });

  test('should clear state on logout', () => {
    const { result } = renderHook(() => useAuthStore());
    
    // First login
    const mockUser = { id: '123', username: 'testuser', email: 'test@example.com' };
    const mockToken = 'test-token';
    
    act(() => {
      result.current.login(mockUser, mockToken);
    });
    
    // Then logout
    act(() => {
      result.current.logout();
    });
    
    expect(result.current.user).toBeNull();
    expect(result.current.token).toBeNull();
    expect(result.current.isAuthenticated).toBe(false);
  });

  test('should update user information', () => {
    const { result } = renderHook(() => useAuthStore());
    
    // First login
    const mockUser = { id: '123', username: 'testuser', email: 'test@example.com' };
    const mockToken = 'test-token';
    
    act(() => {
      result.current.login(mockUser, mockToken);
    });
    
    // Then update user
    const updatedUser = { id: '123', username: 'updateduser', email: 'updated@example.com' };
    
    act(() => {
      result.current.updateUser(updatedUser);
    });
    
    expect(result.current.user).toEqual(updatedUser);
    expect(result.current.token).toBe(mockToken); // Token should remain unchanged
    expect(result.current.isAuthenticated).toBe(true); // Authentication status should remain unchanged
  });
});