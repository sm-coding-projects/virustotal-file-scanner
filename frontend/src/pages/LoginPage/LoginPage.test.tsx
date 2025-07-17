import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { BrowserRouter } from 'react-router-dom';
import LoginPage from './LoginPage';
import api from '../../services/api';
import { useAuthStore } from '../../store/authStore';

// Mock the API service
jest.mock('../../services/api', () => ({
  post: jest.fn(),
}));

// Mock the useNavigate hook
jest.mock('react-router-dom', () => ({
  ...jest.requireActual('react-router-dom'),
  useNavigate: () => jest.fn(),
}));

// Mock the auth store
jest.mock('../../store/authStore', () => ({
  useAuthStore: jest.fn(),
}));

describe('LoginPage Component', () => {
  const mockLogin = jest.fn();
  
  beforeEach(() => {
    jest.clearAllMocks();
    
    // Mock the auth store
    (useAuthStore as jest.Mock).mockReturnValue({
      login: mockLogin,
    });
    
    // Default API mock implementation
    (api.post as jest.Mock).mockResolvedValue({
      data: {
        user: {
          id: '123',
          username: 'testuser',
          email: 'test@example.com',
        },
        access_token: 'test-token',
      },
    });
  });

  test('renders the login form', () => {
    render(
      <BrowserRouter>
        <LoginPage />
      </BrowserRouter>
    );
    
    expect(screen.getByRole('heading', { name: /Login/i })).toBeInTheDocument();
    expect(screen.getByLabelText(/Username or Email/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/Password/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Login/i })).toBeInTheDocument();
    expect(screen.getByText(/Don't have an account/i)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /Register/i })).toBeInTheDocument();
  });

  test('validates form inputs', async () => {
    render(
      <BrowserRouter>
        <LoginPage />
      </BrowserRouter>
    );
    
    // Try to submit the form without filling in the fields
    const submitButton = screen.getByRole('button', { name: /Login/i });
    await userEvent.click(submitButton);
    
    expect(await screen.findByText(/Please enter both username\/email and password/i)).toBeInTheDocument();
    expect(api.post).not.toHaveBeenCalled();
  });

  test('submits the form with valid inputs', async () => {
    render(
      <BrowserRouter>
        <LoginPage />
      </BrowserRouter>
    );
    
    // Fill in the form
    const usernameInput = screen.getByLabelText(/Username or Email/i);
    const passwordInput = screen.getByLabelText(/Password/i);
    const submitButton = screen.getByRole('button', { name: /Login/i });
    
    await userEvent.type(usernameInput, 'testuser');
    await userEvent.type(passwordInput, 'password123');
    await userEvent.click(submitButton);
    
    await waitFor(() => {
      expect(api.post).toHaveBeenCalledWith('/auth/login', {
        username: 'testuser',
        password: 'password123',
      });
      expect(mockLogin).toHaveBeenCalledWith(
        {
          id: '123',
          username: 'testuser',
          email: 'test@example.com',
        },
        'test-token'
      );
    });
  });

  test('displays error message on login failure', async () => {
    // Mock API to return an error
    (api.post as jest.Mock).mockRejectedValue({
      response: {
        data: {
          error: 'Invalid credentials',
        },
      },
    });
    
    render(
      <BrowserRouter>
        <LoginPage />
      </BrowserRouter>
    );
    
    // Fill in the form
    const usernameInput = screen.getByLabelText(/Username or Email/i);
    const passwordInput = screen.getByLabelText(/Password/i);
    const submitButton = screen.getByRole('button', { name: /Login/i });
    
    await userEvent.type(usernameInput, 'testuser');
    await userEvent.type(passwordInput, 'wrongpassword');
    await userEvent.click(submitButton);
    
    expect(await screen.findByText(/Invalid credentials/i)).toBeInTheDocument();
    expect(mockLogin).not.toHaveBeenCalled();
  });

  test('shows loading state during form submission', async () => {
    // Mock API to delay response
    (api.post as jest.Mock).mockImplementation(() => {
      return new Promise((resolve) => {
        setTimeout(() => {
          resolve({
            data: {
              user: {
                id: '123',
                username: 'testuser',
                email: 'test@example.com',
              },
              access_token: 'test-token',
            },
          });
        }, 100);
      });
    });
    
    render(
      <BrowserRouter>
        <LoginPage />
      </BrowserRouter>
    );
    
    // Fill in the form
    const usernameInput = screen.getByLabelText(/Username or Email/i);
    const passwordInput = screen.getByLabelText(/Password/i);
    const submitButton = screen.getByRole('button', { name: /Login/i });
    
    await userEvent.type(usernameInput, 'testuser');
    await userEvent.type(passwordInput, 'password123');
    await userEvent.click(submitButton);
    
    // Check for loading state
    expect(screen.getByText(/Logging in.../i)).toBeInTheDocument();
    expect(submitButton).toBeDisabled();
    
    // Wait for the API call to resolve
    await waitFor(() => {
      expect(mockLogin).toHaveBeenCalled();
    });
  });

  test('clears error when user starts typing', async () => {
    // Mock API to return an error
    (api.post as jest.Mock).mockRejectedValue({
      response: {
        data: {
          error: 'Invalid credentials',
        },
      },
    });
    
    render(
      <BrowserRouter>
        <LoginPage />
      </BrowserRouter>
    );
    
    // Fill in the form and submit to trigger an error
    const usernameInput = screen.getByLabelText(/Username or Email/i);
    const passwordInput = screen.getByLabelText(/Password/i);
    const submitButton = screen.getByRole('button', { name: /Login/i });
    
    await userEvent.type(usernameInput, 'testuser');
    await userEvent.type(passwordInput, 'wrongpassword');
    await userEvent.click(submitButton);
    
    // Wait for error message
    expect(await screen.findByText(/Invalid credentials/i)).toBeInTheDocument();
    
    // Start typing again
    await userEvent.type(usernameInput, 'a');
    
    // Error should be cleared
    expect(screen.queryByText(/Invalid credentials/i)).not.toBeInTheDocument();
  });
});