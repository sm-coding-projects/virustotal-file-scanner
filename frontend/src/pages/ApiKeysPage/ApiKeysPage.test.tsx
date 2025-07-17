import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import ApiKeysPage from './ApiKeysPage';
import apiKeyService from '../../services/apiKeyService';

// Mock the API key service
jest.mock('../../services/apiKeyService', () => ({
  getAllApiKeys: jest.fn(),
  getApiKey: jest.fn(),
  createApiKey: jest.fn(),
  updateApiKey: jest.fn(),
  deleteApiKey: jest.fn(),
  validateApiKey: jest.fn(),
}));

describe('ApiKeysPage Component', () => {
  const mockApiKeys = [
    {
      id: '1',
      name: 'Test Key 1',
      is_active: true,
      created_at: '2023-01-01T00:00:00Z',
      updated_at: '2023-01-01T00:00:00Z',
    },
    {
      id: '2',
      name: 'Test Key 2',
      is_active: false,
      created_at: '2023-01-02T00:00:00Z',
      updated_at: '2023-01-02T00:00:00Z',
    },
  ];

  beforeEach(() => {
    jest.clearAllMocks();
    
    // Default mock implementations
    (apiKeyService.getAllApiKeys as jest.Mock).mockResolvedValue(mockApiKeys);
    (apiKeyService.validateApiKey as jest.Mock).mockResolvedValue({ valid: true, message: 'API key is valid' });
    (apiKeyService.createApiKey as jest.Mock).mockResolvedValue({
      id: '3',
      name: 'New Key',
      is_active: true,
      created_at: '2023-01-03T00:00:00Z',
      updated_at: '2023-01-03T00:00:00Z',
    });
    (apiKeyService.updateApiKey as jest.Mock).mockResolvedValue({
      id: '1',
      name: 'Updated Key',
      is_active: true,
      created_at: '2023-01-01T00:00:00Z',
      updated_at: '2023-01-03T00:00:00Z',
    });
    (apiKeyService.deleteApiKey as jest.Mock).mockResolvedValue(undefined);
  });

  test('renders the API keys page with loading state', () => {
    // Mock API call to not resolve immediately
    (apiKeyService.getAllApiKeys as jest.Mock).mockImplementation(() => {
      return new Promise((resolve) => {
        setTimeout(() => resolve(mockApiKeys), 100);
      });
    });
    
    render(<ApiKeysPage />);
    
    expect(screen.getByText(/API Key Management/i)).toBeInTheDocument();
    expect(screen.getByText(/Loading.../i)).toBeInTheDocument();
  });

  test('renders the API keys list after loading', async () => {
    render(<ApiKeysPage />);
    
    // Wait for the API keys to load
    await waitFor(() => {
      expect(apiKeyService.getAllApiKeys).toHaveBeenCalled();
    });
    
    expect(screen.getByText('Test Key 1')).toBeInTheDocument();
    expect(screen.getByText('Test Key 2')).toBeInTheDocument();
    expect(screen.getByText('Active')).toBeInTheDocument();
    expect(screen.getByText('Inactive')).toBeInTheDocument();
  });

  test('renders empty state when no API keys are available', async () => {
    (apiKeyService.getAllApiKeys as jest.Mock).mockResolvedValue([]);
    
    render(<ApiKeysPage />);
    
    // Wait for the API keys to load
    await waitFor(() => {
      expect(apiKeyService.getAllApiKeys).toHaveBeenCalled();
    });
    
    expect(screen.getByText(/No API keys found/i)).toBeInTheDocument();
  });

  test('validates form inputs when adding a new API key', async () => {
    render(<ApiKeysPage />);
    
    // Wait for the API keys to load
    await waitFor(() => {
      expect(apiKeyService.getAllApiKeys).toHaveBeenCalled();
    });
    
    // Click the add button
    const addButton = screen.getByRole('button', { name: /add api key/i });
    fireEvent.click(addButton);
    
    // Try to submit the form without filling in the fields
    const submitButton = screen.getByRole('button', { name: /save/i });
    fireEvent.click(submitButton);
    
    // Check for validation errors
    expect(screen.getByText(/key name is required/i)).toBeInTheDocument();
    expect(screen.getByText(/api key is required/i)).toBeInTheDocument();
    
    // Fill in the form
    const nameInput = screen.getByLabelText(/key name/i);
    const keyInput = screen.getByLabelText(/api key/i);
    
    fireEvent.change(nameInput, { target: { value: 'New Key' } });
    fireEvent.change(keyInput, { target: { value: 'test_api_key' } });
    
    // Submit the form
    fireEvent.click(submitButton);
    
    // Check that the API key is validated
    await waitFor(() => {
      expect(apiKeyService.validateApiKey).toHaveBeenCalledWith('test_api_key');
    });
    
    // Check that the API key is created
    await waitFor(() => {
      expect(apiKeyService.createApiKey).toHaveBeenCalledWith('New Key', 'test_api_key');
    });
    
    // Check that the API keys are reloaded
    await waitFor(() => {
      expect(apiKeyService.getAllApiKeys).toHaveBeenCalledTimes(2);
    });
  });

  test('handles API key validation failure', async () => {
    // Mock validation failure
    (apiKeyService.validateApiKey as jest.Mock).mockResolvedValue({
      valid: false,
      message: 'Invalid API key',
    });
    
    render(<ApiKeysPage />);
    
    // Wait for the API keys to load
    await waitFor(() => {
      expect(apiKeyService.getAllApiKeys).toHaveBeenCalled();
    });
    
    // Click the add button
    const addButton = screen.getByRole('button', { name: /add api key/i });
    fireEvent.click(addButton);
    
    // Fill in the form
    const nameInput = screen.getByLabelText(/key name/i);
    const keyInput = screen.getByLabelText(/api key/i);
    
    fireEvent.change(nameInput, { target: { value: 'New Key' } });
    fireEvent.change(keyInput, { target: { value: 'invalid_api_key' } });
    
    // Submit the form
    const submitButton = screen.getByRole('button', { name: /save/i });
    fireEvent.click(submitButton);
    
    // Check that the API key is validated
    await waitFor(() => {
      expect(apiKeyService.validateApiKey).toHaveBeenCalledWith('invalid_api_key');
    });
    
    // Check for validation error message
    expect(await screen.findByText(/Invalid API key/i)).toBeInTheDocument();
    
    // Check that the API key is not created
    expect(apiKeyService.createApiKey).not.toHaveBeenCalled();
  });

  test('updates an existing API key', async () => {
    render(<ApiKeysPage />);
    
    // Wait for the API keys to load
    await waitFor(() => {
      expect(apiKeyService.getAllApiKeys).toHaveBeenCalled();
    });
    
    // Click the edit button for the first key
    const editButtons = screen.getAllByRole('button', { name: /edit/i });
    fireEvent.click(editButtons[0]);
    
    // Check that the form is populated with the key data
    const nameInput = screen.getByLabelText(/key name/i);
    expect(nameInput).toHaveValue('Test Key 1');
    
    // Update the name
    fireEvent.change(nameInput, { target: { value: 'Updated Key' } });
    
    // Submit the form
    const submitButton = screen.getByRole('button', { name: /save/i });
    fireEvent.click(submitButton);
    
    // Check that the API key is updated
    await waitFor(() => {
      expect(apiKeyService.updateApiKey).toHaveBeenCalledWith('1', {
        name: 'Updated Key',
        is_active: true,
      });
    });
    
    // Check that the API keys are reloaded
    await waitFor(() => {
      expect(apiKeyService.getAllApiKeys).toHaveBeenCalledTimes(2);
    });
  });

  test('deletes an API key', async () => {
    render(<ApiKeysPage />);
    
    // Wait for the API keys to load
    await waitFor(() => {
      expect(apiKeyService.getAllApiKeys).toHaveBeenCalled();
    });
    
    // Click the delete button for the first key
    const deleteButtons = screen.getAllByRole('button', { name: /delete/i });
    fireEvent.click(deleteButtons[0]);
    
    // Confirm the deletion
    const confirmButton = screen.getByRole('button', { name: /confirm/i });
    fireEvent.click(confirmButton);
    
    // Check that the API key is deleted
    await waitFor(() => {
      expect(apiKeyService.deleteApiKey).toHaveBeenCalledWith('1');
    });
    
    // Check that the API keys are reloaded
    await waitFor(() => {
      expect(apiKeyService.getAllApiKeys).toHaveBeenCalledTimes(2);
    });
  });

  test('toggles API key active status', async () => {
    render(<ApiKeysPage />);
    
    // Wait for the API keys to load
    await waitFor(() => {
      expect(apiKeyService.getAllApiKeys).toHaveBeenCalled();
    });
    
    // Click the toggle button for the first key
    const toggleButtons = screen.getAllByRole('switch');
    fireEvent.click(toggleButtons[0]);
    
    // Check that the API key is updated
    await waitFor(() => {
      expect(apiKeyService.updateApiKey).toHaveBeenCalledWith('1', {
        is_active: false,
      });
    });
    
    // Check that the API keys are reloaded
    await waitFor(() => {
      expect(apiKeyService.getAllApiKeys).toHaveBeenCalledTimes(2);
    });
  });
});