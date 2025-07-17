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
    
    // Wait for the A