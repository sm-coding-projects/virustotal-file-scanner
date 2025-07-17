import React from 'react';
import { render, screen, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import { useAuthStore } from '../store/authStore';
import LoginPage from '../pages/LoginPage/LoginPage';
import ApiKeysPage from '../pages/ApiKeysPage/ApiKeysPage';
import FilesPage from '../pages/FilesPage/FilesPage';
import ScanResultsPage from '../pages/ScanResultsPage/ScanResultsPage';
import apiKeyService from '../services/apiKeyService';
import fileService from '../services/fileService';

// Mock the API services
jest.mock('../services/apiKeyService');
jest.mock('../services/fileService');
jest.mock('../services/api', () => ({
  __esModule: true,
  default: {
    interceptors: {
      request: { use: jest.fn() },
      response: { use: jest.fn() },
    },
  },
}));

// Mock the auth store
jest.mock('../store/authStore', () => ({
  useAuthStore: {
    getState: jest.fn(),
    setState: jest.fn(),
  },
}));

describe('Integration Tests', () => {
  // Reset all mocks before each test
  beforeEach(() => {
    jest.clearAllMocks();
    
    // Mock auth store state
    (useAuthStore.getState as jest.Mock).mockReturnValue({
      isAuthenticated: false,
      token: null,
      user: null,
      login: jest.fn((token, user) => {
        (useAuthStore.getState as jest.Mock).mockReturnValue({
          isAuthenticated: true,
          token,
          user,
          login: jest.fn(),
          logout: jest.fn(),
        });
      }),
      logout: jest.fn(),
    });
  });

  describe('Authentication and API Key Management Workflow', () => {
    test('User can login and manage API keys', async () => {
      // Mock login API response
      const mockLoginResponse = {
        access_token: 'test_token',
        refresh_token: 'test_refresh_token',
        user: {
          id: '1',
          username: 'testuser',
          email: 'test@example.com',
        },
      };
      
      // Mock API key service responses
      const mockApiKeys = [
        {
          id: '1',
          name: 'Test Key 1',
          is_active: true,
          created_at: '2023-01-01T00:00:00Z',
          updated_at: '2023-01-01T00:00:00Z',
        },
      ];
      
      (apiKeyService.getAllApiKeys as jest.Mock).mockResolvedValue(mockApiKeys);
      (apiKeyService.createApiKey as jest.Mock).mockResolvedValue({
        id: '2',
        name: 'New Test Key',
        is_active: true,
        created_at: '2023-01-02T00:00:00Z',
        updated_at: '2023-01-02T00:00:00Z',
      });
      (apiKeyService.validateApiKey as jest.Mock).mockResolvedValue({
        valid: true,
        message: 'API key is valid',
      });
      
      // Step 1: Render the login page
      render(
        <MemoryRouter initialEntries={['/login']}>
          <Routes>
            <Route path="/login" element={<LoginPage />} />
            <Route path="/api-keys" element={<ApiKeysPage />} />
          </Routes>
        </MemoryRouter>
      );
      
      // Step 2: Fill in login form
      const usernameInput = screen.getByLabelText(/username/i);
      const passwordInput = screen.getByLabelText(/password/i);
      const loginButton = screen.getByRole('button', { name: /login/i });
      
      await act(async () => {
        await userEvent.type(usernameInput, 'testuser');
        await userEvent.type(passwordInput, 'password123');
      });
      
      // Step 3: Submit login form
      // Mock the login API call
      const loginMock = jest.fn().mockResolvedValue(mockLoginResponse);
      (useAuthStore.getState() as any).login = loginMock;
      
      await act(async () => {
        await userEvent.click(loginButton);
      });
      
      // Step 4: Verify login was called
      await waitFor(() => {
        expect(loginMock).toHaveBeenCalled();
      });
      
      // Step 5: Navigate to API Keys page
      // We need to re-render with the authenticated state
      (useAuthStore.getState as jest.Mock).mockReturnValue({
        isAuthenticated: true,
        token: 'test_token',
        user: {
          id: '1',
          username: 'testuser',
          email: 'test@example.com',
        },
        login: jest.fn(),
        logout: jest.fn(),
      });
      
      render(
        <MemoryRouter initialEntries={['/api-keys']}>
          <Routes>
            <Route path="/api-keys" element={<ApiKeysPage />} />
          </Routes>
        </MemoryRouter>
      );
      
      // Step 6: Verify API keys are loaded
      await waitFor(() => {
        expect(apiKeyService.getAllApiKeys).toHaveBeenCalled();
      });
      
      // Step 7: Verify API key is displayed
      await waitFor(() => {
        expect(screen.getByText('Test Key 1')).toBeInTheDocument();
      });
      
      // Step 8: Add a new API key
      const addButton = screen.getByRole('button', { name: /add api key/i });
      
      await act(async () => {
        await userEvent.click(addButton);
      });
      
      // Step 9: Fill in the API key form
      const nameInput = screen.getByLabelText(/key name/i);
      const keyInput = screen.getByLabelText(/api key/i);
      const submitButton = screen.getByRole('button', { name: /save/i });
      
      await act(async () => {
        await userEvent.type(nameInput, 'New Test Key');
        await userEvent.type(keyInput, 'test_api_key_value');
      });
      
      // Step 10: Submit the form
      await act(async () => {
        await userEvent.click(submitButton);
      });
      
      // Step 11: Verify API key was created
      await waitFor(() => {
        expect(apiKeyService.createApiKey).toHaveBeenCalledWith('New Test Key', 'test_api_key_value');
      });
      
      // Step 12: Verify API keys are reloaded
      await waitFor(() => {
        expect(apiKeyService.getAllApiKeys).toHaveBeenCalledTimes(2);
      });
    });
  });

  describe('File Upload and Scan Workflow', () => {
    test('User can upload a file and scan it', async () => {
      // Mock authenticated state
      (useAuthStore.getState as jest.Mock).mockReturnValue({
        isAuthenticated: true,
        token: 'test_token',
        user: {
          id: '1',
          username: 'testuser',
          email: 'test@example.com',
        },
        login: jest.fn(),
        logout: jest.fn(),
      });
      
      // Mock API key service response
      const mockApiKeys = [
        {
          id: '1',
          name: 'Test Key 1',
          is_active: true,
          created_at: '2023-01-01T00:00:00Z',
          updated_at: '2023-01-01T00:00:00Z',
        },
      ];
      
      (apiKeyService.getAllApiKeys as jest.Mock).mockResolvedValue(mockApiKeys);
      
      // Mock file service responses
      const mockUploadResponse = {
        id: 'file1',
        filename: 'test.txt',
        file_size: 1024,
        mime_type: 'text/plain',
        hash_md5: 'test_md5',
        hash_sha1: 'test_sha1',
        hash_sha256: 'test_sha256',
        upload_date: '2023-01-01T00:00:00Z',
      };
      
      const mockScanResponse = {
        scan_id: 'scan1',
        status: 'pending',
      };
      
      const mockScanResults = {
        scan_id: 'scan1',
        file_id: 'file1',
        filename: 'test.txt',
        status: 'completed',
        detection_ratio: '0/70',
        scan_date: '2023-01-01T00:00:00Z',
        results: [
          {
            engine_name: 'TestAV1',
            engine_version: '1.0',
            result: null,
            category: 'harmless',
            update_date: '2023-01-01',
          },
          {
            engine_name: 'TestAV2',
            engine_version: '2.0',
            result: null,
            category: 'harmless',
            update_date: '2023-01-01',
          },
        ],
        summary: {
          stats: {
            malicious: 0,
            suspicious: 0,
            harmless: 60,
            undetected: 10,
          },
        },
      };
      
      (fileService.uploadFile as jest.Mock).mockResolvedValue(mockUploadResponse);
      (fileService.getFiles as jest.Mock).mockResolvedValue([mockUploadResponse]);
      (fileService.scanFile as jest.Mock).mockResolvedValue(mockScanResponse);
      (fileService.getScanResults as jest.Mock).mockResolvedValue(mockScanResults);
      
      // Step 1: Render the files page
      render(
        <MemoryRouter initialEntries={['/files']}>
          <Routes>
            <Route path="/files" element={<FilesPage />} />
            <Route path="/scan/:scanId" element={<ScanResultsPage />} />
          </Routes>
        </MemoryRouter>
      );
      
      // Step 2: Verify files are loaded
      await waitFor(() => {
        expect(fileService.getFiles).toHaveBeenCalled();
      });
      
      // Step 3: Upload a file
      // Mock the file input and upload
      const file = new File(['test file content'], 'test.txt', { type: 'text/plain' });
      const uploadMock = jest.fn().mockResolvedValue(mockUploadResponse);
      (fileService.uploadFile as jest.Mock) = uploadMock;
      
      // Find the upload button and simulate file selection
      const uploadButton = screen.getByText(/upload file/i);
      
      // Mock the file upload process
      await act(async () => {
        // Simulate file selection and upload
        await userEvent.upload(uploadButton, file);
      });
      
      // Step 4: Verify file was uploaded
      await waitFor(() => {
        expect(uploadMock).toHaveBeenCalled();
      });
      
      // Step 5: Scan the file
      const scanButton = screen.getByText(/scan/i);
      
      await act(async () => {
        await userEvent.click(scanButton);
      });
      
      // Step 6: Verify scan was initiated
      await waitFor(() => {
        expect(fileService.scanFile).toHaveBeenCalledWith('file1', '1');
      });
      
      // Step 7: Navigate to scan results
      // We need to re-render with the scan results route
      render(
        <MemoryRouter initialEntries={['/scan/scan1']}>
          <Routes>
            <Route path="/scan/:scanId" element={<ScanResultsPage />} />
          </Routes>
        </MemoryRouter>
      );
      
      // Step 8: Verify scan results are loaded
      await waitFor(() => {
        expect(fileService.getScanResults).toHaveBeenCalledWith('scan1');
      });
      
      // Step 9: Verify scan results are displayed
      await waitFor(() => {
        expect(screen.getByText('test.txt')).toBeInTheDocument();
        expect(screen.getByText('0/70')).toBeInTheDocument();
        expect(screen.getByText('TestAV1')).toBeInTheDocument();
        expect(screen.getByText('TestAV2')).toBeInTheDocument();
      });
    });
  });
});
</text>