import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import FileUpload from './FileUpload';
import * as fileService from '../../services/fileService';

// Mock the file service
jest.mock('../../services/fileService', () => ({
  uploadFile: jest.fn(),
  validateFile: jest.fn(),
  formatFileSize: jest.fn((size) => `${size} bytes`),
}));

describe('FileUpload Component', () => {
  const mockOnUploadSuccess = jest.fn();
  const mockOnUploadError = jest.fn();
  
  beforeEach(() => {
    jest.clearAllMocks();
    
    // Default mock implementations
    (fileService.validateFile as jest.Mock).mockImplementation(() => ({ valid: true }));
    (fileService.uploadFile as jest.Mock).mockResolvedValue({
      id: '123',
      filename: 'test-file.txt',
      file_size: 1024,
      mime_type: 'text/plain',
      hash_md5: 'md5hash',
      hash_sha1: 'sha1hash',
      hash_sha256: 'sha256hash',
      upload_date: '2023-01-01T00:00:00Z',
    });
  });

  test('renders the file upload component', () => {
    render(
      <FileUpload 
        onUploadSuccess={mockOnUploadSuccess} 
        onUploadError={mockOnUploadError} 
      />
    );
    
    expect(screen.getByText(/Drag and drop files here, or click to select files/i)).toBeInTheDocument();
    expect(screen.getByText(/Maximum file size:/i)).toBeInTheDocument();
    expect(screen.getByText(/Supported file types: All/i)).toBeInTheDocument();
  });

  test('shows drag active state when dragging files', () => {
    render(
      <FileUpload 
        onUploadSuccess={mockOnUploadSuccess} 
        onUploadError={mockOnUploadError} 
      />
    );
    
    const dropZone = screen.getByRole('button', { name: /File upload area/i });
    
    fireEvent.dragEnter(dropZone);
    expect(screen.getByText(/Drop files here to upload/i)).toBeInTheDocument();
    
    fireEvent.dragLeave(dropZone);
    expect(screen.getByText(/Drag and drop files here, or click to select files/i)).toBeInTheDocument();
  });

  test('handles file selection via input', async () => {
    render(
      <FileUpload 
        onUploadSuccess={mockOnUploadSuccess} 
        onUploadError={mockOnUploadError} 
      />
    );
    
    const file = new File(['test content'], 'test-file.txt', { type: 'text/plain' });
    const input = screen.getByLabelText(/File upload input/i);
    
    await userEvent.upload(input, file);
    
    expect(await screen.findByText('test-file.txt')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Upload and Scan/i })).toBeInTheDocument();
  });

  test('validates files based on size constraints', async () => {
    // Mock the validateFile function to return an error for large files
    (fileService.validateFile as jest.Mock).mockImplementation((file) => {
      if (file.name === 'large-file.txt') {
        return { valid: false, error: 'File is too large. Maximum size is 32MB.' };
      }
      return { valid: true };
    });
    
    render(
      <FileUpload 
        onUploadSuccess={mockOnUploadSuccess} 
        onUploadError={mockOnUploadError} 
        maxFileSize={1000} // 1000 bytes max
      />
    );
    
    const largeFile = new File(['x'.repeat(2000)], 'large-file.txt', { type: 'text/plain' });
    const input = screen.getByLabelText(/File upload input/i);
    
    await userEvent.upload(input, largeFile);
    
    expect(await screen.findByText('large-file.txt')).toBeInTheDocument();
    expect(screen.getByText(/File is too large/i)).toBeInTheDocument();
  });

  test('uploads files when upload button is clicked', async () => {
    render(
      <FileUpload 
        onUploadSuccess={mockOnUploadSuccess} 
        onUploadError={mockOnUploadError} 
      />
    );
    
    const file = new File(['test content'], 'test-file.txt', { type: 'text/plain' });
    const input = screen.getByLabelText(/File upload input/i);
    
    await userEvent.upload(input, file);
    
    const uploadButton = screen.getByRole('button', { name: /Upload and Scan/i });
    await userEvent.click(uploadButton);
    
    await waitFor(() => {
      expect(fileService.uploadFile).toHaveBeenCalledWith(file);
      expect(mockOnUploadSuccess).toHaveBeenCalled();
    });
  });

  test('handles upload errors', async () => {
    // Mock the uploadFile function to throw an error
    (fileService.uploadFile as jest.Mock).mockRejectedValue(new Error('Network error'));
    
    render(
      <FileUpload 
        onUploadSuccess={mockOnUploadSuccess} 
        onUploadError={mockOnUploadError} 
      />
    );
    
    const file = new File(['test content'], 'test-file.txt', { type: 'text/plain' });
    const input = screen.getByLabelText(/File upload input/i);
    
    await userEvent.upload(input, file);
    
    const uploadButton = screen.getByRole('button', { name: /Upload and Scan/i });
    await userEvent.click(uploadButton);
    
    await waitFor(() => {
      expect(mockOnUploadError).toHaveBeenCalledWith('Network error');
      expect(screen.getByText(/Upload failed/i)).toBeInTheDocument();
    });
  });

  test('allows removing selected files', async () => {
    render(
      <FileUpload 
        onUploadSuccess={mockOnUploadSuccess} 
        onUploadError={mockOnUploadError} 
      />
    );
    
    const file = new File(['test content'], 'test-file.txt', { type: 'text/plain' });
    const input = screen.getByLabelText(/File upload input/i);
    
    await userEvent.upload(input, file);
    
    expect(await screen.findByText('test-file.txt')).toBeInTheDocument();
    
    const removeButton = screen.getByRole('button', { name: /Remove test-file.txt/i });
    await userEvent.click(removeButton);
    
    expect(screen.queryByText('test-file.txt')).not.toBeInTheDocument();
  });
});