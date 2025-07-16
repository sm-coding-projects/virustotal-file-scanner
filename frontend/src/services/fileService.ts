import api from './api';

export interface FileUploadResponse {
  id: string;
  filename: string;
  file_size: number;
  mime_type: string;
  hash_md5: string;
  hash_sha1: string;
  hash_sha256: string;
  upload_date: string;
  scan?: {
    scan_id?: string;
    status?: string;
    message?: string;
    error?: string;
  };
}

export interface FileListItem {
  id: string;
  filename: string;
  file_size: number;
  mime_type: string;
  hash_md5: string;
  hash_sha1: string;
  hash_sha256: string;
  upload_date: string;
}

export interface ScanResult {
  scan_id: string;
  file_id: string;
  filename: string;
  status: string;
  detection_ratio: string;
  scan_date: string;
  results?: Array<{
    engine_name: string;
    engine_version: string;
    result: string;
    category: string;
    update_date: string;
  }>;
  summary?: {
    stats: {
      malicious: number;
      suspicious: number;
      harmless: number;
      undetected: number;
      timeout: number;
      [key: string]: number;
    };
  };
}

/**
 * Upload a file to the server
 * @param file The file to upload
 * @returns Promise with the upload response
 */
export const uploadFile = async (file: File): Promise<FileUploadResponse> => {
  const formData = new FormData();
  formData.append('file', file);

  const response = await api.post('/files/upload', formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
    onUploadProgress: (progressEvent) => {
      // You can use this to track upload progress if needed
      const percentCompleted = Math.round((progressEvent.loaded * 100) / progressEvent.total!);
      console.log(`Upload progress: ${percentCompleted}%`);
    },
  });

  return response.data;
};

/**
 * Get a list of all uploaded files
 * @returns Promise with the list of files
 */
export const getFiles = async (): Promise<FileListItem[]> => {
  const response = await api.get('/files');
  return response.data;
};

/**
 * Get details of a specific file
 * @param fileId The ID of the file
 * @returns Promise with the file details
 */
export const getFile = async (fileId: string): Promise<FileListItem> => {
  const response = await api.get(`/files/${fileId}`);
  return response.data;
};

/**
 * Delete a file
 * @param fileId The ID of the file to delete
 * @returns Promise with the deletion response
 */
export const deleteFile = async (fileId: string): Promise<{ message: string }> => {
  const response = await api.delete(`/files/${fileId}`);
  return response.data;
};

/**
 * Get scan results for a file
 * @param fileId The ID of the file
 * @returns Promise with the scan results
 */
export const getFileScanResults = async (fileId: string): Promise<ScanResult[]> => {
  const response = await api.get(`/scan/file/${fileId}`);
  return response.data;
};

/**
 * Initiate a scan for a file
 * @param fileId The ID of the file to scan
 * @param apiKeyId Optional API key ID to use for scanning
 * @returns Promise with the scan response
 */
export const scanFile = async (fileId: string, apiKeyId?: string): Promise<{ scan_id: string; status: string }> => {
  const response = await api.post(`/scan/file/${fileId}`, apiKeyId ? { api_key_id: apiKeyId } : {});
  return response.data;
};

/**
 * Get the status of a scan
 * @param scanId The ID of the scan
 * @returns Promise with the scan status
 */
export const getScanStatus = async (scanId: string): Promise<{ scan_id: string; status: string; detection_ratio?: string }> => {
  const response = await api.get(`/scan/${scanId}/status`);
  return response.data;
};

/**
 * Get detailed results of a scan
 * @param scanId The ID of the scan
 * @returns Promise with the detailed scan results
 */
export const getScanResults = async (scanId: string): Promise<ScanResult> => {
  const response = await api.get(`/scan/${scanId}/results`);
  return response.data;
};

/**
 * Format file size in a human-readable format
 * @param bytes File size in bytes
 * @returns Formatted file size string
 */
export const formatFileSize = (bytes: number): string => {
  if (bytes === 0) return '0 Bytes';
  
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
};

/**
 * Check if a file is valid based on size and type constraints
 * @param file The file to validate
 * @param maxSize Maximum file size in bytes
 * @returns Object with validation result and error message if any
 */
export const validateFile = (file: File, maxSize: number = 32 * 1024 * 1024): { valid: boolean; error?: string } => {
  if (file.size > maxSize) {
    return { 
      valid: false, 
      error: `File is too large. Maximum size is ${formatFileSize(maxSize)}.` 
    };
  }
  
  return { valid: true };
};

export default {
  uploadFile,
  getFiles,
  getFile,
  deleteFile,
  getFileScanResults,
  scanFile,
  getScanStatus,
  getScanResults,
  formatFileSize,
  validateFile,
};