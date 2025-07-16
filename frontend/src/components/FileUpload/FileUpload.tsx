import React, { useState, useRef, useCallback } from 'react';
import { uploadFile, validateFile, formatFileSize } from '../../services/fileService';

interface FileUploadProps {
  onUploadSuccess: (fileData: any) => void;
  onUploadError: (error: string) => void;
  maxFileSize?: number; // in bytes, default is 32MB
}

const FileUpload: React.FC<FileUploadProps> = ({ 
  onUploadSuccess, 
  onUploadError, 
  maxFileSize = 32 * 1024 * 1024 // 32MB default
}) => {
  const [isDragging, setIsDragging] = useState(false);
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);
  const [uploadProgress, setUploadProgress] = useState<{ [key: string]: number }>({});
  const [uploadStatus, setUploadStatus] = useState<{ [key: string]: 'pending' | 'uploading' | 'success' | 'error' }>({});
  const [validationErrors, setValidationErrors] = useState<{ [key: string]: string }>({});
  const [isUploading, setIsUploading] = useState(false);
  
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Handle drag events
  const handleDragEnter = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  }, []);

  const handleDragOver = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  }, []);

  // Process files when dropped or selected
  const processFiles = useCallback((files: FileList) => {
    const newFiles: File[] = [];
    const newValidationErrors: { [key: string]: string } = {};
    
    Array.from(files).forEach(file => {
      // Check for duplicate files
      const isDuplicate = selectedFiles.some(existingFile => 
        existingFile.name === file.name && 
        existingFile.size === file.size
      );
      
      if (isDuplicate) {
        newValidationErrors[file.name] = 'File already selected.';
        return;
      }
      
      const validation = validateFile(file, maxFileSize);
      
      if (validation.valid) {
        newFiles.push(file);
      } else if (validation.error) {
        newValidationErrors[file.name] = validation.error;
      }
    });
    
    if (Object.keys(newValidationErrors).length > 0) {
      setValidationErrors(prev => ({ ...prev, ...newValidationErrors }));
    }
    
    if (newFiles.length > 0) {
      setSelectedFiles(prev => [...prev, ...newFiles]);
      
      // Initialize upload status and progress for new files
      const newUploadStatus: { [key: string]: 'pending' | 'uploading' | 'success' | 'error' } = {};
      const newUploadProgress: { [key: string]: number } = {};
      
      newFiles.forEach(file => {
        newUploadStatus[file.name] = 'pending';
        newUploadProgress[file.name] = 0;
      });
      
      setUploadStatus(prev => ({ ...prev, ...newUploadStatus }));
      setUploadProgress(prev => ({ ...prev, ...newUploadProgress }));
    }
  }, [maxFileSize]);

  // Handle file drop
  const handleDrop = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
    
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      processFiles(e.dataTransfer.files);
    }
  }, [processFiles]);

  // Handle file selection via input
  const handleFileSelect = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      processFiles(e.target.files);
      // Reset the input value so the same file can be selected again if needed
      e.target.value = '';
    }
  }, [processFiles]);

  // Open file dialog when clicking on the drop zone
  const openFileDialog = () => {
    if (fileInputRef.current) {
      fileInputRef.current.click();
    }
  };

  // Remove a file from the selected files list
  const removeFile = (fileName: string) => {
    setSelectedFiles(prev => prev.filter(file => file.name !== fileName));
    setValidationErrors(prev => {
      const newErrors = { ...prev };
      delete newErrors[fileName];
      return newErrors;
    });
    setUploadStatus(prev => {
      const newStatus = { ...prev };
      delete newStatus[fileName];
      return newStatus;
    });
    setUploadProgress(prev => {
      const newProgress = { ...prev };
      delete newProgress[fileName];
      return newProgress;
    });
  };

  // Upload all selected files
  const uploadFiles = async () => {
    if (selectedFiles.length === 0 || isUploading) return;
    
    setIsUploading(true);
    
    for (const file of selectedFiles) {
      try {
        setUploadStatus(prev => ({ ...prev, [file.name]: 'uploading' }));
        
        // Create an XMLHttpRequest to track upload progress
        const xhr = new XMLHttpRequest();
        const formData = new FormData();
        formData.append('file', file);
        
        xhr.upload.addEventListener('progress', (event) => {
          if (event.lengthComputable) {
            const progress = Math.round((event.loaded * 100) / event.total);
            setUploadProgress(prev => ({ ...prev, [file.name]: progress }));
          }
        });
        
        // Use a promise to handle the XHR request
        const response = await new Promise<any>((resolve, reject) => {
          // Get the API base URL from environment or default to localhost
          const baseUrl = process.env.REACT_APP_API_URL || 'http://localhost:5000/api';
          xhr.open('POST', `${baseUrl}/files/upload`);
          
          // Get the auth token from localStorage
          const token = localStorage.getItem('token');
          if (token) {
            xhr.setRequestHeader('Authorization', `Bearer ${token}`);
          }
          
          xhr.onload = () => {
            if (xhr.status >= 200 && xhr.status < 300) {
              resolve(JSON.parse(xhr.responseText));
            } else {
              reject(new Error(`HTTP Error: ${xhr.status}`));
            }
          };
          
          xhr.onerror = () => reject(new Error('Network Error'));
          xhr.send(formData);
        });
        
        setUploadStatus(prev => ({ ...prev, [file.name]: 'success' }));
        onUploadSuccess(response);
        
        // Remove the file from the list after successful upload
        setTimeout(() => {
          removeFile(file.name);
        }, 2000);
        
      } catch (error) {
        console.error(`Error uploading ${file.name}:`, error);
        setUploadStatus(prev => ({ ...prev, [file.name]: 'error' }));
        onUploadError(error instanceof Error ? error.message : 'Unknown error occurred');
      }
    }
    
    setIsUploading(false);
  };

  return (
    <div className="file-upload-component">
      <div 
        className={`file-drop-zone ${isDragging ? 'active' : ''} ${Object.keys(validationErrors).length > 0 ? 'error' : ''}`}
        onDragEnter={handleDragEnter}
        onDragLeave={handleDragLeave}
        onDragOver={handleDragOver}
        onDrop={handleDrop}
        onClick={openFileDialog}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            openFileDialog();
          }
        }}
        aria-label="File upload area. Click or press Enter to select files, or drag and drop files here"
        aria-describedby="upload-instructions"
      >
        <div className="file-drop-content">
          <i className="file-icon" aria-hidden="true">{isDragging ? '📥' : '📁'}</i>
          <p id="upload-instructions">
            {isDragging ? 'Drop files here to upload' : 'Drag and drop files here, or click to select files'}
          </p>
          <input 
            type="file" 
            className="file-input" 
            ref={fileInputRef}
            onChange={handleFileSelect}
            multiple
            aria-label="File upload input"
            tabIndex={-1}
          />
        </div>
      </div>
      
      <div className="upload-info">
        <p>Maximum file size: {formatFileSize(maxFileSize)}</p>
        <p>Supported file types: All</p>
      </div>
      
      {selectedFiles.length > 0 && (
        <div className="selected-files" aria-live="polite">
          <h3>Selected Files</h3>
          <ul className="file-list" role="list">
            {selectedFiles.map((file, index) => (
              <li key={`${file.name}-${index}`} className="file-item">
                <div className="file-preview">
                  <div className="file-preview-icon" aria-hidden="true">📄</div>
                  <div className="file-preview-info">
                    <div className="file-preview-name">{file.name}</div>
                    <div className="file-preview-size">{formatFileSize(file.size)}</div>
                    
                    {validationErrors[file.name] && (
                      <div className="file-validation-error" role="alert">
                        {validationErrors[file.name]}
                      </div>
                    )}
                    
                    {uploadStatus[file.name] && (
                      <div className="file-progress" role="progressbar" 
                           aria-valuenow={uploadProgress[file.name]} 
                           aria-valuemin={0} 
                           aria-valuemax={100}
                           aria-label={`Upload progress for ${file.name}: ${uploadProgress[file.name]}%`}>
                        <div 
                          className={`file-progress-bar ${uploadStatus[file.name]}`} 
                          style={{ width: `${uploadProgress[file.name]}%` }}
                        ></div>
                      </div>
                    )}
                    
                    {uploadStatus[file.name] === 'uploading' && (
                      <div className="file-status-text">
                        Uploading: {uploadProgress[file.name]}%
                      </div>
                    )}
                    
                    {uploadStatus[file.name] === 'success' && (
                      <div className="file-validation-success" role="status">
                        Upload successful!
                      </div>
                    )}
                    
                    {uploadStatus[file.name] === 'error' && (
                      <div className="file-validation-error" role="alert">
                        Upload failed. Please try again.
                      </div>
                    )}
                  </div>
                  <button 
                    className="file-preview-remove" 
                    onClick={(e) => {
                      e.stopPropagation();
                      removeFile(file.name);
                    }}
                    disabled={uploadStatus[file.name] === 'uploading'}
                    aria-label={`Remove ${file.name}`}
                  >
                    ✖
                  </button>
                </div>
              </li>
            ))}
          </ul>
          
          <button 
            className="btn btn-primary upload-button"
            onClick={uploadFiles}
            disabled={
              isUploading || 
              selectedFiles.length === 0 || 
              Object.values(uploadStatus).some(status => status === 'uploading')
            }
            aria-busy={isUploading}
          >
            {isUploading ? 'Uploading...' : 'Upload and Scan'}
          </button>
        </div>
      )}
    </div>
  );
};

export default FileUpload;