import React, { useState, useEffect } from 'react';
import './FilesPage.css';
import FileUpload from '../../components/FileUpload/FileUpload';
import { getFiles, deleteFile, scanFile, formatFileSize, FileListItem } from '../../services/fileService';

const FilesPage: React.FC = () => {
  const [files, setFiles] = useState<FileListItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [refreshTrigger, setRefreshTrigger] = useState<number>(0);
  const [scanningFiles, setScanningFiles] = useState<Set<string>>(new Set());

  // Load files when component mounts or refreshTrigger changes
  useEffect(() => {
    const fetchFiles = async () => {
      try {
        setLoading(true);
        const fetchedFiles = await getFiles();
        setFiles(fetchedFiles);
        setError(null);
      } catch (err) {
        console.error('Error fetching files:', err);
        setError('Failed to load files. Please try again later.');
      } finally {
        setLoading(false);
      }
    };

    fetchFiles();
  }, [refreshTrigger]);

  // Handle successful file upload
  const handleUploadSuccess = (fileData: any) => {
    // Refresh the file list
    setRefreshTrigger(prev => prev + 1);
  };

  // Handle file upload error
  const handleUploadError = (errorMessage: string) => {
    setError(`Upload error: ${errorMessage}`);
    // Clear error after 5 seconds
    setTimeout(() => setError(null), 5000);
  };

  // Handle file deletion
  const handleDeleteFile = async (fileId: string, filename: string) => {
    if (window.confirm(`Are you sure you want to delete "${filename}"? This action cannot be undone.`)) {
      try {
        await deleteFile(fileId);
        // Refresh the file list
        setRefreshTrigger(prev => prev + 1);
      } catch (err) {
        console.error('Error deleting file:', err);
        setError('Failed to delete file. Please try again later.');
        // Clear error after 5 seconds
        setTimeout(() => setError(null), 5000);
      }
    }
  };

  // Handle file scan
  const handleScanFile = async (fileId: string) => {
    try {
      setScanningFiles(prev => new Set(prev).add(fileId));
      await scanFile(fileId);
      // Refresh the file list
      setRefreshTrigger(prev => prev + 1);
    } catch (err) {
      console.error('Error scanning file:', err);
      setError('Failed to scan file. Please try again later.');
      // Clear error after 5 seconds
      setTimeout(() => setError(null), 5000);
    } finally {
      setScanningFiles(prev => {
        const newSet = new Set(prev);
        newSet.delete(fileId);
        return newSet;
      });
    }
  };

  // Format date for display
  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleString();
  };

  return (
    <div className="files-page">
      <h1>File Upload</h1>
      <p className="page-description">
        Upload files to scan them for malicious content using the VirusTotal API.
      </p>
      
      {error && (
        <div className="alert alert-danger" role="alert">
          {error}
        </div>
      )}
      
      <div className="card">
        <div className="card-header">
          <h2>Upload Files</h2>
        </div>
        <div className="card-body">
          <FileUpload 
            onUploadSuccess={handleUploadSuccess}
            onUploadError={handleUploadError}
            maxFileSize={32 * 1024 * 1024} // 32MB
          />
        </div>
      </div>
      
      <section className="uploaded-files" aria-labelledby="uploaded-files-heading">
        <h2 id="uploaded-files-heading">Uploaded Files</h2>
        
        {loading ? (
          <div className="loading-spinner" role="status" aria-live="polite">
            <span className="sr-only">Loading files...</span>
            Loading files...
          </div>
        ) : files.length === 0 ? (
          <div className="empty-state" role="status">
            <p>No files uploaded yet. Use the upload form above to get started.</p>
          </div>
        ) : (
          <div className="files-table-container">
            <div className="sr-only" aria-live="polite">
              {files.length} file{files.length !== 1 ? 's' : ''} uploaded
            </div>
            <table className="table" role="table" aria-label="Uploaded files">
              <thead>
                <tr>
                  <th scope="col">Filename</th>
                  <th scope="col" className="mobile-hidden">Size</th>
                  <th scope="col" className="mobile-hidden">Upload Date</th>
                  <th scope="col" className="mobile-hidden">Hash (SHA-256)</th>
                  <th scope="col">Actions</th>
                </tr>
              </thead>
              <tbody>
                {files.map(file => (
                  <tr key={file.id}>
                    <th scope="row">{file.filename}</th>
                    <td className="mobile-hidden">{formatFileSize(file.file_size)}</td>
                    <td className="mobile-hidden">
                      <time dateTime={file.upload_date}>
                        {formatDate(file.upload_date)}
                      </time>
                    </td>
                    <td className="mobile-hidden">
                      <span 
                        className="hash-value" 
                        title={`Full SHA-256 hash: ${file.hash_sha256}`}
                        aria-label={`SHA-256 hash starting with ${file.hash_sha256.substring(0, 8)}`}
                      >
                        {file.hash_sha256.substring(0, 8)}...
                      </span>
                    </td>
                    <td>
                      <div className="file-actions" role="group" aria-label={`Actions for ${file.filename}`}>
                        <button 
                          className="btn btn-primary"
                          onClick={() => handleScanFile(file.id)}
                          disabled={scanningFiles.has(file.id)}
                          aria-busy={scanningFiles.has(file.id)}
                          aria-label={`${scanningFiles.has(file.id) ? 'Scanning' : 'Scan'} ${file.filename}`}
                        >
                          {scanningFiles.has(file.id) ? 'Scanning...' : 'Scan'}
                        </button>
                        <button 
                          className="btn btn-success"
                          onClick={() => window.location.href = `/scan-results/${file.id}`}
                          aria-label={`View scan results for ${file.filename}`}
                        >
                          Results
                        </button>
                        <button 
                          className="btn btn-danger"
                          onClick={() => handleDeleteFile(file.id, file.filename)}
                          disabled={scanningFiles.has(file.id)}
                          aria-label={`Delete ${file.filename}`}
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
};

export default FilesPage;