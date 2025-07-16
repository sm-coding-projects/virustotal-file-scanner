import React from 'react';
import './FilesPage.css';

const FilesPage: React.FC = () => {
  return (
    <div className="files-page">
      <h1>File Upload</h1>
      <p className="page-description">
        Upload files to scan them for malicious content using the VirusTotal API.
      </p>
      
      <div className="card">
        <div className="card-header">
          <h2>Upload Files</h2>
        </div>
        <div className="card-body">
          <div className="file-upload-container">
            <div className="file-drop-zone">
              <div className="file-drop-content">
                <i className="file-icon">📁</i>
                <p>Drag and drop files here, or click to select files</p>
                <input type="file" className="file-input" multiple />
              </div>
            </div>
            
            <div className="upload-info">
              <p>Maximum file size: 32MB</p>
              <p>Supported file types: All</p>
            </div>
            
            <button className="btn btn-primary upload-button">
              Upload and Scan
            </button>
          </div>
        </div>
      </div>
      
      <div className="uploaded-files">
        <h2>Uploaded Files</h2>
        <p>No files uploaded yet.</p>
        
        {/* This will be populated with actual uploaded files */}
        <div className="files-table-container">
          <table className="table">
            <thead>
              <tr>
                <th>Filename</th>
                <th>Size</th>
                <th>Upload Date</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {/* Files will be listed here */}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default FilesPage;