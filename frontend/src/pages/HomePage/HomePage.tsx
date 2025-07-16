import React from 'react';
import { Link } from 'react-router-dom';
import { useAuthStore } from '../../store/authStore';
import './HomePage.css';

const HomePage: React.FC = () => {
  const { user } = useAuthStore();

  return (
    <div className="home-page">
      <header className="welcome-section">
        <h1>Welcome to VirusTotal File Scanner</h1>
        <p>Hello, <span className="user-name">{user?.username || 'User'}</span>! This application allows you to scan files for malicious content using the VirusTotal API.</p>
      </header>

      <main className="features-section" role="main">
        <h2 className="sr-only">Available Features</h2>
        <div className="feature-card" role="region" aria-labelledby="api-key-heading">
          <h3 id="api-key-heading">API Key Management</h3>
          <p>Add and manage your VirusTotal API keys securely.</p>
          <Link 
            to="/api-keys" 
            className="btn btn-primary"
            aria-describedby="api-key-heading"
          >
            Manage API Keys
          </Link>
        </div>

        <div className="feature-card" role="region" aria-labelledby="file-upload-heading">
          <h3 id="file-upload-heading">File Upload</h3>
          <p>Upload files to scan them for malicious content.</p>
          <Link 
            to="/files" 
            className="btn btn-primary"
            aria-describedby="file-upload-heading"
          >
            Upload Files
          </Link>
        </div>

        <div className="feature-card" role="region" aria-labelledby="scan-results-heading">
          <h3 id="scan-results-heading">Scan Results</h3>
          <p>View and analyze the results of your file scans.</p>
          <Link 
            to="/scan-results" 
            className="btn btn-primary"
            aria-describedby="scan-results-heading"
          >
            View Results
          </Link>
        </div>
      </main>
    </div>
  );
};

export default HomePage;