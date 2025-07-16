import React from 'react';
import { Link } from 'react-router-dom';
import { useAuthStore } from '../../store/authStore';
import './HomePage.css';

const HomePage: React.FC = () => {
  const { user } = useAuthStore();

  return (
    <div className="home-page">
      <div className="welcome-section">
        <h1>Welcome to VirusTotal File Scanner</h1>
        <p>Hello, {user?.username || 'User'}! This application allows you to scan files for malicious content using the VirusTotal API.</p>
      </div>

      <div className="features-section">
        <div className="feature-card">
          <h2>API Key Management</h2>
          <p>Add and manage your VirusTotal API keys securely.</p>
          <Link to="/api-keys" className="btn btn-primary">Manage API Keys</Link>
        </div>

        <div className="feature-card">
          <h2>File Upload</h2>
          <p>Upload files to scan them for malicious content.</p>
          <Link to="/files" className="btn btn-primary">Upload Files</Link>
        </div>

        <div className="feature-card">
          <h2>Scan Results</h2>
          <p>View and analyze the results of your file scans.</p>
          <Link to="/scan-results" className="btn btn-primary">View Results</Link>
        </div>
      </div>
    </div>
  );
};

export default HomePage;