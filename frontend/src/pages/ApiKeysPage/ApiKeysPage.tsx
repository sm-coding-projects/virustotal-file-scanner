import React from 'react';
import './ApiKeysPage.css';

const ApiKeysPage: React.FC = () => {
  return (
    <div className="api-keys-page">
      <h1>API Key Management</h1>
      <p className="page-description">
        Manage your VirusTotal API keys. You need at least one valid API key to use the file scanning functionality.
      </p>
      
      <div className="card">
        <div className="card-header">
          <h2>Add New API Key</h2>
        </div>
        <div className="card-body">
          <form className="api-key-form">
            <div className="form-group">
              <label htmlFor="keyName">Key Name</label>
              <input 
                type="text" 
                id="keyName" 
                className="form-control" 
                placeholder="Enter a name for this API key"
                required
              />
            </div>
            
            <div className="form-group">
              <label htmlFor="apiKey">API Key</label>
              <input 
                type="text" 
                id="apiKey" 
                className="form-control" 
                placeholder="Enter your VirusTotal API key"
                required
              />
            </div>
            
            <button type="submit" className="btn btn-primary">
              Add API Key
            </button>
          </form>
        </div>
      </div>
      
      <div className="api-keys-list">
        <h2>Your API Keys</h2>
        <p>No API keys found. Add a key above to get started.</p>
        
        {/* This will be populated with actual API keys */}
        <div className="api-key-table-container">
          <table className="table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Key (masked)</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {/* API keys will be listed here */}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default ApiKeysPage;