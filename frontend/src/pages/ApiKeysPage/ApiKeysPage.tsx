import React, { useState, useEffect } from 'react';
import './ApiKeysPage.css';
import apiKeyService, { ApiKey } from '../../services/apiKeyService';

interface AlertProps {
  type: 'success' | 'danger' | 'warning';
  message: string;
}

interface ConfirmModalProps {
  title: string;
  message: string;
  onConfirm: () => void;
  onCancel: () => void;
}

const ApiKeysPage: React.FC = () => {
  const [apiKeys, setApiKeys] = useState<ApiKey[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [keyName, setKeyName] = useState<string>('');
  const [keyValue, setKeyValue] = useState<string>('');
  const [validating, setValidating] = useState<boolean>(false);
  const [alert, setAlert] = useState<AlertProps | null>(null);
  const [errors, setErrors] = useState<{ keyName?: string; keyValue?: string }>({});
  const [confirmModal, setConfirmModal] = useState<ConfirmModalProps | null>(null);
  const [editingKey, setEditingKey] = useState<ApiKey | null>(null);

  // Fetch API keys on component mount
  useEffect(() => {
    fetchApiKeys();
  }, []);

  const fetchApiKeys = async () => {
    try {
      setLoading(true);
      const keys = await apiKeyService.getAllApiKeys();
      setApiKeys(keys);
    } catch (error) {
      console.error('Error fetching API keys:', error);
      setAlert({
        type: 'danger',
        message: 'Failed to load API keys. Please try again later.'
      });
    } finally {
      setLoading(false);
    }
  };

  const validateForm = (): boolean => {
    const newErrors: { keyName?: string; keyValue?: string } = {};
    
    if (!keyName.trim()) {
      newErrors.keyName = 'Key name is required';
    }
    
    if (!keyValue.trim()) {
      newErrors.keyValue = 'API key is required';
    } else if (keyValue.length < 32) {
      newErrors.keyValue = 'API key appears to be invalid (too short)';
    }
    
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!validateForm()) {
      return;
    }
    
    try {
      setValidating(true);
      
      // First validate the API key
      const validationResult = await apiKeyService.validateApiKey(keyValue);
      
      if (!validationResult.valid) {
        setErrors({
          ...errors,
          keyValue: `Invalid API key: ${validationResult.message}`
        });
        return;
      }
      
      // If we're editing an existing key
      if (editingKey) {
        await apiKeyService.updateApiKey(editingKey.id, {
          name: keyName,
          key_value: keyValue
        });
        
        setAlert({
          type: 'success',
          message: 'API key updated successfully!'
        });
        
        setEditingKey(null);
      } else {
        // Create a new key
        await apiKeyService.createApiKey(keyName, keyValue);
        
        setAlert({
          type: 'success',
          message: 'API key added successfully!'
        });
      }
      
      // Reset form
      setKeyName('');
      setKeyValue('');
      setErrors({});
      
      // Refresh the API keys list
      fetchApiKeys();
      
    } catch (error) {
      console.error('Error saving API key:', error);
      setAlert({
        type: 'danger',
        message: 'Failed to save API key. Please try again.'
      });
    } finally {
      setValidating(false);
    }
  };

  const handleEdit = (key: ApiKey) => {
    setEditingKey(key);
    setKeyName(key.name);
    setKeyValue(''); // We don't get the actual key value from the server
    setErrors({});
    
    // Scroll to the form
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleCancelEdit = () => {
    setEditingKey(null);
    setKeyName('');
    setKeyValue('');
    setErrors({});
  };

  const handleToggleStatus = async (key: ApiKey) => {
    try {
      await apiKeyService.updateApiKey(key.id, {
        is_active: !key.is_active
      });
      
      setAlert({
        type: 'success',
        message: `API key ${key.is_active ? 'disabled' : 'enabled'} successfully!`
      });
      
      // Refresh the API keys list
      fetchApiKeys();
      
    } catch (error) {
      console.error('Error updating API key status:', error);
      setAlert({
        type: 'danger',
        message: 'Failed to update API key status. Please try again.'
      });
    }
  };

  const handleDelete = (key: ApiKey) => {
    setConfirmModal({
      title: 'Delete API Key',
      message: `Are you sure you want to delete the API key "${key.name}"? This action cannot be undone.`,
      onConfirm: async () => {
        try {
          await apiKeyService.deleteApiKey(key.id);
          
          setAlert({
            type: 'success',
            message: 'API key deleted successfully!'
          });
          
          // Refresh the API keys list
          fetchApiKeys();
          
        } catch (error) {
          console.error('Error deleting API key:', error);
          setAlert({
            type: 'danger',
            message: 'Failed to delete API key. Please try again.'
          });
        } finally {
          setConfirmModal(null);
        }
      },
      onCancel: () => {
        setConfirmModal(null);
      }
    });
  };

  const dismissAlert = () => {
    setAlert(null);
  };

  // Mask API key for display (show only first and last 4 characters)
  const maskApiKey = (key: string): string => {
    if (key.length <= 8) return '********';
    return `${key.substring(0, 4)}...${key.substring(key.length - 4)}`;
  };

  return (
    <div className="api-keys-page">
      <h1>API Key Management</h1>
      <p className="page-description">
        Manage your VirusTotal API keys. You need at least one valid API key to use the file scanning functionality.
      </p>
      
      {alert && (
        <div className={`alert alert-${alert.type}`}>
          {alert.message}
          <button 
            type="button" 
            className="close" 
            onClick={dismissAlert}
            style={{ float: 'right', background: 'none', border: 'none', cursor: 'pointer' }}
          >
            &times;
          </button>
        </div>
      )}
      
      <div className="card">
        <div className="card-header">
          <h2>{editingKey ? 'Edit API Key' : 'Add New API Key'}</h2>
        </div>
        <div className="card-body">
          <form className="api-key-form" onSubmit={handleSubmit}>
            <div className="form-group">
              <label htmlFor="keyName">Key Name</label>
              <input 
                type="text" 
                id="keyName" 
                className={`form-control ${errors.keyName ? 'is-invalid' : ''}`}
                placeholder="Enter a name for this API key"
                value={keyName}
                onChange={(e) => setKeyName(e.target.value)}
                required
              />
              {errors.keyName && <div className="form-error">{errors.keyName}</div>}
            </div>
            
            <div className="form-group">
              <label htmlFor="apiKey">API Key</label>
              <input 
                type="text" 
                id="apiKey" 
                className={`form-control ${errors.keyValue ? 'is-invalid' : ''}`}
                placeholder={editingKey ? 'Enter new API key value or leave blank to keep current' : 'Enter your VirusTotal API key'}
                value={keyValue}
                onChange={(e) => setKeyValue(e.target.value)}
                required={!editingKey}
              />
              {errors.keyValue && <div className="form-error">{errors.keyValue}</div>}
              <small className="form-text text-muted">
                You can get your VirusTotal API key from your VirusTotal account settings.
              </small>
            </div>
            
            <div style={{ display: 'flex', gap: '10px' }}>
              <button 
                type="submit" 
                className="btn btn-primary"
                disabled={validating}
              >
                {validating ? 'Validating...' : editingKey ? 'Update API Key' : 'Add API Key'}
              </button>
              
              {editingKey && (
                <button 
                  type="button" 
                  className="btn btn-secondary"
                  onClick={handleCancelEdit}
                >
                  Cancel
                </button>
              )}
            </div>
          </form>
        </div>
      </div>
      
      <div className="api-keys-list">
        <h2>Your API Keys</h2>
        
        {loading ? (
          <div className="loading-spinner">Loading...</div>
        ) : apiKeys.length === 0 ? (
          <div className="empty-state">
            <p>No API keys found. Add a key above to get started.</p>
          </div>
        ) : (
          <div className="api-key-table-container">
            <table className="table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Key (masked)</th>
                  <th>Status</th>
                  <th className="mobile-hidden">Created</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {apiKeys.map((key) => (
                  <tr key={key.id}>
                    <td>{key.name}</td>
                    <td className="key-masked">{maskApiKey('xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx')}</td>
                    <td>
                      <span className={`badge ${key.is_active ? 'badge-success' : 'badge-danger'}`}>
                        {key.is_active ? 'Active' : 'Inactive'}
                      </span>
                    </td>
                    <td className="mobile-hidden">{new Date(key.created_at).toLocaleDateString()}</td>
                    <td className="actions-cell">
                      <button 
                        className="btn btn-sm btn-secondary"
                        onClick={() => handleEdit(key)}
                      >
                        Edit
                      </button>
                      <button 
                        className="btn btn-sm btn-secondary"
                        onClick={() => handleToggleStatus(key)}
                      >
                        {key.is_active ? 'Disable' : 'Enable'}
                      </button>
                      <button 
                        className="btn btn-sm btn-danger"
                        onClick={() => handleDelete(key)}
                      >
                        Delete
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
      
      {/* Confirmation Modal */}
      {confirmModal && (
        <div className="modal-backdrop">
          <div className="modal">
            <div className="modal-header">
              <h3>{confirmModal.title}</h3>
              <button className="modal-close" onClick={confirmModal.onCancel}>&times;</button>
            </div>
            <div className="modal-body">
              <p>{confirmModal.message}</p>
            </div>
            <div className="modal-footer">
              <button className="btn btn-secondary" onClick={confirmModal.onCancel}>Cancel</button>
              <button className="btn btn-danger" onClick={confirmModal.onConfirm}>Delete</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ApiKeysPage;