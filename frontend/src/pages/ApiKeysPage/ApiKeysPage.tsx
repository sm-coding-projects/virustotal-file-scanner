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
        <div className={`alert alert-${alert.type}`} role="alert" aria-live="polite">
          {alert.message}
          <button 
            type="button" 
            className="close" 
            onClick={dismissAlert}
            aria-label="Dismiss alert"
            style={{ float: 'right', background: 'none', border: 'none', cursor: 'pointer' }}
          >
            &times;
          </button>
        </div>
      )}
      
      <section className="card" aria-labelledby="add-key-heading">
        <div className="card-header">
          <h2 id="add-key-heading">{editingKey ? 'Edit API Key' : 'Add New API Key'}</h2>
        </div>
        <div className="card-body">
          <form className="api-key-form" onSubmit={handleSubmit} noValidate>
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
                aria-describedby={errors.keyName ? "keyName-error" : "keyName-help"}
                aria-invalid={errors.keyName ? "true" : "false"}
              />
              <div id="keyName-help" className="form-text">
                Choose a descriptive name to identify this API key
              </div>
              {errors.keyName && (
                <div id="keyName-error" className="form-error" role="alert">
                  {errors.keyName}
                </div>
              )}
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
                aria-describedby={errors.keyValue ? "apiKey-error" : "apiKey-help"}
                aria-invalid={errors.keyValue ? "true" : "false"}
              />
              <div id="apiKey-help" className="form-text">
                You can get your VirusTotal API key from your VirusTotal account settings.
              </div>
              {errors.keyValue && (
                <div id="apiKey-error" className="form-error" role="alert">
                  {errors.keyValue}
                </div>
              )}
            </div>
            
            <div style={{ display: 'flex', gap: '10px' }}>
              <button 
                type="submit" 
                className="btn btn-primary"
                disabled={validating}
                aria-busy={validating}
                aria-describedby="validation-status"
              >
                {validating ? 'Validating...' : editingKey ? 'Update API Key' : 'Add API Key'}
              </button>
              
              {editingKey && (
                <button 
                  type="button" 
                  className="btn btn-secondary"
                  onClick={handleCancelEdit}
                  aria-label="Cancel editing API key"
                >
                  Cancel
                </button>
              )}
            </div>
            
            <div id="validation-status" className="sr-only" aria-live="polite">
              {validating ? 'Validating API key, please wait...' : ''}
            </div>
          </form>
        </div>
      </section>
      
      <section className="api-keys-list" aria-labelledby="keys-list-heading">
        <h2 id="keys-list-heading">Your API Keys</h2>
        
        {loading ? (
          <div className="loading-spinner" role="status" aria-live="polite">
            <span className="sr-only">Loading API keys...</span>
            Loading...
          </div>
        ) : apiKeys.length === 0 ? (
          <div className="empty-state" role="status">
            <p>No API keys found. Add a key above to get started.</p>
          </div>
        ) : (
          <div className="api-key-table-container">
            <table className="table" role="table" aria-label="API Keys">
              <thead>
                <tr>
                  <th scope="col">Name</th>
                  <th scope="col">Key (masked)</th>
                  <th scope="col">Status</th>
                  <th scope="col" className="mobile-hidden">Created</th>
                  <th scope="col">Actions</th>
                </tr>
              </thead>
              <tbody>
                {apiKeys.map((key) => (
                  <tr key={key.id}>
                    <th scope="row">{key.name}</th>
                    <td className="key-masked">{maskApiKey('xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx')}</td>
                    <td>
                      <span 
                        className={`badge ${key.is_active ? 'badge-success' : 'badge-danger'}`}
                        aria-label={`Status: ${key.is_active ? 'Active' : 'Inactive'}`}
                      >
                        {key.is_active ? 'Active' : 'Inactive'}
                      </span>
                    </td>
                    <td className="mobile-hidden">{new Date(key.created_at).toLocaleDateString()}</td>
                    <td className="actions-cell">
                      <button 
                        className="btn btn-sm btn-secondary"
                        onClick={() => handleEdit(key)}
                        aria-label={`Edit API key ${key.name}`}
                      >
                        Edit
                      </button>
                      <button 
                        className="btn btn-sm btn-secondary"
                        onClick={() => handleToggleStatus(key)}
                        aria-label={`${key.is_active ? 'Disable' : 'Enable'} API key ${key.name}`}
                      >
                        {key.is_active ? 'Disable' : 'Enable'}
                      </button>
                      <button 
                        className="btn btn-sm btn-danger"
                        onClick={() => handleDelete(key)}
                        aria-label={`Delete API key ${key.name}`}
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
      </section>
      
      {/* Confirmation Modal */}
      {confirmModal && (
        <div 
          className="modal-backdrop" 
          role="dialog" 
          aria-modal="true" 
          aria-labelledby="modal-title"
          aria-describedby="modal-description"
        >
          <div className="modal">
            <div className="modal-header">
              <h3 id="modal-title">{confirmModal.title}</h3>
              <button 
                className="modal-close" 
                onClick={confirmModal.onCancel}
                aria-label="Close dialog"
              >
                &times;
              </button>
            </div>
            <div className="modal-body">
              <p id="modal-description">{confirmModal.message}</p>
            </div>
            <div className="modal-footer">
              <button 
                className="btn btn-secondary" 
                onClick={confirmModal.onCancel}
                autoFocus
              >
                Cancel
              </button>
              <button 
                className="btn btn-danger" 
                onClick={confirmModal.onConfirm}
                aria-describedby="modal-description"
              >
                Delete
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ApiKeysPage;