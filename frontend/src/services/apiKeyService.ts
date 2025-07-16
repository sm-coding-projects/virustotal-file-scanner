import api from './api';

export interface ApiKey {
  id: string;
  name: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface ApiKeyWithValue {
  id: string;
  name: string;
  key_value: string;
  is_active: boolean;
}

export interface ApiKeyValidationResult {
  valid: boolean;
  message: string;
}

const apiKeyService = {
  /**
   * Get all API keys for the current user
   */
  getAllApiKeys: async (): Promise<ApiKey[]> => {
    const response = await api.get('/keys');
    return response.data.api_keys;
  },

  /**
   * Get a specific API key by ID
   */
  getApiKey: async (keyId: string): Promise<ApiKey> => {
    const response = await api.get(`/keys/${keyId}`);
    return response.data.api_key;
  },

  /**
   * Create a new API key
   */
  createApiKey: async (name: string, keyValue: string): Promise<ApiKey> => {
    const response = await api.post('/keys', { name, key_value: keyValue });
    return response.data.api_key;
  },

  /**
   * Update an existing API key
   */
  updateApiKey: async (keyId: string, data: Partial<ApiKeyWithValue>): Promise<ApiKey> => {
    const response = await api.put(`/keys/${keyId}`, data);
    return response.data.api_key;
  },

  /**
   * Delete an API key
   */
  deleteApiKey: async (keyId: string): Promise<void> => {
    await api.delete(`/keys/${keyId}`);
  },

  /**
   * Validate an API key with VirusTotal
   */
  validateApiKey: async (keyValue: string): Promise<ApiKeyValidationResult> => {
    const response = await api.post('/keys/validate', { key_value: keyValue });
    return response.data;
  }
};

export default apiKeyService;