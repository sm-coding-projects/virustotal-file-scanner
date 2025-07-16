import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import './LoginPage.css';
import api from '../../services/api';
import { useAuthStore } from '../../store/authStore';

const LoginPage: React.FC = () => {
  const [formData, setFormData] = useState({
    username: '',
    password: ''
  });
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const navigate = useNavigate();
  const { login } = useAuthStore();

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { id, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [id]: value
    }));
    // Clear error when user starts typing
    if (error) setError(null);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    // Basic validation
    if (!formData.username.trim() || !formData.password.trim()) {
      setError('Please enter both username/email and password');
      return;
    }
    
    setIsLoading(true);
    setError(null);
    
    try {
      const response = await api.post('/auth/login', formData);
      
      // Store auth data in zustand store
      login(response.data.user, response.data.access_token);
      
      // Redirect to home page
      navigate('/');
    } catch (err: any) {
      console.error('Login error:', err);
      setError(
        err.response?.data?.error || 
        'Failed to login. Please check your credentials and try again.'
      );
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="auth-page">
      <div className="auth-card">
        <h1>Login</h1>
        <p className="auth-description">Sign in to your account to access the VirusTotal File Scanner</p>
        
        {error && (
          <div className="error-message" role="alert" aria-live="polite">
            {error}
          </div>
        )}
        
        <form className="auth-form" onSubmit={handleSubmit} noValidate>
          <div className="form-group">
            <label htmlFor="username">Username or Email</label>
            <input 
              type="text" 
              id="username" 
              className="form-control" 
              placeholder="Enter your username or email"
              value={formData.username}
              onChange={handleChange}
              required
              disabled={isLoading}
              aria-describedby={error ? "login-error" : undefined}
              aria-invalid={error ? "true" : "false"}
              autoComplete="username"
            />
          </div>
          
          <div className="form-group">
            <label htmlFor="password">Password</label>
            <input 
              type="password" 
              id="password" 
              className="form-control" 
              placeholder="Enter your password"
              value={formData.password}
              onChange={handleChange}
              required
              disabled={isLoading}
              aria-describedby={error ? "login-error" : undefined}
              aria-invalid={error ? "true" : "false"}
              autoComplete="current-password"
            />
          </div>
          
          <button 
            type="submit" 
            className="btn btn-primary btn-block"
            disabled={isLoading}
            aria-busy={isLoading}
            aria-describedby="login-status"
          >
            {isLoading ? 'Logging in...' : 'Login'}
          </button>
          
          <div id="login-status" className="sr-only" aria-live="polite">
            {isLoading ? 'Logging in, please wait...' : ''}
          </div>
          
          {error && (
            <div id="login-error" className="sr-only">
              Login error: {error}
            </div>
          )}
        </form>
        
        <div className="auth-footer">
          <p>
            Don't have an account? <Link to="/register" aria-label="Go to registration page">Register</Link>
          </p>
        </div>
      </div>
    </div>
  );
};

export default LoginPage;