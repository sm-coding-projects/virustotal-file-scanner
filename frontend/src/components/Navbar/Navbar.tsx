import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuthStore } from '../../store/authStore';
import api from '../../services/api';
import './Navbar.css';

const Navbar: React.FC = () => {
  const { isAuthenticated, user, logout } = useAuthStore();
  const [isLoggingOut, setIsLoggingOut] = useState(false);
  const navigate = useNavigate();

  const handleLogout = async () => {
    if (isLoggingOut) return;
    
    setIsLoggingOut(true);
    try {
      // Call the logout API endpoint
      await api.post('/auth/logout');
    } catch (error) {
      console.error('Logout error:', error);
      // Continue with logout even if API call fails
    } finally {
      // Clear local auth state
      logout();
      setIsLoggingOut(false);
      navigate('/login');
    }
  };

  return (
    <nav className="navbar">
      <div className="container navbar-container">
        <Link to="/" className="navbar-brand">
          VirusTotal File Scanner
        </Link>
        <div className="navbar-menu">
          {isAuthenticated ? (
            <>
              <Link to="/" className="navbar-item">Home</Link>
              <Link to="/api-keys" className="navbar-item">API Keys</Link>
              <Link to="/files" className="navbar-item">Files</Link>
              <Link to="/scan-results" className="navbar-item">Scan Results</Link>
              <button onClick={handleLogout} className="navbar-item logout-button">
                Logout
              </button>
            </>
          ) : (
            <>
              <Link to="/login" className="navbar-item">Login</Link>
              <Link to="/register" className="navbar-item">Register</Link>
            </>
          )}
        </div>
      </div>
    </nav>
  );
};

export default Navbar;