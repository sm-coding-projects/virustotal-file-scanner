import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuthStore } from '../../store/authStore';
import api from '../../services/api';
import './Navbar.css';

const Navbar: React.FC = () => {
  const { isAuthenticated, user, logout } = useAuthStore();
  const [isLoggingOut, setIsLoggingOut] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
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
      setMenuOpen(false);
      navigate('/login');
    }
  };

  const toggleMenu = () => {
    setMenuOpen(!menuOpen);
    // Prevent scrolling when menu is open on mobile
    document.body.style.overflow = !menuOpen ? 'hidden' : '';
  };

  const closeMenu = () => {
    setMenuOpen(false);
    // Re-enable scrolling when menu is closed
    document.body.style.overflow = '';
  };

  return (
    <nav className="navbar">
      <div className="container navbar-container">
        <div className="navbar-top">
          <Link to="/" className="navbar-brand" onClick={closeMenu}>
            VirusTotal File Scanner
          </Link>
          <button 
            className={`navbar-toggle ${menuOpen ? 'active' : ''}`}
            aria-label="Toggle navigation menu"
            onClick={toggleMenu}
            aria-expanded={menuOpen}
          >
            <span className="navbar-toggle-icon"></span>
          </button>
        </div>
        <div className={`navbar-menu ${menuOpen ? 'navbar-menu-open' : ''}`}>
          {isAuthenticated ? (
            <>
              <Link to="/" className="navbar-item" onClick={closeMenu}>Home</Link>
              <Link to="/api-keys" className="navbar-item" onClick={closeMenu}>API Keys</Link>
              <Link to="/files" className="navbar-item" onClick={closeMenu}>Files</Link>
              <Link to="/scan-results" className="navbar-item" onClick={closeMenu}>Scan Results</Link>
              <button onClick={handleLogout} className="navbar-item logout-button">
                Logout
              </button>
            </>
          ) : (
            <>
              <Link to="/login" className="navbar-item" onClick={closeMenu}>Login</Link>
              <Link to="/register" className="navbar-item" onClick={closeMenu}>Register</Link>
            </>
          )}
        </div>
      </div>
    </nav>
  );
};

export default Navbar;