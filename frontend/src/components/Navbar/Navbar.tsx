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
    <nav className="navbar" role="navigation" aria-label="Main navigation">
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
            aria-controls="navbar-menu"
            type="button"
          >
            <span className="navbar-toggle-icon" aria-hidden="true"></span>
          </button>
        </div>
        <div 
          id="navbar-menu"
          className={`navbar-menu ${menuOpen ? 'navbar-menu-open' : ''}`}
          role="menubar"
          aria-hidden={!menuOpen}
        >
          {isAuthenticated ? (
            <>
              <Link to="/" className="navbar-item" onClick={closeMenu} role="menuitem">Home</Link>
              <Link to="/api-keys" className="navbar-item" onClick={closeMenu} role="menuitem">API Keys</Link>
              <Link to="/files" className="navbar-item" onClick={closeMenu} role="menuitem">Files</Link>
              <Link to="/scan-results" className="navbar-item" onClick={closeMenu} role="menuitem">Scan Results</Link>
              <button 
                onClick={handleLogout} 
                className="navbar-item logout-button"
                role="menuitem"
                aria-busy={isLoggingOut}
                disabled={isLoggingOut}
              >
                {isLoggingOut ? 'Logging out...' : 'Logout'}
              </button>
            </>
          ) : (
            <>
              <Link to="/login" className="navbar-item" onClick={closeMenu} role="menuitem">Login</Link>
              <Link to="/register" className="navbar-item" onClick={closeMenu} role="menuitem">Register</Link>
            </>
          )}
        </div>
      </div>
    </nav>
  );
};

export default Navbar;