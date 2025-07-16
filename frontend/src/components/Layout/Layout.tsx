import React from 'react';
import { Outlet } from 'react-router-dom';
import Navbar from '../Navbar/Navbar';
import AccessibilityTester from '../AccessibilityTester/AccessibilityTester';
import './Layout.css';

const Layout: React.FC = () => {
  return (
    <div className="app-container">
      <a href="#main-content" className="skip-link">Skip to main content</a>
      <Navbar />
      <main id="main-content" className="main-content" role="main">
        <div className="container">
          <Outlet />
        </div>
      </main>
      <footer className="footer" role="contentinfo">
        <div className="container">
          <p>&copy; {new Date().getFullYear()} VirusTotal File Scanner</p>
        </div>
      </footer>
      
      {/* Accessibility testing tools - only enabled in development */}
      <AccessibilityTester enabled={process.env.NODE_ENV === 'development'} />
    </div>
  );
};

export default Layout;