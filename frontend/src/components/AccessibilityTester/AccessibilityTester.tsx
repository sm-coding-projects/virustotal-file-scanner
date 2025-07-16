import React, { useState, useEffect } from 'react';
import { auditAccessibility, announceToScreenReader } from '../../utils/accessibilityHelpers';

interface AccessibilityTesterProps {
  enabled?: boolean;
}

const AccessibilityTester: React.FC<AccessibilityTesterProps> = ({ enabled = false }) => {
  const [issues, setIssues] = useState<string[]>([]);
  const [isVisible, setIsVisible] = useState(false);

  useEffect(() => {
    if (enabled) {
      // Run accessibility audit
      const auditResults = auditAccessibility();
      setIssues(auditResults);
    }
  }, [enabled]);

  const runAudit = () => {
    const auditResults = auditAccessibility();
    setIssues(auditResults);
    announceToScreenReader(`Accessibility audit complete. Found ${auditResults.length} issues.`);
  };

  const testScreenReaderAnnouncement = () => {
    announceToScreenReader('This is a test announcement for screen readers.', 'assertive');
  };

  const testKeyboardNavigation = () => {
    // Focus the first interactive element
    const firstButton = document.querySelector('button') as HTMLElement;
    if (firstButton) {
      firstButton.focus();
      announceToScreenReader('Focused first button for keyboard navigation test.');
    }
  };

  if (!enabled) {
    return null;
  }

  return (
    <div 
      className={`accessibility-tester ${isVisible ? 'visible' : 'hidden'}`}
      style={{
        position: 'fixed',
        bottom: '20px',
        right: '20px',
        background: '#fff',
        border: '2px solid #333',
        borderRadius: '8px',
        padding: '1rem',
        maxWidth: '400px',
        zIndex: 9999,
        boxShadow: '0 4px 6px rgba(0, 0, 0, 0.1)'
      }}
      role="region"
      aria-label="Accessibility Testing Tools"
    >
      <button
        onClick={() => setIsVisible(!isVisible)}
        style={{
          position: 'absolute',
          top: '-40px',
          right: '0',
          background: '#333',
          color: '#fff',
          border: 'none',
          padding: '0.5rem 1rem',
          borderRadius: '4px 4px 0 0',
          cursor: 'pointer'
        }}
        aria-expanded={isVisible}
        aria-controls="accessibility-tester-content"
      >
        A11y Tools
      </button>

      {isVisible && (
        <div id="accessibility-tester-content">
          <h3>Accessibility Testing Tools</h3>
          
          <div style={{ marginBottom: '1rem' }}>
            <button 
              onClick={runAudit}
              style={{
                background: '#007cba',
                color: '#fff',
                border: 'none',
                padding: '0.5rem 1rem',
                borderRadius: '4px',
                cursor: 'pointer',
                marginRight: '0.5rem'
              }}
            >
              Run Audit
            </button>
            
            <button 
              onClick={testScreenReaderAnnouncement}
              style={{
                background: '#28a745',
                color: '#fff',
                border: 'none',
                padding: '0.5rem 1rem',
                borderRadius: '4px',
                cursor: 'pointer',
                marginRight: '0.5rem'
              }}
            >
              Test SR
            </button>
            
            <button 
              onClick={testKeyboardNavigation}
              style={{
                background: '#ffc107',
                color: '#000',
                border: 'none',
                padding: '0.5rem 1rem',
                borderRadius: '4px',
                cursor: 'pointer'
              }}
            >
              Test KB Nav
            </button>
          </div>

          {issues.length > 0 && (
            <div>
              <h4>Accessibility Issues Found:</h4>
              <ul style={{ fontSize: '0.875rem', maxHeight: '200px', overflow: 'auto' }}>
                {issues.map((issue, index) => (
                  <li key={index} style={{ marginBottom: '0.25rem' }}>
                    {issue}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {issues.length === 0 && (
            <div style={{ color: '#28a745', fontSize: '0.875rem' }}>
              No accessibility issues detected!
            </div>
          )}

          <div style={{ marginTop: '1rem', fontSize: '0.75rem', color: '#666' }}>
            <p><strong>Keyboard shortcuts:</strong></p>
            <ul>
              <li>Tab: Navigate forward</li>
              <li>Shift+Tab: Navigate backward</li>
              <li>Enter/Space: Activate buttons</li>
              <li>Escape: Close modals</li>
            </ul>
          </div>
        </div>
      )}
    </div>
  );
};

export default AccessibilityTester;