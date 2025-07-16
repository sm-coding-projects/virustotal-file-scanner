import React, { useEffect } from 'react';

const ViewportMeta: React.FC = () => {
  useEffect(() => {
    // Check if viewport meta tag exists
    let viewportMeta = document.querySelector('meta[name="viewport"]');
    
    // If it doesn't exist, create it
    if (!viewportMeta) {
      viewportMeta = document.createElement('meta');
      viewportMeta.setAttribute('name', 'viewport');
      document.head.appendChild(viewportMeta);
    }
    
    // Set the content attribute for proper mobile scaling
    viewportMeta.setAttribute('content', 'width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no');
    
    // Cleanup function
    return () => {
      // Optional: Remove or reset the viewport meta if needed when component unmounts
      // In most cases, you'll want to keep it
    };
  }, []);

  return null; // This component doesn't render anything
};

export default ViewportMeta;