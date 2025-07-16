import React, { useEffect, useState } from 'react';
import { useAuthStore } from '../../store/authStore';
import api from '../../services/api';

/**
 * Component that verifies the user's authentication status on app load
 * and refreshes the user profile if authenticated
 */
const AuthCheck: React.FC = () => {
  const { isAuthenticated, token, user, updateUser, logout } = useAuthStore();
  const [isChecking, setIsChecking] = useState(false);

  useEffect(() => {
    // Only check if we have a token and user data
    if (isAuthenticated && token && user) {
      const verifyAuth = async () => {
        setIsChecking(true);
        try {
          // Try to get the user profile to verify the token is still valid
          const response = await api.get('/auth/profile');
          
          // Update user data if needed
          if (response.data && response.data.user) {
            updateUser(response.data.user);
          }
        } catch (error) {
          console.error('Auth verification failed:', error);
          // If verification fails, log the user out
          logout();
        } finally {
          setIsChecking(false);
        }
      };

      verifyAuth();
    }
  }, [isAuthenticated, token, user, updateUser, logout]);

  // This component doesn't render anything
  return null;
};

export default AuthCheck;