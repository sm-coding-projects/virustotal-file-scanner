import React, { useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import './App.css';
import Layout from './components/Layout/Layout';
import HomePage from './pages/HomePage/HomePage';
import LoginPage from './pages/LoginPage/LoginPage';
import RegisterPage from './pages/RegisterPage/RegisterPage';
import ApiKeysPage from './pages/ApiKeysPage/ApiKeysPage';
import FilesPage from './pages/FilesPage/FilesPage';
import ScanResultsPage from './pages/ScanResultsPage/ScanResultsPage';
import NotFoundPage from './pages/NotFoundPage/NotFoundPage';
import AuthCheck from './components/AuthCheck/AuthCheck';
import ViewportMeta from './components/ViewportMeta/ViewportMeta';
import { useAuthStore } from './store/authStore';

const App: React.FC = () => {
  const { isAuthenticated } = useAuthStore();

  return (
    <Router>
      {/* ViewportMeta component adds proper mobile viewport settings */}
      <ViewportMeta />
      {/* AuthCheck component verifies authentication status on app load */}
      <AuthCheck />
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={isAuthenticated ? <HomePage /> : <Navigate to="/login" />} />
          <Route path="login" element={!isAuthenticated ? <LoginPage /> : <Navigate to="/" />} />
          <Route path="register" element={!isAuthenticated ? <RegisterPage /> : <Navigate to="/" />} />
          <Route path="api-keys" element={isAuthenticated ? <ApiKeysPage /> : <Navigate to="/login" />} />
          <Route path="files" element={isAuthenticated ? <FilesPage /> : <Navigate to="/login" />} />
          <Route path="scan-results" element={isAuthenticated ? <ScanResultsPage /> : <Navigate to="/login" />} />
          <Route path="*" element={<NotFoundPage />} />
        </Route>
      </Routes>
    </Router>
  );
};

export default App;