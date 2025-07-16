import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import './ScanResultsPage.css';
import { 
  getFileScanResults, 
  getScanResults, 
  getFile, 
  formatFileSize, 
  ScanResult 
} from '../../services/fileService';

interface SortConfig {
  key: string;
  direction: 'asc' | 'desc';
}

interface FilterState {
  status: string;
  dateRange: string;
  search: string;
}

interface PaginationState {
  currentPage: number;
  totalPages: number;
  itemsPerPage: number;
}

const ScanResultsPage: React.FC = () => {
  const { fileId } = useParams<{ fileId?: string }>();
  
  const [scanResults, setScanResults] = useState<ScanResult[]>([]);
  const [filteredResults, setFilteredResults] = useState<ScanResult[]>([]);
  const [displayedResults, setDisplayedResults] = useState<ScanResult[]>([]);
  const [selectedScan, setSelectedScan] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [sortConfig, setSortConfig] = useState<SortConfig>({ key: 'scan_date', direction: 'desc' });
  const [filters, setFilters] = useState<FilterState>({
    status: 'all',
    dateRange: 'all',
    search: ''
  });
  const [pagination, setPagination] = useState<PaginationState>({
    currentPage: 1,
    totalPages: 1,
    itemsPerPage: 10
  });
  const [showExportModal, setShowExportModal] = useState<boolean>(false);
  const [exportFormat, setExportFormat] = useState<string>('csv');
  const [fileInfo, setFileInfo] = useState<any>(null);

  // Fetch scan results when component mounts or fileId changes
  useEffect(() => {
    const fetchData = async () => {
      try {
        setLoading(true);
        setError(null);
        
        if (fileId) {
          // Fetch file info
          const fileData = await getFile(fileId);
          setFileInfo(fileData);
          
          // Fetch scan results for specific file
          const results = await getFileScanResults(fileId);
          setScanResults(results);
          setFilteredResults(results);
          
          // Set pagination
          setPagination(prev => ({
            ...prev,
            totalPages: Math.ceil(results.length / prev.itemsPerPage) || 1
          }));
        } else {
          // TODO: Implement fetching all scan results when no fileId is provided
          setError('Please select a file to view scan results.');
        }
      } catch (err) {
        console.error('Error fetching scan results:', err);
        setError('Failed to load scan results. Please try again later.');
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, [fileId]);

  // Update displayed results when filtered results or pagination changes
  useEffect(() => {
    const startIndex = (pagination.currentPage - 1) * pagination.itemsPerPage;
    const endIndex = startIndex + pagination.itemsPerPage;
    setDisplayedResults(filteredResults.slice(startIndex, endIndex));
  }, [filteredResults, pagination.currentPage, pagination.itemsPerPage]);

  // Handle sorting
  const handleSort = (key: string) => {
    let direction: 'asc' | 'desc' = 'asc';
    
    if (sortConfig.key === key && sortConfig.direction === 'asc') {
      direction = 'desc';
    }
    
    setSortConfig({ key, direction });
    
    const sortedResults = [...filteredResults].sort((a, b) => {
      const aValue = a[key as keyof ScanResult];
      const bValue = b[key as keyof ScanResult];
      
      if (aValue == null || bValue == null) {
        return 0;
      }
      
      if (aValue < bValue) {
        return direction === 'asc' ? -1 : 1;
      }
      if (aValue > bValue) {
        return direction === 'asc' ? 1 : -1;
      }
      return 0;
    });
    
    setFilteredResults(sortedResults);
  };

  // Get sort icon based on current sort config
  const getSortIcon = (key: string) => {
    if (sortConfig.key !== key) {
      return '⇅';
    }
    return sortConfig.direction === 'asc' ? '↑' : '↓';
  };

  // Handle filter changes
  const handleFilterChange = (e: React.ChangeEvent<HTMLSelectElement | HTMLInputElement>) => {
    const { id, value } = e.target;
    const filterKey = id.replace('Filter', '') as keyof FilterState;
    
    setFilters(prev => ({
      ...prev,
      [filterKey]: value
    }));
  };

  // Apply filters
  const applyFilters = () => {
    let results = [...scanResults];
    
    // Filter by status
    if (filters.status !== 'all') {
      results = results.filter(result => {
        if (filters.status === 'clean') {
          return result.detection_ratio === '0/0' || 
                 (result.summary?.stats?.malicious === 0 && result.summary?.stats?.suspicious === 0);
        } else if (filters.status === 'malicious') {
          return (result.summary?.stats?.malicious || 0) > 0;
        } else if (filters.status === 'suspicious') {
          return (result.summary?.stats?.suspicious || 0) > 0 && (result.summary?.stats?.malicious || 0) === 0;
        }
        return true;
      });
    }
    
    // Filter by date range
    if (filters.dateRange !== 'all') {
      const now = new Date();
      let startDate = new Date();
      
      if (filters.dateRange === 'today') {
        startDate.setHours(0, 0, 0, 0);
      } else if (filters.dateRange === 'week') {
        startDate.setDate(now.getDate() - 7);
      } else if (filters.dateRange === 'month') {
        startDate.setMonth(now.getMonth() - 1);
      }
      
      results = results.filter(result => {
        const scanDate = new Date(result.scan_date);
        return scanDate >= startDate && scanDate <= now;
      });
    }
    
    // Filter by search term
    if (filters.search.trim()) {
      const searchTerm = filters.search.toLowerCase();
      results = results.filter(result => 
        result.filename.toLowerCase().includes(searchTerm)
      );
    }
    
    setFilteredResults(results);
    setPagination(prev => ({
      ...prev,
      currentPage: 1,
      totalPages: Math.ceil(results.length / prev.itemsPerPage) || 1
    }));
  };

  // Reset filters
  const resetFilters = () => {
    setFilters({
      status: 'all',
      dateRange: 'all',
      search: ''
    });
    setFilteredResults(scanResults);
    setPagination(prev => ({
      ...prev,
      currentPage: 1,
      totalPages: Math.ceil(scanResults.length / prev.itemsPerPage) || 1
    }));
  };

  // Handle pagination
  const handlePageChange = (newPage: number) => {
    if (newPage >= 1 && newPage <= pagination.totalPages) {
      setPagination(prev => ({
        ...prev,
        currentPage: newPage
      }));
    }
  };

  // View scan details
  const viewScanDetails = async (scanId: string) => {
    try {
      setLoading(true);
      const scanDetails = await getScanResults(scanId);
      setSelectedScan(scanDetails);
    } catch (err) {
      console.error('Error fetching scan details:', err);
      setError('Failed to load scan details. Please try again later.');
    } finally {
      setLoading(false);
    }
  };

  // Close scan details view
  const closeScanDetails = () => {
    setSelectedScan(null);
  };

  // Format date for display
  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleString();
  };

  // Get status badge class based on scan result
  const getStatusBadgeClass = (result: ScanResult) => {
    if (!result.summary) return 'status-unknown';
    
    const { malicious, suspicious } = result.summary.stats;
    
    if (malicious > 0) return 'status-malicious';
    if (suspicious > 0) return 'status-suspicious';
    return 'status-clean';
  };

  // Get status text based on scan result
  const getStatusText = (result: ScanResult) => {
    if (!result.summary) return 'Unknown';
    
    const { malicious, suspicious } = result.summary.stats;
    
    if (malicious > 0) return 'Malicious';
    if (suspicious > 0) return 'Suspicious';
    return 'Clean';
  };

  // Export scan results
  const exportResults = () => {
    let content = '';
    const filename = `scan-results-${new Date().toISOString().slice(0, 10)}`;
    
    if (exportFormat === 'csv') {
      // Create CSV content
      const headers = ['Filename', 'Scan Date', 'Detection Ratio', 'Status'];
      content = headers.join(',') + '\n';
      
      filteredResults.forEach(result => {
        const row = [
          `"${result.filename}"`,
          `"${formatDate(result.scan_date)}"`,
          `"${result.detection_ratio}"`,
          `"${getStatusText(result)}"`
        ];
        content += row.join(',') + '\n';
      });
      
      // Create and download file
      const blob = new Blob([content], { type: 'text/csv' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `${filename}.csv`;
      link.click();
      URL.revokeObjectURL(url);
    } else if (exportFormat === 'json') {
      // Create JSON content
      content = JSON.stringify(filteredResults, null, 2);
      
      // Create and download file
      const blob = new Blob([content], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `${filename}.json`;
      link.click();
      URL.revokeObjectURL(url);
    }
    
    setShowExportModal(false);
  };

  return (
    <div className="scan-results-page">
      <h1>Scan Results</h1>
      <p className="page-description">
        View and analyze the results of your file scans.
      </p>
      
      {fileInfo && (
        <div className="file-info">
          <h2>{fileInfo.filename}</h2>
          <p>Size: {formatFileSize(fileInfo.file_size)}</p>
          <p>Hash (SHA-256): {fileInfo.hash_sha256}</p>
        </div>
      )}
      
      {error && (
        <div className="alert alert-danger" role="alert">
          {error}
        </div>
      )}
      
      {!selectedScan ? (
        <>
          <div className="results-filters">
            <div className="filter-group">
              <label htmlFor="statusFilter">Status:</label>
              <select 
                id="statusFilter" 
                className="form-control"
                value={filters.status}
                onChange={handleFilterChange}
              >
                <option value="all">All</option>
                <option value="clean">Clean</option>
                <option value="malicious">Malicious</option>
                <option value="suspicious">Suspicious</option>
              </select>
            </div>
            
            <div className="filter-group">
              <label htmlFor="dateRangeFilter">Date Range:</label>
              <select 
                id="dateRangeFilter" 
                className="form-control"
                value={filters.dateRange}
                onChange={handleFilterChange}
              >
                <option value="all">All Time</option>
                <option value="today">Today</option>
                <option value="week">This Week</option>
                <option value="month">This Month</option>
              </select>
            </div>
            
            <div className="filter-group">
              <label htmlFor="searchFilter">Search:</label>
              <input 
                type="text" 
                id="searchFilter" 
                className="form-control" 
                placeholder="Search by filename"
                value={filters.search}
                onChange={handleFilterChange}
              />
            </div>
            
            <div className="filter-buttons">
              <button 
                className="btn btn-primary"
                onClick={applyFilters}
              >
                Apply Filters
              </button>
              
              <button 
                className="btn btn-secondary"
                onClick={resetFilters}
              >
                Reset Filters
              </button>
              
              <button 
                className="btn btn-secondary"
                onClick={() => setShowExportModal(true)}
                disabled={filteredResults.length === 0}
              >
                Export Results
              </button>
            </div>
          </div>
          
          <div className="results-table-container">
            {loading ? (
              <div className="loading">Loading scan results...</div>
            ) : displayedResults.length === 0 ? (
              <div className="no-results">No scan results found.</div>
            ) : (
              <table className="table">
                <thead>
                  <tr>
                    <th onClick={() => handleSort('filename')}>
                      Filename <span className="sort-icon">{getSortIcon('filename')}</span>
                    </th>
                    <th onClick={() => handleSort('scan_date')} className="mobile-hidden">
                      Scan Date <span className="sort-icon">{getSortIcon('scan_date')}</span>
                    </th>
                    <th onClick={() => handleSort('detection_ratio')}>
                      Detection Ratio <span className="sort-icon">{getSortIcon('detection_ratio')}</span>
                    </th>
                    <th>Status</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {displayedResults.map((result) => (
                    <tr key={result.scan_id}>
                      <td>{result.filename}</td>
                      <td className="mobile-hidden">{formatDate(result.scan_date)}</td>
                      <td>{result.detection_ratio}</td>
                      <td>
                        <span className={`status-badge ${getStatusBadgeClass(result)}`}>
                          {getStatusText(result)}
                        </span>
                      </td>
                      <td>
                        <div className="file-actions">
                          <button 
                            className="btn btn-primary"
                            onClick={() => viewScanDetails(result.scan_id)}
                          >
                            View Details
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            
            {!loading && filteredResults.length > 0 && (
              <div className="pagination">
                <button 
                  className="pagination-button"
                  onClick={() => handlePageChange(pagination.currentPage - 1)}
                  disabled={pagination.currentPage === 1}
                >
                  Previous
                </button>
                <span className="pagination-info">
                  Page {pagination.currentPage} of {pagination.totalPages}
                </span>
                <button 
                  className="pagination-button"
                  onClick={() => handlePageChange(pagination.currentPage + 1)}
                  disabled={pagination.currentPage === pagination.totalPages}
                >
                  Next
                </button>
              </div>
            )}
          </div>
        </>
      ) : (
        <div className="scan-details">
          <div className="scan-details-header">
            <h2>Scan Details</h2>
            <button 
              className="btn btn-secondary"
              onClick={closeScanDetails}
            >
              Back to Results
            </button>
          </div>
          
          <div className="scan-details-body">
            <div className="scan-details-section">
              <h3>File Information</h3>
              <div className="scan-details-grid">
                <div className="scan-details-item">
                  <div className="scan-details-label">Filename</div>
                  <div className="scan-details-value">{selectedScan.filename}</div>
                </div>
                <div className="scan-details-item">
                  <div className="scan-details-label">Scan Date</div>
                  <div className="scan-details-value">{formatDate(selectedScan.scan_date)}</div>
                </div>
                <div className="scan-details-item">
                  <div className="scan-details-label">Detection Ratio</div>
                  <div className="scan-details-value">{selectedScan.detection_ratio}</div>
                </div>
                <div className="scan-details-item">
                  <div className="scan-details-label">Status</div>
                  <div className="scan-details-value">
                    <span className={`status-badge ${getStatusBadgeClass(selectedScan)}`}>
                      {getStatusText(selectedScan)}
                    </span>
                  </div>
                </div>
              </div>
            </div>
            
            {selectedScan.summary && (
              <div className="scan-details-section">
                <h3>Scan Summary</h3>
                <div className="scan-summary">
                  <div className="summary-item summary-item-malicious">
                    <div className="summary-count">{selectedScan.summary.stats.malicious}</div>
                    <div className="summary-label">Malicious</div>
                  </div>
                  <div className="summary-item summary-item-suspicious">
                    <div className="summary-count">{selectedScan.summary.stats.suspicious}</div>
                    <div className="summary-label">Suspicious</div>
                  </div>
                  <div className="summary-item summary-item-harmless">
                    <div className="summary-count">{selectedScan.summary.stats.harmless}</div>
                    <div className="summary-label">Harmless</div>
                  </div>
                  <div className="summary-item summary-item-undetected">
                    <div className="summary-count">{selectedScan.summary.stats.undetected}</div>
                    <div className="summary-label">Undetected</div>
                  </div>
                </div>
              </div>
            )}
            
            {selectedScan.results && selectedScan.results.length > 0 && (
              <div className="scan-details-section">
                <h3>Detection Details</h3>
                <div className="detection-table-container">
                  <table className="table">
                    <thead>
                      <tr>
                        <th>Engine</th>
                        <th className="mobile-hidden">Version</th>
                        <th>Result</th>
                        <th className="mobile-hidden">Category</th>
                        <th className="mobile-hidden">Update Date</th>
                      </tr>
                    </thead>
                    <tbody>
                      {selectedScan.results.map((result, index) => (
                        <tr key={index}>
                          <td>{result.engine_name}</td>
                          <td className="mobile-hidden">{result.engine_version}</td>
                          <td>{result.result || 'Clean'}</td>
                          <td className="mobile-hidden">{result.category}</td>
                          <td className="mobile-hidden">{formatDate(result.update_date)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
      
      {showExportModal && (
        <div className="modal-overlay">
          <div className="modal">
            <div className="modal-header">
              <h2>Export Scan Results</h2>
              <button 
                className="modal-close"
                onClick={() => setShowExportModal(false)}
              >
                ×
              </button>
            </div>
            <div className="modal-body">
              <div className="export-options">
                <div className="export-option">
                  <input 
                    type="radio" 
                    id="csv" 
                    name="exportFormat" 
                    value="csv"
                    checked={exportFormat === 'csv'}
                    onChange={(e) => setExportFormat(e.target.value)}
                  />
                  <label htmlFor="csv">CSV Format (.csv)</label>
                </div>
                <div className="export-option">
                  <input 
                    type="radio" 
                    id="json" 
                    name="exportFormat" 
                    value="json"
                    checked={exportFormat === 'json'}
                    onChange={(e) => setExportFormat(e.target.value)}
                  />
                  <label htmlFor="json">JSON Format (.json)</label>
                </div>
              </div>
            </div>
            <div className="modal-footer">
              <button 
                className="btn btn-secondary"
                onClick={() => setShowExportModal(false)}
              >
                Cancel
              </button>
              <button 
                className="btn btn-primary"
                onClick={exportResults}
              >
                Export
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ScanResultsPage;