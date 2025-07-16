import React from 'react';
import './ScanResultsPage.css';

const ScanResultsPage: React.FC = () => {
  return (
    <div className="scan-results-page">
      <h1>Scan Results</h1>
      <p className="page-description">
        View and analyze the results of your file scans.
      </p>
      
      <div className="results-filters">
        <div className="filter-group">
          <label htmlFor="statusFilter">Status:</label>
          <select id="statusFilter" className="form-control">
            <option value="all">All</option>
            <option value="clean">Clean</option>
            <option value="malicious">Malicious</option>
            <option value="suspicious">Suspicious</option>
          </select>
        </div>
        
        <div className="filter-group">
          <label htmlFor="dateFilter">Date Range:</label>
          <select id="dateFilter" className="form-control">
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
          />
        </div>
        
        <button className="btn btn-primary">
          Apply Filters
        </button>
        
        <button className="btn btn-secondary">
          Export Results
        </button>
      </div>
      
      <div className="results-table-container">
        <table className="table">
          <thead>
            <tr>
              <th>Filename</th>
              <th>Scan Date</th>
              <th>Detection Ratio</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {/* Scan results will be listed here */}
            <tr>
              <td colSpan={5} className="no-results">No scan results found.</td>
            </tr>
          </tbody>
        </table>
        
        <div className="pagination">
          <button className="pagination-button" disabled>Previous</button>
          <span className="pagination-info">Page 1 of 1</span>
          <button className="pagination-button" disabled>Next</button>
        </div>
      </div>
    </div>
  );
};

export default ScanResultsPage;