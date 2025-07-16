"""
Tests for the scan results management functionality.
"""
import os
import json
import pytest
import datetime
from unittest.mock import patch, MagicMock
from flask import url_for
from backend.models.database import db, User, ApiKey, File, Scan, ScanResult, ScanStatus

@pytest.fixture
def test_scan_results(client, test_user, test_file, test_api_key):
    """Create test scan results for testing."""
    # Create multiple scan records with different statuses and dates
    scans = []
    
    # Completed scan with high detection ratio
    scan1 = Scan(
        file_id=test_file.id,
        api_key_id=test_api_key.id,
        vt_scan_id='scan-id-1',
        status=ScanStatus.COMPLETED,
        detection_ratio='10/70',
        scan_date=datetime.datetime.now() - datetime.timedelta(days=1),
        result_summary={
            'status': 'completed',
            'stats': {
                'malicious': 10,
                'suspicious': 5,
                'undetected': 55,
                'harmless': 0,
                'timeout': 0
            },
            'detection_ratio': '10/70'
        }
    )
    
    # Completed scan with low detection ratio
    scan2 = Scan(
        file_id=test_file.id,
        api_key_id=test_api_key.id,
        vt_scan_id='scan-id-2',
        status=ScanStatus.COMPLETED,
        detection_ratio='2/70',
        scan_date=datetime.datetime.now() - datetime.timedelta(days=2),
        result_summary={
            'status': 'completed',
            'stats': {
                'malicious': 2,
                'suspicious': 1,
                'undetected': 67,
                'harmless': 0,
                'timeout': 0
            },
            'detection_ratio': '2/70'
        }
    )
    
    # Failed scan
    scan3 = Scan(
        file_id=test_file.id,
        api_key_id=test_api_key.id,
        vt_scan_id='scan-id-3',
        status=ScanStatus.FAILED,
        scan_date=datetime.datetime.now() - datetime.timedelta(days=3)
    )
    
    # Pending scan
    scan4 = Scan(
        file_id=test_file.id,
        api_key_id=test_api_key.id,
        vt_scan_id='scan-id-4',
        status=ScanStatus.PENDING
    )
    
    db.session.add_all([scan1, scan2, scan3, scan4])
    db.session.commit()
    
    # Add scan results for the completed scans
    results1 = [
        ScanResult(
            scan_id=scan1.id,
            engine_name='Engine1',
            engine_version='1.0',
            result='malware',
            category='malicious',
            update_date=datetime.datetime.now() - datetime.timedelta(days=1)
        ),
        ScanResult(
            scan_id=scan1.id,
            engine_name='Engine2',
            engine_version='2.0',
            result='trojan',
            category='malicious',
            update_date=datetime.datetime.now() - datetime.timedelta(days=1)
        )
    ]
    
    results2 = [
        ScanResult(
            scan_id=scan2.id,
            engine_name='Engine1',
            engine_version='1.0',
            result='suspicious',
            category='suspicious',
            update_date=datetime.datetime.now() - datetime.timedelta(days=2)
        )
    ]
    
    db.session.add_all(results1 + results2)
    db.session.commit()
    
    scans = [scan1, scan2, scan3, scan4]
    yield scans

@pytest.mark.usefixtures('client_class', 'auth_tokens')
class TestScanResultsManagement:
    """Test the scan results management functionality."""
    
    def test_get_all_scan_results(self, test_scan_results):
        """Test getting all scan results."""
        # Make a request to get all scan results
        response = self.client.get(
            '/api/scan/results',
            headers={'Authorization': f'Bearer {self.access_token}'}
        )
        
        # Check the response
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'scans' in data
        assert 'pagination' in data
        assert len(data['scans']) == 4  # All scans should be returned
        
        # Check pagination info
        assert data['pagination']['page'] == 1
        assert data['pagination']['per_page'] == 10
        assert data['pagination']['total_items'] == 4
    
    def test_filter_scan_results_by_status(self, test_scan_results):
        """Test filtering scan results by status."""
        # Make a request to get completed scan results
        response = self.client.get(
            '/api/scan/results?status=completed',
            headers={'Authorization': f'Bearer {self.access_token}'}
        )
        
        # Check the response
        assert response.status_code == 200
        data = json.loads(response.data)
        assert len(data['scans']) == 2  # Only completed scans
        
        # Make a request to get failed scan results
        response = self.client.get(
            '/api/scan/results?status=failed',
            headers={'Authorization': f'Bearer {self.access_token}'}
        )
        
        # Check the response
        assert response.status_code == 200
        data = json.loads(response.data)
        assert len(data['scans']) == 1  # Only failed scans
    
    def test_filter_scan_results_by_detection_ratio(self, test_scan_results):
        """Test filtering scan results by detection ratio."""
        # Make a request to get scan results with detection ratio >= 5
        response = self.client.get(
            '/api/scan/results?detection_min=5',
            headers={'Authorization': f'Bearer {self.access_token}'}
        )
        
        # Check the response
        assert response.status_code == 200
        data = json.loads(response.data)
        assert len(data['scans']) == 1  # Only scan1 has detection ratio >= 5
        assert data['scans'][0]['detection_ratio'] == '10/70'
        
        # Make a request to get scan results with detection ratio <= 5
        response = self.client.get(
            '/api/scan/results?detection_max=5',
            headers={'Authorization': f'Bearer {self.access_token}'}
        )
        
        # Check the response
        assert response.status_code == 200
        data = json.loads(response.data)
        # Should include scan2 (2/70) and the failed/pending scans (no detection ratio)
        assert len(data['scans']) == 3
    
    def test_sort_scan_results(self, test_scan_results):
        """Test sorting scan results."""
        # Make a request to get scan results sorted by scan date (ascending)
        response = self.client.get(
            '/api/scan/results?sort_by=scan_date&sort_order=asc',
            headers={'Authorization': f'Bearer {self.access_token}'}
        )
        
        # Check the response
        assert response.status_code == 200
        data = json.loads(response.data)
        # The oldest scan should be first (scan3, then scan2, then scan1)
        # scan4 (pending) has no scan date so it might be last or first depending on DB handling
        scans = data['scans']
        for i in range(1, len(scans)):
            if scans[i-1].get('scan_date') and scans[i].get('scan_date'):
                assert scans[i-1]['scan_date'] <= scans[i]['scan_date']
        
        # Make a request to get scan results sorted by detection ratio (descending)
        response = self.client.get(
            '/api/scan/results?sort_by=detection_ratio&sort_order=desc',
            headers={'Authorization': f'Bearer {self.access_token}'}
        )
        
        # Check the response
        assert response.status_code == 200
        data = json.loads(response.data)
        # The scan with highest detection ratio should be first
        scans = data['scans']
        assert scans[0]['detection_ratio'] == '10/70'
    
    def test_pagination(self, test_scan_results):
        """Test pagination of scan results."""
        # Make a request to get the first page with 2 results per page
        response = self.client.get(
            '/api/scan/results?page=1&per_page=2',
            headers={'Authorization': f'Bearer {self.access_token}'}
        )
        
        # Check the response
        assert response.status_code == 200
        data = json.loads(response.data)
        assert len(data['scans']) == 2
        assert data['pagination']['page'] == 1
        assert data['pagination']['per_page'] == 2
        assert data['pagination']['total_pages'] == 2
        assert data['pagination']['total_items'] == 4
        
        # Make a request to get the second page
        response = self.client.get(
            '/api/scan/results?page=2&per_page=2',
            headers={'Authorization': f'Bearer {self.access_token}'}
        )
        
        # Check the response
        assert response.status_code == 200
        data = json.loads(response.data)
        assert len(data['scans']) == 2
        assert data['pagination']['page'] == 2
    
    def test_export_scan_results_csv(self, test_scan_results):
        """Test exporting scan results as CSV."""
        # Get the first completed scan
        scan = test_scan_results[0]  # This is scan1 with high detection ratio
        
        # Make a request to export the scan results as CSV
        response = self.client.get(
            f'/api/scan/{scan.id}/export?format=csv',
            headers={'Authorization': f'Bearer {self.access_token}'}
        )
        
        # Check the response
        assert response.status_code == 200
        assert response.headers['Content-Type'] == 'text/csv; charset=utf-8'
        assert 'attachment; filename=' in response.headers['Content-Disposition']
        
        # Check the content
        content = response.data.decode('utf-8')
        assert 'Engine Name,Engine Version,Result,Category,Update Date' in content
        assert 'Engine1,1.0,malware,malicious,' in content
        assert 'Engine2,2.0,trojan,malicious,' in content
    
    def test_export_scan_results_json(self, test_scan_results):
        """Test exporting scan results as JSON."""
        # Get the first completed scan
        scan = test_scan_results[0]  # This is scan1 with high detection ratio
        
        # Make a request to export the scan results as JSON
        response = self.client.get(
            f'/api/scan/{scan.id}/export?format=json',
            headers={'Authorization': f'Bearer {self.access_token}'}
        )
        
        # Check the response
        assert response.status_code == 200
        assert response.headers['Content-Type'] == 'application/json; charset=utf-8'
        assert 'attachment; filename=' in response.headers['Content-Disposition']
        
        # Check the content
        data = json.loads(response.data)
        assert data['scan_id'] == str(scan.id)
        assert data['detection_ratio'] == '10/70'
        assert len(data['results']) == 2
        assert data['results'][0]['engine_name'] == 'Engine1'
        assert data['results'][0]['result'] == 'malware'
        assert data['results'][1]['engine_name'] == 'Engine2'
        assert data['results'][1]['result'] == 'trojan'
    
    def test_export_all_scan_results(self, test_scan_results):
        """Test exporting all scan results."""
        # Make a request to export all scan results as CSV
        response = self.client.get(
            '/api/scan/results/export?format=csv',
            headers={'Authorization': f'Bearer {self.access_token}'}
        )
        
        # Check the response
        assert response.status_code == 200
        assert response.headers['Content-Type'] == 'text/csv; charset=utf-8'
        assert 'attachment; filename=' in response.headers['Content-Disposition']
        
        # Check the content
        content = response.data.decode('utf-8')
        assert 'Scan ID,File Name,File Hash (SHA256),Detection Ratio,Scan Date,Status' in content
        assert '10/70' in content
        assert '2/70' in content
        assert 'completed' in content
        assert 'failed' in content
        
        # Make a request to export all scan results as JSON
        response = self.client.get(
            '/api/scan/results/export?format=json',
            headers={'Authorization': f'Bearer {self.access_token}'}
        )
        
        # Check the response
        assert response.status_code == 200
        assert response.headers['Content-Type'] == 'application/json; charset=utf-8'
        assert 'attachment; filename=' in response.headers['Content-Disposition']
        
        # Check the content
        data = json.loads(response.data)
        assert len(data) == 4
        assert any(scan['detection_ratio'] == '10/70' for scan in data)
        assert any(scan['detection_ratio'] == '2/70' for scan in data)
        assert any(scan['status'] == 'completed' for scan in data)
        assert any(scan['status'] == 'failed' for scan in data)
    
    def test_filter_export_scan_results(self, test_scan_results):
        """Test filtering exported scan results."""
        # Make a request to export only completed scan results
        response = self.client.get(
            '/api/scan/results/export?status=completed&format=json',
            headers={'Authorization': f'Bearer {self.access_token}'}
        )
        
        # Check the response
        assert response.status_code == 200
        data = json.loads(response.data)
        assert len(data) == 2
        assert all(scan['status'] == 'completed' for scan in data)
        
        # Make a request to export scan results with high detection ratio
        response = self.client.get(
            '/api/scan/results/export?detection_min=5&format=json',
            headers={'Authorization': f'Bearer {self.access_token}'}
        )
        
        # Check the response
        assert response.status_code == 200
        data = json.loads(response.data)
        assert len(data) == 1
        assert data[0]['detection_ratio'] == '10/70'