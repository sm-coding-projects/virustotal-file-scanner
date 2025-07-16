"""
Tests for the VirusTotal service and scan API.
"""
import os
import json
import pytest
from unittest.mock import patch, MagicMock
from flask import url_for
from backend.models.database import db, User, ApiKey, File, Scan, ScanResult, ScanStatus
from backend.services.virustotal import VirusTotalService

# Sample response data for mocking VirusTotal API responses
SAMPLE_SCAN_RESPONSE = {
    "data": {
        "id": "sample-analysis-id",
        "type": "analysis"
    }
}

SAMPLE_ANALYSIS_RESPONSE = {
    "data": {
        "id": "sample-analysis-id",
        "type": "analysis",
        "attributes": {
            "status": "completed",
            "stats": {
                "malicious": 2,
                "suspicious": 1,
                "undetected": 67,
                "harmless": 0,
                "timeout": 0
            },
            "results": {
                "Engine1": {
                    "category": "malicious",
                    "engine_name": "Engine1",
                    "engine_version": "1.0",
                    "result": "malware",
                    "engine_update": "20220101"
                },
                "Engine2": {
                    "category": "malicious",
                    "engine_name": "Engine2",
                    "engine_version": "2.0",
                    "result": "trojan",
                    "engine_update": "20220102"
                },
                "Engine3": {
                    "category": "suspicious",
                    "engine_name": "Engine3",
                    "engine_version": "3.0",
                    "result": "suspicious",
                    "engine_update": "20220103"
                }
            },
            "date": "2022-01-01T00:00:00Z"
        }
    }
}

SAMPLE_FILE_REPORT_RESPONSE = {
    "data": {
        "attributes": {
            "last_analysis_results": {
                "Engine1": {
                    "category": "malicious",
                    "engine_name": "Engine1",
                    "engine_version": "1.0",
                    "result": "malware",
                    "engine_update": "20220101"
                },
                "Engine2": {
                    "category": "malicious",
                    "engine_name": "Engine2",
                    "engine_version": "2.0",
                    "result": "trojan",
                    "engine_update": "20220102"
                }
            },
            "last_analysis_stats": {
                "malicious": 2,
                "suspicious": 0,
                "undetected": 68,
                "harmless": 0,
                "timeout": 0
            },
            "last_analysis_date": 1640995200  # 2022-01-01 00:00:00 UTC
        }
    }
}

@pytest.fixture
def mock_vt_service():
    """Create a mock VirusTotal service."""
    with patch('backend.services.virustotal.VirusTotalService') as mock:
        # Configure the mock service
        instance = mock.return_value
        
        # Mock validate_api_key
        instance.validate_api_key.return_value = (True, None)
        
        # Mock scan_file
        instance.scan_file.return_value = (True, None, SAMPLE_SCAN_RESPONSE)
        
        # Mock get_analysis_status
        instance.get_analysis_status.return_value = (True, None, SAMPLE_ANALYSIS_RESPONSE)
        
        # Mock get_file_report_by_hash
        instance.get_file_report_by_hash.return_value = (True, None, SAMPLE_FILE_REPORT_RESPONSE)
        
        # Mock rescan_file
        instance.rescan_file.return_value = (True, None, SAMPLE_SCAN_RESPONSE)
        
        # Mock parse_scan_results
        instance.parse_scan_results.return_value = {
            'status': 'completed',
            'stats': {
                'malicious': 2,
                'suspicious': 1,
                'undetected': 67,
                'harmless': 0,
                'timeout': 0
            },
            'detection_ratio': '2/70',
            'scan_date': '2022-01-01T00:00:00Z',
            'engine_results': [
                {
                    'engine_name': 'Engine1',
                    'engine_version': '1.0',
                    'result': 'malware',
                    'category': 'malicious',
                    'update_date': '20220101'
                },
                {
                    'engine_name': 'Engine2',
                    'engine_version': '2.0',
                    'result': 'trojan',
                    'category': 'malicious',
                    'update_date': '20220102'
                },
                {
                    'engine_name': 'Engine3',
                    'engine_version': '3.0',
                    'result': 'suspicious',
                    'category': 'suspicious',
                    'update_date': '20220103'
                }
            ]
        }
        
        yield instance

@pytest.fixture
def test_file(client, test_user):
    """Create a test file for scanning."""
    # Create a temporary file
    file_path = os.path.join(os.path.dirname(__file__), 'test_file.txt')
    with open(file_path, 'w') as f:
        f.write('Test file content for scanning')
    
    # Create a file record in the database
    file = File(
        user_id=test_user.id,
        filename='test_file.txt',
        file_size=len('Test file content for scanning'),
        mime_type='text/plain',
        storage_path=file_path,
        hash_md5='d41d8cd98f00b204e9800998ecf8427e',
        hash_sha1='da39a3ee5e6b4b0d3255bfef95601890afd80709',
        hash_sha256='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    )
    db.session.add(file)
    db.session.commit()
    
    yield file
    
    # Clean up
    if os.path.exists(file_path):
        os.remove(file_path)

@pytest.fixture
def test_api_key(client, test_user):
    """Create a test API key."""
    api_key = ApiKey(
        user_id=test_user.id,
        key_value='test-api-key',
        name='Test API Key',
        is_active=True
    )
    db.session.add(api_key)
    db.session.commit()
    
    yield api_key

def test_virustotal_service_validate_api_key(app):
    """Test VirusTotal service API key validation."""
    with app.app_context():
        # Mock the requests.get method
        with patch('requests.get') as mock_get:
            # Configure the mock to return a successful response
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_get.return_value = mock_response
            
            # Create a VirusTotal service instance
            vt_service = VirusTotalService('test-api-key')
            
            # Test valid API key
            is_valid, error = vt_service.validate_api_key()
            assert is_valid is True
            assert error is None
            
            # Configure the mock to return an error response
            mock_response.status_code = 401
            
            # Test invalid API key
            is_valid, error = vt_service.validate_api_key()
            assert is_valid is False
            assert error == "Invalid API key"

def test_virustotal_service_scan_file(app):
    """Test VirusTotal service file scanning."""
    with app.app_context():
        # Create a temporary file
        file_path = os.path.join(os.path.dirname(__file__), 'test_scan_file.txt')
        with open(file_path, 'w') as f:
            f.write('Test file content for scanning')
        
        try:
            # Mock the requests.post method
            with patch('requests.post') as mock_post:
                # Configure the mock to return a successful response
                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_response.json.return_value = SAMPLE_SCAN_RESPONSE
                mock_post.return_value = mock_response
                
                # Create a VirusTotal service instance
                vt_service = VirusTotalService('test-api-key')
                
                # Test file scanning
                success, error, data = vt_service.scan_file(file_path)
                assert success is True
                assert error is None
                assert data == SAMPLE_SCAN_RESPONSE
                
                # Configure the mock to return an error response
                mock_response.status_code = 401
                
                # Test file scanning with invalid API key
                success, error, data = vt_service.scan_file(file_path)
                assert success is False
                assert error == "Invalid API key"
                assert data is None
        finally:
            # Clean up
            if os.path.exists(file_path):
                os.remove(file_path)

def test_virustotal_service_get_analysis_status(app):
    """Test VirusTotal service analysis status checking."""
    with app.app_context():
        # Mock the requests.get method
        with patch('requests.get') as mock_get:
            # Configure the mock to return a successful response
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = SAMPLE_ANALYSIS_RESPONSE
            mock_get.return_value = mock_response
            
            # Create a VirusTotal service instance
            vt_service = VirusTotalService('test-api-key')
            
            # Test analysis status checking
            success, error, data = vt_service.get_analysis_status('sample-analysis-id')
            assert success is True
            assert error is None
            assert data == SAMPLE_ANALYSIS_RESPONSE
            
            # Configure the mock to return an error response
            mock_response.status_code = 404
            
            # Test analysis status checking with invalid analysis ID
            success, error, data = vt_service.get_analysis_status('invalid-analysis-id')
            assert success is False
            assert error == "Analysis not found"
            assert data is None

def test_virustotal_service_parse_scan_results(app):
    """Test VirusTotal service scan results parsing."""
    with app.app_context():
        # Create a VirusTotal service instance
        vt_service = VirusTotalService('test-api-key')
        
        # Test scan results parsing
        results = vt_service.parse_scan_results(SAMPLE_ANALYSIS_RESPONSE)
        
        # Verify the parsed results
        assert results['status'] == 'completed'
        assert results['detection_ratio'] == '2/70'
        assert len(results['engine_results']) == 3
        assert results['engine_results'][0]['engine_name'] == 'Engine1'
        assert results['engine_results'][0]['result'] == 'malware'
        assert results['engine_results'][1]['engine_name'] == 'Engine2'
        assert results['engine_results'][1]['result'] == 'trojan'
        assert results['engine_results'][2]['engine_name'] == 'Engine3'
        assert results['engine_results'][2]['result'] == 'suspicious'

@pytest.mark.usefixtures('client_class', 'auth_tokens')
class TestScanAPI:
    """Test the scan API endpoints."""
    
    def test_scan_file(self, test_file, test_api_key, mock_vt_service):
        """Test scanning a file."""
        with patch('backend.api.scan.VirusTotalService', return_value=mock_vt_service):
            # Make a request to scan the file
            response = self.client.post(
                f'/api/scan/file/{test_file.id}',
                headers={'Authorization': f'Bearer {self.access_token}'}
            )
            
            # Check the response
            assert response.status_code == 202
            data = json.loads(response.data)
            assert data['message'] == 'Scan initiated successfully'
            assert 'scan_id' in data
            assert data['status'] == 'scanning'
            
            # Verify that a scan record was created
            scan = Scan.query.filter_by(file_id=test_file.id).first()
            assert scan is not None
            assert scan.status == ScanStatus.SCANNING
            assert scan.vt_scan_id == 'sample-analysis-id'
    
    def test_get_scan_status(self, test_file, test_api_key, mock_vt_service):
        """Test getting scan status."""
        # Create a scan record
        scan = Scan(
            file_id=test_file.id,
            api_key_id=test_api_key.id,
            vt_scan_id='sample-analysis-id',
            status=ScanStatus.SCANNING
        )
        db.session.add(scan)
        db.session.commit()
        
        with patch('backend.api.scan.VirusTotalService', return_value=mock_vt_service):
            # Make a request to get the scan status
            response = self.client.get(
                f'/api/scan/{scan.id}/status',
                headers={'Authorization': f'Bearer {self.access_token}'}
            )
            
            # Check the response
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data['status'] == 'completed'
            assert data['detection_ratio'] == '2/70'
            
            # Verify that the scan record was updated
            updated_scan = Scan.query.get(scan.id)
            assert updated_scan.status == ScanStatus.COMPLETED
            assert updated_scan.detection_ratio == '2/70'
            
            # Verify that scan results were created
            results = ScanResult.query.filter_by(scan_id=scan.id).all()
            assert len(results) == 3
    
    def test_get_scan_results(self, test_file, test_api_key):
        """Test getting scan results."""
        # Create a scan record with results
        scan = Scan(
            file_id=test_file.id,
            api_key_id=test_api_key.id,
            vt_scan_id='sample-analysis-id',
            status=ScanStatus.COMPLETED,
            detection_ratio='2/70',
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
        db.session.add(scan)
        db.session.commit()
        
        # Add scan results
        result1 = ScanResult(
            scan_id=scan.id,
            engine_name='Engine1',
            engine_version='1.0',
            result='malware',
            category='malicious'
        )
        result2 = ScanResult(
            scan_id=scan.id,
            engine_name='Engine2',
            engine_version='2.0',
            result='trojan',
            category='malicious'
        )
        db.session.add_all([result1, result2])
        db.session.commit()
        
        # Make a request to get the scan results
        response = self.client.get(
            f'/api/scan/{scan.id}/results',
            headers={'Authorization': f'Bearer {self.access_token}'}
        )
        
        # Check the response
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'completed'
        assert data['detection_ratio'] == '2/70'
        assert len(data['results']) == 2
        assert data['results'][0]['engine_name'] == 'Engine1'
        assert data['results'][0]['result'] == 'malware'
        assert data['results'][1]['engine_name'] == 'Engine2'
        assert data['results'][1]['result'] == 'trojan'
    
    def test_rescan_file(self, test_file, test_api_key, mock_vt_service):
        """Test rescanning a file."""
        with patch('backend.api.scan.VirusTotalService', return_value=mock_vt_service):
            # Make a request to rescan the file
            response = self.client.post(
                f'/api/scan/file/{test_file.id}/rescan',
                headers={'Authorization': f'Bearer {self.access_token}'}
            )
            
            # Check the response
            assert response.status_code == 202
            data = json.loads(response.data)
            assert data['message'] == 'Rescan initiated successfully'
            assert 'scan_id' in data
            assert data['status'] == 'scanning'
            
            # Verify that a scan record was created
            scan = Scan.query.filter_by(file_id=test_file.id).first()
            assert scan is not None
            assert scan.status == ScanStatus.SCANNING
            assert scan.vt_scan_id == 'sample-analysis-id'
    
    def test_get_file_scans(self, test_file, test_api_key):
        """Test getting all scans for a file."""
        # Create scan records
        scan1 = Scan(
            file_id=test_file.id,
            api_key_id=test_api_key.id,
            status=ScanStatus.COMPLETED,
            detection_ratio='2/70'
        )
        scan2 = Scan(
            file_id=test_file.id,
            api_key_id=test_api_key.id,
            status=ScanStatus.FAILED
        )
        db.session.add_all([scan1, scan2])
        db.session.commit()
        
        # Make a request to get the file scans
        response = self.client.get(
            f'/api/scan/file/{test_file.id}',
            headers={'Authorization': f'Bearer {self.access_token}'}
        )
        
        # Check the response
        assert response.status_code == 200
        data = json.loads(response.data)
        assert len(data) == 2
        assert data[0]['status'] == 'completed'
        assert data[0]['detection_ratio'] == '2/70'
        assert data[1]['status'] == 'failed'