"""
Integration tests for API endpoints.
Tests the complete API flow from request to response.
"""

import pytest
import json
import sys
import os
from unittest.mock import patch, MagicMock

# Add the parent directory to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestHealthEndpoint:
    """Test cases for health check endpoint."""
    
    def test_health_check_success(self, client):
        """Test successful health check."""
        response = client.get('/health')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['status'] == 'healthy'
        assert 'timestamp' in data
    
    def test_health_check_database_connected(self, client):
        """Test health check shows database connection status."""
        with patch('services.database.db_service.is_connected') as mock_connected:
            mock_connected.return_value = True
            
            response = client.get('/health')
            
            assert response.status_code == 200
            data = response.get_json()
            assert data['database_connected'] is True
    
    def test_health_check_database_disconnected(self, client):
        """Test health check shows database disconnection status."""
        with patch('services.database.db_service.is_connected') as mock_connected:
            mock_connected.return_value = False
            
            response = client.get('/health')
            
            assert response.status_code == 200
            data = response.get_json()
            assert data['database_connected'] is False


class TestUserRegistrationEndpoint:
    """Test cases for user registration endpoint."""
    
    def test_register_success(self, client, api_headers):
        """Test successful user registration."""
        user_data = {
            "email": "test@example.com",
            "password": "TestPassword123!"
        }
        
        with patch('services.user_service.user_service.create_user') as mock_create:
            from models.user import UserResponse
            mock_user_response = MagicMock(spec=UserResponse)
            mock_user_response.model_dump.return_value = {
                "id": "507f1f77bcf86cd799439011",
                "email": "test@example.com"
            }
            mock_create.return_value = (True, "User created successfully", mock_user_response)
            
            response = client.post('/api/register', 
                                 data=json.dumps(user_data), 
                                 headers=api_headers)
            
            assert response.status_code == 201
            data = response.get_json()
            assert data['success'] is True
            assert data['message'] == "User created successfully"
            assert 'user' in data
    
    def test_register_missing_email(self, client, api_headers):
        """Test registration with missing email."""
        user_data = {
            "password": "TestPassword123!"
        }
        
        response = client.post('/api/register', 
                             data=json.dumps(user_data), 
                             headers=api_headers)
        
        assert response.status_code == 400
        data = response.get_json()
        assert data['success'] is False
        assert 'email' in data['message'].lower()
    
    def test_register_missing_password(self, client, api_headers):
        """Test registration with missing password."""
        user_data = {
            "email": "test@example.com"
        }
        
        response = client.post('/api/register', 
                             data=json.dumps(user_data), 
                             headers=api_headers)
        
        assert response.status_code == 400
        data = response.get_json()
        assert data['success'] is False
        assert 'password' in data['message'].lower()
    
    def test_register_invalid_email_format(self, client, api_headers):
        """Test registration with invalid email format."""
        user_data = {
            "email": "invalid-email",
            "password": "TestPassword123!"
        }
        
        response = client.post('/api/register', 
                             data=json.dumps(user_data), 
                             headers=api_headers)
        
        assert response.status_code == 400
        data = response.get_json()
        assert data['success'] is False
    
    def test_register_invalid_email_domain(self, client, api_headers):
        """Test registration with invalid email domain (less than 2 letters after dot)."""
        user_data = {
            "email": "test@example.c",
            "password": "TestPassword123!"
        }
        
        response = client.post('/api/register', 
                             data=json.dumps(user_data), 
                             headers=api_headers)
        
        assert response.status_code == 400
        data = response.get_json()
        assert data['success'] is False
        assert 'domain' in data['message'].lower()
    
    def test_register_short_password(self, client, api_headers):
        """Test registration with short password."""
        user_data = {
            "email": "test@example.com",
            "password": "123"
        }
        
        response = client.post('/api/register', 
                             data=json.dumps(user_data), 
                             headers=api_headers)
        
        assert response.status_code == 400
        data = response.get_json()
        assert data['success'] is False
        assert 'password' in data['message'].lower()
    
    def test_register_duplicate_user(self, client, api_headers):
        """Test registration with duplicate email."""
        user_data = {
            "email": "test@example.com",
            "password": "TestPassword123!"
        }
        
        with patch('services.user_service.user_service.create_user') as mock_create:
            mock_create.return_value = (False, "User with this email already exists", None)
            
            response = client.post('/api/register', 
                                 data=json.dumps(user_data), 
                                 headers=api_headers)
            
            assert response.status_code == 409
            data = response.get_json()
            assert data['success'] is False
            assert 'already exists' in data['message']
    
    def test_register_invalid_json(self, client):
        """Test registration with invalid JSON."""
        response = client.post('/api/register', 
                             data="invalid json", 
                             headers={'Content-Type': 'application/json'})
        
        assert response.status_code == 400
        data = response.get_json()
        assert data['success'] is False
    
    def test_register_empty_request(self, client, api_headers):
        """Test registration with empty request body."""
        response = client.post('/api/register', 
                             data=json.dumps({}), 
                             headers=api_headers)
        
        assert response.status_code == 400
        data = response.get_json()
        assert data['success'] is False


class TestUserLoginEndpoint:
    """Test cases for user login endpoint."""
    
    def test_login_success(self, client, api_headers):
        """Test successful user login."""
        login_data = {
            "email": "test@example.com",
            "password": "TestPassword123!"
        }
        
        with patch('services.user_service.user_service.authenticate_user') as mock_auth:
            # Create a mock UserInDB object
            from models.user import UserInDB, PyObjectId
            from bson import ObjectId
            mock_user = UserInDB(
                email="test@example.com",
                password="hashed_password",
                _id=PyObjectId("507f1f77bcf86cd799439011")
            )
            mock_auth.return_value = (True, "Login successful", mock_user)
            
            # Mock the external API call
            with patch('requests.get') as mock_get:
                mock_response = mock_get.return_value
                mock_response.raise_for_status.return_value = None
                mock_response.json.return_value = {"output": "jwt_token_here"}
                
                response = client.post('/api/login', 
                                     data=json.dumps(login_data), 
                                     headers=api_headers)
            
            assert response.status_code == 200
            data = response.get_json()
            assert data['success'] is True
            assert data['message'] == "Login successful"
            assert 'user' in data
            assert 'token' in data
    
    def test_login_invalid_credentials(self, client, api_headers):
        """Test login with invalid credentials."""
        login_data = {
            "email": "test@example.com",
            "password": "WrongPassword"
        }
        
        with patch('services.user_service.user_service.authenticate_user') as mock_auth:
            mock_auth.return_value = (False, "Invalid credentials", None)
            
            response = client.post('/api/login', 
                                 data=json.dumps(login_data), 
                                 headers=api_headers)
            
            assert response.status_code == 401
            data = response.get_json()
            assert data['success'] is False
            assert 'invalid' in data['message'].lower()
    
    def test_login_missing_email(self, client, api_headers):
        """Test login with missing email."""
        login_data = {
            "password": "TestPassword123!"
        }
        
        response = client.post('/api/login', 
                             data=json.dumps(login_data), 
                             headers=api_headers)
        
        assert response.status_code == 400
        data = response.get_json()
        assert data['success'] is False
    
    def test_login_missing_password(self, client, api_headers):
        """Test login with missing password."""
        login_data = {
            "email": "test@example.com"
        }
        
        response = client.post('/api/login', 
                             data=json.dumps(login_data), 
                             headers=api_headers)
        
        assert response.status_code == 400
        data = response.get_json()
        assert data['success'] is False
    
    def test_login_invalid_email_domain(self, client, api_headers):
        """Test login with invalid email domain."""
        login_data = {
            "email": "test@example.c",
            "password": "TestPassword123!"
        }
        
        response = client.post('/api/login', 
                             data=json.dumps(login_data), 
                             headers=api_headers)
        
        assert response.status_code == 400
        data = response.get_json()
        assert data['success'] is False


class TestRateLimiting:
    """Test cases for rate limiting functionality."""
    
    def test_login_rate_limit(self, client, api_headers):
        """Test rate limiting on login endpoint."""
        login_data = {
            "email": "test@example.com",
            "password": "TestPassword123!"
        }
        
        # Mock authentication to always fail to trigger rate limiting
        with patch('services.user_service.user_service.authenticate_user') as mock_auth:
            mock_auth.return_value = (False, "Invalid credentials", None)
            
            # Make multiple requests to trigger rate limit
            responses = []
            for i in range(6):  # Rate limit is 5 per minute for login
                response = client.post('/api/login', 
                                     data=json.dumps(login_data), 
                                     headers=api_headers)
                responses.append(response)
            
            # First 5 should be handled normally (return 401)
            for response in responses[:5]:
                assert response.status_code == 401
            
            # 6th request should be rate limited (return 429)
            assert responses[5].status_code == 429
    
    def test_register_rate_limit(self, client, api_headers):
        """Test rate limiting on register endpoint."""
        user_data = {
            "email": "test@example.com",
            "password": "TestPassword123!"
        }
        
        # Mock user creation to always fail to trigger rate limiting
        with patch('services.user_service.user_service.create_user') as mock_create:
            mock_create.return_value = (False, "User with this email already exists", None)
            
            # Make multiple requests to trigger rate limit
            responses = []
            for i in range(4):  # Rate limit is 3 per minute for register
                response = client.post('/api/register', 
                                     data=json.dumps(user_data), 
                                     headers=api_headers)
                responses.append(response)
            
            # First 3 should be handled normally (return 409)
            for response in responses[:3]:
                assert response.status_code == 409
            
            # 4th request should be rate limited (return 429)
            assert responses[3].status_code == 429


class TestSecurityHeaders:
    """Test cases for security headers."""
    
    def test_security_headers_present(self, client):
        """Test that security headers are present in responses."""
        response = client.get('/health')
        
        # Check for common security headers that should be set by Talisman
        assert response.status_code == 200
        
        # Note: The exact headers depend on your Talisman configuration
        # Common ones include:
        # - X-Content-Type-Options: nosniff
        # - X-Frame-Options: SAMEORIGIN
        # - X-XSS-Protection: 1; mode=block
        
        # At minimum, we expect some security-related headers
        assert len(response.headers) > 5  # Basic check that headers are being set
    
    def test_content_type_validation(self, client):
        """Test content type validation."""
        # Test with wrong content type
        response = client.post('/api/register', 
                             data="test data", 
                             headers={'Content-Type': 'text/plain'})
        
        # Should reject non-JSON content types
        assert response.status_code in [400, 415]  # Bad Request or Unsupported Media Type


class TestInputSanitization:
    """Test cases for input sanitization."""
    
    def test_xss_prevention_in_registration(self, client, api_headers):
        """Test XSS prevention in user registration."""
        malicious_data = {
            "email": "<script>alert('xss')</script>@example.com",
            "password": "TestPassword123!"
        }
        
        response = client.post('/api/register', 
                             data=json.dumps(malicious_data), 
                             headers=api_headers)
        
        # Should either reject the malicious input or sanitize it
        assert response.status_code == 400  # Expecting validation error
    
    def test_sql_injection_prevention(self, client, api_headers):
        """Test SQL injection prevention (even though we use MongoDB)."""
        malicious_data = {
            "email": "'; DROP TABLE users; --@example.com",
            "password": "TestPassword123!"
        }
        
        response = client.post('/api/register', 
                             data=json.dumps(malicious_data), 
                             headers=api_headers)
        
        # Should reject malicious input
        assert response.status_code == 400


class TestErrorHandling:
    """Test cases for error handling."""
    
    def test_404_for_nonexistent_endpoint(self, client):
        """Test 404 response for nonexistent endpoints."""
        response = client.get('/api/nonexistent')
        
        assert response.status_code == 404
        data = response.get_json()
        assert data['success'] is False
        assert 'not found' in data['message'].lower()
    
    def test_405_for_wrong_method(self, client):
        """Test 405 response for wrong HTTP method."""
        response = client.get('/api/register')  # Should be POST
        
        assert response.status_code == 405
        data = response.get_json()
        assert data['success'] is False
        assert 'method not allowed' in data['message'].lower()
    
    @patch('services.user_service.user_service.create_user')
    def test_500_internal_error_handling(self, mock_create, client, api_headers):
        """Test internal server error handling."""
        mock_create.side_effect = Exception("Database connection lost")
        
        user_data = {
            "email": "test@example.com",
            "password": "TestPassword123!"
        }
        
        response = client.post('/api/register', 
                             data=json.dumps(user_data), 
                             headers=api_headers)
        
        assert response.status_code == 500
        data = response.get_json()
        assert data['success'] is False
        assert 'internal server error' in data['message'].lower()
        # Should not expose sensitive error details
        assert 'database connection lost' not in data['message'].lower()
