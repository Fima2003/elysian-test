"""
Test configuration and fixtures for the testing module.
"""

import pytest
import os
import sys
from unittest.mock import MagicMock, patch
from pymongo.collection import Collection
from pymongo.database import Database

# Add the parent directory to the path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from application import create_app
from models.user import UserCreate, UserLogin


@pytest.fixture
def app():
    """Create and configure a test Flask app."""
    # Set testing environment
    os.environ['FLASK_ENV'] = 'testing'
    os.environ['MONGO_DATABASE'] = 'elysian_db_test'
    
    app = create_app()
    
    # Set testing mode
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    
    with app.app_context():
        yield app


@pytest.fixture
def client(app):
    """Create a test client."""
    return app.test_client()


@pytest.fixture
def mock_database_service():
    """Mock database service for testing."""
    from services.database_service import DatabaseService
    mock_service = MagicMock(spec=DatabaseService)
    mock_service.is_connected.return_value = True
    mock_service.get_collection.return_value = MagicMock(spec=Collection)
    return mock_service


@pytest.fixture
def mock_mongo_collection():
    """Mock MongoDB collection."""
    mock_collection = MagicMock(spec=Collection)
    return mock_collection


@pytest.fixture
def mock_mongo_database():
    """Mock MongoDB database."""
    mock_db = MagicMock(spec=Database)
    return mock_db


@pytest.fixture
def sample_user_data():
    """Sample user data for testing."""
    return {
        "email": "test@example.com",
        "password": "TestPassword123!",
        "full_name": "Test User",
        "age": 25
    }


@pytest.fixture
def sample_user_create(sample_user_data):
    """Sample UserCreate model for testing."""
    return UserCreate(**sample_user_data)


@pytest.fixture
def sample_user_login():
    """Sample UserLogin model for testing."""
    return UserLogin(
        email="test@example.com",
        password="TestPassword123!"
    )


@pytest.fixture
def sample_user_db_record():
    """Sample user database record."""
    from bson import ObjectId
    import bcrypt
    
    return {
        "_id": ObjectId(),
        "email": "test@example.com",
        "password_hash": bcrypt.hashpw("TestPassword123!".encode('utf-8'), bcrypt.gensalt()),
        "full_name": "Test User",
        "age": 25,
        "created_at": "2024-01-01T00:00:00.000000",
        "updated_at": "2024-01-01T00:00:00.000000"
    }


@pytest.fixture(autouse=True)
def mock_environment_variables():
    """Mock environment variables for testing."""
    with patch.dict(os.environ, {
        'MONGODB_URI': 'mongodb://localhost:27017/test_db',
        'DATABASE_NAME': 'test_db',
        'FLASK_ENV': 'testing',
        'SECRET_KEY': 'test_secret_key_for_testing_only'
    }):
        yield


@pytest.fixture
def mock_bcrypt():
    """Mock bcrypt operations."""
    with patch('bcrypt.hashpw') as mock_hash, \
         patch('bcrypt.checkpw') as mock_check, \
         patch('bcrypt.gensalt') as mock_salt:
        
        mock_salt.return_value = b'$2b$12$test_salt'
        mock_hash.return_value = b'$2b$12$test_hash'
        mock_check.return_value = True
        
        yield {
            'hashpw': mock_hash,
            'checkpw': mock_check,
            'gensalt': mock_salt
        }


@pytest.fixture
def api_headers():
    """Standard API headers for testing."""
    return {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
