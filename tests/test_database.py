"""
Unit tests for database functions.
Tests the user service and repository layers.
"""

import pytest
from unittest.mock import MagicMock, patch, Mock
from bson import ObjectId
import bcrypt
from pymongo.errors import DuplicateKeyError, ConnectionFailure
import sys
import os

# Add the parent directory to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.user import UserCreate, UserLogin


class TestUserModels:
    """Test cases for User models."""
    
    def test_user_create_valid(self):
        """Test creating a valid UserCreate model."""
        user_data = {
            "email": "test@example.com",
            "password": "TestPassword123!"
        }
        
        user = UserCreate(**user_data)
        
        assert user.email == "test@example.com"
        assert user.password == "TestPassword123!"
    
    def test_user_create_invalid_email(self):
        """Test UserCreate with invalid email domain."""
        with pytest.raises(ValueError, match="Email domain must have at least 2 letters"):
            UserCreate(email="test@example.c", password="TestPassword123!")
    
    def test_user_create_short_password(self):
        """Test UserCreate with short password."""
        with pytest.raises(ValueError, match="Password must be at least 6 characters long"):
            UserCreate(email="test@example.com", password="123")
    
    def test_user_login_valid(self):
        """Test creating a valid UserLogin model."""
        login_data = {
            "email": "test@example.com",
            "password": "TestPassword123!"
        }
        
        user_login = UserLogin(**login_data)
        
        assert user_login.email == "test@example.com"
        assert user_login.password == "TestPassword123!"
    
    def test_user_login_invalid_email_domain(self):
        """Test UserLogin with invalid email domain."""
        with pytest.raises(ValueError, match="Email domain must have at least 2 letters"):
            UserLogin(email="test@example.c", password="TestPassword123!")


class TestPasswordHashing:
    """Test cases for password hashing and validation."""
    
    @patch('utils.security.hash_password')
    def test_hash_password_called(self, mock_hash):
        """Test that password hashing is called during user creation."""
        mock_hash.return_value = "hashed_password"
        
        from utils.security import hash_password
        result = hash_password("TestPassword123!")
        
        mock_hash.assert_called_once_with("TestPassword123!")
    
    @patch('utils.security.verify_password')
    def test_verify_password_success(self, mock_verify):
        """Test password verification success."""
        mock_verify.return_value = True
        
        from utils.security import verify_password
        result = verify_password("TestPassword123!", "hashed_password")
        
        assert result is True
        mock_verify.assert_called_once_with("TestPassword123!", "hashed_password")
    
    @patch('utils.security.verify_password')
    def test_verify_password_failure(self, mock_verify):
        """Test password verification failure."""
        mock_verify.return_value = False
        
        from utils.security import verify_password
        result = verify_password("WrongPassword", "hashed_password")
        
        assert result is False
        mock_verify.assert_called_once_with("WrongPassword", "hashed_password")


class TestUserService:
    """Test cases for UserService class."""
    
    @patch('services.user_repository.user_repository')
    def test_user_service_init(self, mock_repository):
        """Test UserService initialization."""
        from services.user_service import UserService
        
        service = UserService()
        
        assert service.repository is not None
    
    @patch('services.user_repository.user_repository.create_user')
    def test_create_user_success(self, mock_create):
        """Test successful user creation through service."""
        from services.user_service import UserService
        from models.user import UserInDB, UserResponse
        from datetime import datetime, timezone
        
        # Mock user creation
        mock_user_in_db = MagicMock(spec=UserInDB)
        mock_user_in_db.id = ObjectId()
        mock_user_in_db.email = "test@example.com"
        mock_user_in_db.created_at = datetime.now(timezone.utc)
        mock_user_in_db.updated_at = datetime.now(timezone.utc)
        mock_create.return_value = mock_user_in_db
        
        service = UserService()
        user_create = UserCreate(email="test@example.com", password="TestPassword123!")
        
        success, message, user_response = service.create_user(user_create)
        
        assert success is True
        assert "successfully" in message.lower()
        mock_create.assert_called_once_with(user_create)
    
    @patch('services.user_repository.user_repository.create_user')
    def test_create_user_already_exists(self, mock_create):
        """Test user creation when email already exists."""
        from services.user_service import UserService
        
        mock_create.side_effect = ValueError("User with this email already exists")
        
        service = UserService()
        user_create = UserCreate(email="test@example.com", password="TestPassword123!")
        
        success, message, user_response = service.create_user(user_create)
        
        assert success is False
        assert "already exists" in message
        assert user_response is None


class TestUserRepository:
    """Test cases for UserRepository class."""
    
    @patch('services.database.db_service')
    def test_user_repository_init(self, mock_db_service):
        """Test UserRepository initialization."""
        from services.user_repository import UserRepository
        
        repository = UserRepository()
        
        assert repository.collection_name == "users"
    
    @patch('services.database.db_service.get_collection')
    @patch('utils.security.hash_password')
    def test_create_user_success(self, mock_hash, mock_get_collection):
        """Test successful user creation in repository."""
        from services.user_repository import UserRepository
        
        # Setup mocks
        mock_collection = MagicMock()
        mock_get_collection.return_value = mock_collection
        mock_hash.return_value = "hashed_password"
        
        # Mock successful insertion
        mock_result = MagicMock()
        mock_result.inserted_id = ObjectId()
        mock_collection.insert_one.return_value = mock_result
        
        # Mock find operations
        mock_collection.find_one.side_effect = [None, {"_id": mock_result.inserted_id, "email": "test@example.com"}]
        
        repository = UserRepository()
        user_create = UserCreate(email="test@example.com", password="TestPassword123!")
        
        result = repository.create_user(user_create)
        
        assert result is not None
        mock_collection.insert_one.assert_called_once()
    
    @patch('services.database.db_service.get_collection')
    def test_find_by_email_found(self, mock_get_collection):
        """Test finding user by email when user exists."""
        from services.user_repository import UserRepository
        from datetime import datetime, timezone
        
        mock_collection = MagicMock()
        mock_get_collection.return_value = mock_collection
        
        expected_user_doc = {
            "_id": ObjectId(), 
            "email": "test@example.com",
            "password": "hashed_password",
            "provider": "password",
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc)
        }
        mock_collection.find_one.return_value = expected_user_doc
        
        repository = UserRepository()
        result = repository.find_by_email("test@example.com")
        
        # Check that we got a UserInDB object back
        assert result is not None
        assert result.email == "test@example.com"
        assert result.password == "hashed_password"
        mock_collection.find_one.assert_called_once_with({"email": "test@example.com"})
    
    @patch('services.database.db_service.get_collection')
    def test_find_by_email_not_found(self, mock_get_collection):
        """Test finding user by email when user doesn't exist."""
        from services.user_repository import UserRepository
        
        mock_collection = MagicMock()
        mock_get_collection.return_value = mock_collection
        mock_collection.find_one.return_value = None
        
        repository = UserRepository()
        result = repository.find_by_email("nonexistent@example.com")
        
        assert result is None
