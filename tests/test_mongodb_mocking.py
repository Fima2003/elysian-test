"""
Mock testing for MongoDB connections.
Tests database operations with mocked MongoDB connections.
"""

import pytest
import sys
import os
from datetime import datetime
from unittest.mock import MagicMock, patch, Mock
from bson import ObjectId
import mongomock
from pymongo.errors import ConnectionFailure, DuplicateKeyError

# Add the parent directory to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.user import UserCreate, UserLogin


class TestMongoMock:
    """Test cases using mongomock library."""
    
    @pytest.fixture
    def mock_db(self):
        """Create a mock MongoDB database using mongomock."""
        client = mongomock.MongoClient()
        return client.test_database
    
    @pytest.fixture
    def mock_collection(self, mock_db):
        """Create a mock MongoDB collection."""
        return mock_db.users
    
    def test_mock_insert_user(self, mock_collection):
        """Test inserting a user with mongomock."""
        user_data = {
            "email": "test@example.com",
            "password": "hashed_password",
            "provider": "password",
            "created_at": "2024-01-01T00:00:00"
        }
        
        result = mock_collection.insert_one(user_data)
        
        assert result.inserted_id is not None
        assert isinstance(result.inserted_id, ObjectId)
        
        # Verify the document was inserted
        inserted_user = mock_collection.find_one({"_id": result.inserted_id})
        assert inserted_user["email"] == "test@example.com"
        assert inserted_user["provider"] == "password"
    
    def test_mock_find_user_by_email(self, mock_collection):
        """Test finding a user by email with mongomock."""
        user_data = {
            "email": "test@example.com",
            "password": "hashed_password",
            "provider": "password"
        }
        
        # Insert user
        mock_collection.insert_one(user_data)
        
        # Find user
        found_user = mock_collection.find_one({"email": "test@example.com"})
        
        assert found_user is not None
        assert found_user["email"] == "test@example.com"
        assert found_user["provider"] == "password"
    
    def test_mock_user_not_found(self, mock_collection):
        """Test finding a non-existent user."""
        found_user = mock_collection.find_one({"email": "nonexistent@example.com"})
        
        assert found_user is None
    
    def test_mock_update_user(self, mock_collection):
        """Test updating a user with mongomock."""
        user_data = {
            "email": "test@example.com",
            "password": "hashed_password",
            "provider": "password"
        }
        
        # Insert user
        result = mock_collection.insert_one(user_data)
        user_id = result.inserted_id
        
        # Update user
        update_result = mock_collection.update_one(
            {"_id": user_id},
            {"$set": {"provider": "google", "updated_at": "2024-01-02T00:00:00"}}
        )
        
        assert update_result.modified_count == 1
        
        # Verify update
        updated_user = mock_collection.find_one({"_id": user_id})
        assert updated_user["provider"] == "google"
        assert updated_user["updated_at"] == "2024-01-02T00:00:00"
    
    def test_mock_delete_user(self, mock_collection):
        """Test deleting a user with mongomock."""
        user_data = {
            "email": "test@example.com",
            "password": "hashed_password",
            "provider": "password"
        }
        
        # Insert user
        result = mock_collection.insert_one(user_data)
        user_id = result.inserted_id
        
        # Delete user
        delete_result = mock_collection.delete_one({"_id": user_id})
        
        assert delete_result.deleted_count == 1
        
        # Verify deletion
        deleted_user = mock_collection.find_one({"_id": user_id})
        assert deleted_user is None
    
    def test_mock_duplicate_key_simulation(self, mock_collection):
        """Test simulating duplicate key error."""
        # Create unique index on email
        mock_collection.create_index("email", unique=True)
        
        user_data = {
            "email": "test@example.com",
            "password": "hashed_password",
            "provider": "password"
        }
        
        # Insert first user
        mock_collection.insert_one(user_data)
        
        # Try to insert duplicate - should raise DuplicateKeyError
        with pytest.raises(DuplicateKeyError):
            mock_collection.insert_one(user_data)
    
    def test_mock_count_documents(self, mock_collection):
        """Test counting documents with mongomock."""
        users = [
            {"email": "user1@example.com", "provider": "password"},
            {"email": "user2@example.com", "provider": "google"},
            {"email": "user3@example.com", "provider": "password"}
        ]
        
        # Insert users
        mock_collection.insert_many(users)
        
        # Count all users
        total_count = mock_collection.count_documents({})
        assert total_count == 3
        
        # Count password users only
        password_count = mock_collection.count_documents({"provider": "password"})
        assert password_count == 2
    
    def test_mock_aggregation(self, mock_collection):
        """Test aggregation with mongomock."""
        users = [
            {"email": "user1@example.com", "provider": "password", "age": 25},
            {"email": "user2@example.com", "provider": "google", "age": 30},
            {"email": "user3@example.com", "provider": "password", "age": 35}
        ]
        
        # Insert users
        mock_collection.insert_many(users)
        
        # Aggregate by provider
        pipeline = [
            {"$group": {"_id": "$provider", "count": {"$sum": 1}, "avg_age": {"$avg": "$age"}}}
        ]
        
        results = list(mock_collection.aggregate(pipeline))
        
        assert len(results) == 2
        
        # Find password provider stats
        password_stats = next(r for r in results if r["_id"] == "password")
        assert password_stats["count"] == 2
        assert password_stats["avg_age"] == 30  # (25 + 35) / 2


class TestMongoConnectionMocking:
    """Test cases for mocking MongoDB connection failures and errors."""
    
    @patch('pymongo.MongoClient')
    def test_connection_failure(self, mock_client):
        """Test handling MongoDB connection failure."""
        mock_client.side_effect = ConnectionFailure("Connection failed")
        
        with pytest.raises(ConnectionFailure):
            import pymongo
            pymongo.MongoClient("mongodb://localhost:27017")
    
    @patch('services.database.db_service')
    def test_database_service_connection_failure(self, mock_db_service):
        """Test database service with connection failure."""
        mock_db_service.is_connected.return_value = False
        mock_db_service.get_collection.return_value = None
        
        from services.database import db_service
        
        assert db_service.is_connected() is False
        assert db_service.get_collection("users") is None
    
    @patch('services.database.db_service')
    def test_database_service_successful_connection(self, mock_db_service):
        """Test database service with successful connection."""
        mock_collection = MagicMock()
        mock_db_service.is_connected.return_value = True
        mock_db_service.get_collection.return_value = mock_collection
        
        from services.database import db_service
        
        assert db_service.is_connected() is True
        collection = db_service.get_collection("users")
        assert collection == mock_collection
    
    def test_mock_collection_operations(self):
        """Test various collection operations with mocked collection."""
        mock_collection = MagicMock()
        
        # Mock insert_one
        mock_result = MagicMock()
        mock_result.inserted_id = ObjectId()
        mock_collection.insert_one.return_value = mock_result
        
        # Mock find_one
        expected_user = {"_id": mock_result.inserted_id, "email": "test@example.com"}
        mock_collection.find_one.return_value = expected_user
        
        # Test insert
        user_data = {"email": "test@example.com", "password": "hashed"}
        result = mock_collection.insert_one(user_data)
        
        assert result.inserted_id == mock_result.inserted_id
        mock_collection.insert_one.assert_called_once_with(user_data)
        
        # Test find
        found_user = mock_collection.find_one({"email": "test@example.com"})
        
        assert found_user == expected_user
        mock_collection.find_one.assert_called_once_with({"email": "test@example.com"})
    
    def test_mock_collection_errors(self):
        """Test collection operations with simulated errors."""
        mock_collection = MagicMock()
        
        # Simulate DuplicateKeyError
        mock_collection.insert_one.side_effect = DuplicateKeyError("Email already exists")
        
        with pytest.raises(DuplicateKeyError):
            mock_collection.insert_one({"email": "test@example.com"})
        
        # Simulate ConnectionFailure
        mock_collection.find_one.side_effect = ConnectionFailure("Connection lost")
        
        with pytest.raises(ConnectionFailure):
            mock_collection.find_one({"email": "test@example.com"})


class TestRepositoryWithMocks:
    """Test repository layer with mocked MongoDB."""
    
    @patch('services.user_repository.db_service')
    def test_user_repository_create_success(self, mock_db_service):
        """Test user repository create with mocked database."""
        from services.user_repository import UserRepository
        
        # Setup mock collection
        mock_collection = MagicMock()
        mock_db_service.get_collection.return_value = mock_collection
        
        # Mock successful insertion
        mock_result = MagicMock()
        mock_result.inserted_id = ObjectId()
        mock_collection.insert_one.return_value = mock_result
        
        # Test create user
        repository = UserRepository()
        user_create = UserCreate(email="test@example.com", password="TestPassword123!")
        
        # Mock find_by_email to return None (user doesn't exist)
        with patch.object(repository, 'find_by_email', return_value=None):
            result = repository.create_user(user_create)
        
        # Verify calls
        assert mock_db_service.get_collection.call_count >= 1
        assert mock_collection.insert_one.call_count >= 1
        assert result is not None
        assert result.email == "test@example.com"
    
    @patch('services.user_repository.db_service')
    def test_user_repository_find_by_email(self, mock_db_service):
        """Test user repository find by email with mocked database."""
        from services.user_repository import UserRepository
        
        # Setup mock collection
        mock_collection = MagicMock()
        mock_db_service.get_collection.return_value = mock_collection
        
        expected_user_doc = {
            "_id": ObjectId(), 
            "email": "test@example.com",
            "password": "$2b$12$hashedpassword",
            "provider": "password",
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow()
        }
        mock_collection.find_one.return_value = expected_user_doc
        
        # Test find by email
        repository = UserRepository()
        result = repository.find_by_email("test@example.com")
        
        # Verify call and result
        mock_collection.find_one.assert_called_once_with({"email": "test@example.com"})
        assert result is not None
        assert result.email == "test@example.com"
    
    @patch('services.database.db_service')
    def test_user_repository_duplicate_email(self, mock_db_service):
        """Test user repository with duplicate email."""
        from services.user_repository import UserRepository
        
        # Setup mock collection
        mock_collection = MagicMock()
        mock_db_service.get_collection.return_value = mock_collection
        
        # Mock that user already exists
        mock_collection.find_one.return_value = {"email": "test@example.com"}
        
        # Test create user with duplicate email
        repository = UserRepository()
        user_create = UserCreate(email="test@example.com", password="TestPassword123!")
        
        with pytest.raises(ValueError, match="User with this email already exists"):
            repository.create_user(user_create)


class TestServiceWithMocks:
    """Test service layer with mocked dependencies."""
    
    @patch('services.user_service.user_repository')
    def test_user_service_create_user(self, mock_repository):
        """Test user service create user with mocked repository."""
        from services.user_service import UserService
        from models.user import UserInDB
        
        # Mock successful user creation - add all required attributes
        mock_user_in_db = MagicMock(spec=UserInDB)
        mock_user_in_db.id = ObjectId()
        mock_user_in_db.email = "test@example.com"
        mock_user_in_db.created_at = datetime.utcnow()
        mock_user_in_db.updated_at = datetime.utcnow()
        mock_repository.create_user.return_value = mock_user_in_db
        
        # Test create user
        service = UserService()
        user_create = UserCreate(email="test@example.com", password="TestPassword123!")
        
        success, message, user_response = service.create_user(user_create)
        
        # Verify results
        assert success is True
        assert "successfully" in message.lower()
        mock_repository.create_user.assert_called_once_with(user_create)
    
    @patch('services.user_service.user_repository')
    def test_user_service_authenticate_user(self, mock_repository):
        """Test user service authenticate user with mocked repository."""
        from services.user_service import UserService
        from models.user import UserInDB
        
        # Mock successful authentication - return UserInDB object
        mock_user_in_db = MagicMock(spec=UserInDB)
        mock_user_in_db.id = ObjectId()
        mock_user_in_db.email = "test@example.com"
        mock_user_in_db.password = "$2b$12$hashedpassword"
        mock_repository.find_by_email.return_value = mock_user_in_db
        
        with patch('services.user_service.verify_password') as mock_verify:
            mock_verify.return_value = True
            
            # Test authenticate user
            service = UserService()
            user_login = UserLogin(email="test@example.com", password="TestPassword123!")
            
            success, message, login_response = service.authenticate_user(user_login)
            
            # Verify results
            assert success is True
            mock_repository.find_by_email.assert_called_once_with("test@example.com")
            mock_verify.assert_called_once_with("TestPassword123!", mock_user_in_db.password)
    
    @patch('services.user_service.user_repository')
    def test_user_service_user_not_found(self, mock_repository):
        """Test user service with user not found."""
        from services.user_service import UserService
        
        # Mock user not found
        mock_repository.find_by_email.return_value = None
        
        # Test authenticate non-existent user
        service = UserService()
        user_login = UserLogin(email="nonexistent@example.com", password="TestPassword123!")
        
        success, message, login_response = service.authenticate_user(user_login)
        
        # Verify results
        assert success is False
        assert "not found" in message.lower()
        assert login_response is None


class TestIntegrationWithMocks:
    """Integration tests with comprehensive mocking."""
    
    @patch('services.user_repository.db_service')
    def test_full_user_flow_with_mocks(self, mock_db_service):
        """Test complete user flow with mocked database."""
        from services.user_service import UserService
        
        # Setup mock collection
        mock_collection = MagicMock()
        mock_db_service.get_collection.return_value = mock_collection
        
        # Mock user creation flow
        mock_result = MagicMock()
        mock_result.inserted_id = ObjectId()
        mock_collection.insert_one.return_value = mock_result
        
        # Mock find operations with proper user documents
        created_user_doc = {
            "_id": mock_result.inserted_id,
            "email": "test@example.com",
            "password": "$2b$12$hashedpassword",
            "provider": "password",
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow()
        }
        
        mock_collection.find_one.side_effect = [
            None,  # User doesn't exist during creation check
            created_user_doc,  # User found after creation
            created_user_doc   # User found during authentication
        ]
        
        # Test user creation
        service = UserService()
        user_create = UserCreate(email="test@example.com", password="TestPassword123!")
        
        success, message, user_response = service.create_user(user_create)
        
        assert success is True
        assert user_response is not None
        
        # Test user authentication
        user_login = UserLogin(email="test@example.com", password="TestPassword123!")
        
        with patch('services.user_service.verify_password') as mock_verify:
            mock_verify.return_value = True
            
            success, message, login_response = service.authenticate_user(user_login)
            
            assert success is True
            assert login_response is not None
