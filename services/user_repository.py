from typing import Optional, Dict, Any
from models.user import UserInDB, UserCreate
from services.database import db_service
from utils.security import hash_password
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class UserRepository:
    """User data access layer"""
    
    def __init__(self):
        self.collection_name = "users"
    
    def create_user(self, user_data: UserCreate) -> Optional[UserInDB]:
        """Create a new user"""
        try:
            collection = db_service.get_collection(self.collection_name)
            
            # Check if user already exists
            if self.find_by_email(user_data.email):
                raise ValueError("User with this email already exists")
            
            # Prepare user document
            user_doc = {
                "email": user_data.email.lower(),
                "password": hash_password(user_data.password),  # Match your MongoDB field name
                "provider": "password",
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow()
            }
            
            result = collection.insert_one(user_doc)
            user_doc["_id"] = result.inserted_id
            
            logger.info(f"Created user with email: {user_data.email}")
            return UserInDB(**user_doc)
            
        except Exception as e:
            logger.error(f"Failed to create user: {e}")
            raise
    
    def find_by_email(self, email: str) -> Optional[UserInDB]:
        """Find user by email"""
        try:
            collection = db_service.get_collection(self.collection_name)
            user_doc = collection.find_one({"email": email.lower()})
            
            if user_doc:
                return UserInDB(**user_doc)
            return None
            
        except Exception as e:
            logger.error(f"Failed to find user by email: {e}")
            raise
    
    def find_by_id(self, user_id: str) -> Optional[UserInDB]:
        """Find user by ID"""
        try:
            from bson import ObjectId
            collection = db_service.get_collection(self.collection_name)
            user_doc = collection.find_one({"_id": ObjectId(user_id)})
            
            if user_doc:
                return UserInDB(**user_doc)
            return None
            
        except Exception as e:
            logger.error(f"Failed to find user by ID: {e}")
            raise
    
    def update_user(self, user_id: str, update_data: Dict[str, Any]) -> Optional[UserInDB]:
        """Update user data"""
        try:
            from bson import ObjectId
            collection = db_service.get_collection(self.collection_name)
            
            update_data["updated_at"] = datetime.utcnow()
            
            result = collection.update_one(
                {"_id": ObjectId(user_id)},
                {"$set": update_data}
            )
            
            if result.modified_count > 0:
                return self.find_by_id(user_id)
            return None
            
        except Exception as e:
            logger.error(f"Failed to update user: {e}")
            raise
    
    def delete_user(self, user_id: str) -> bool:
        """Delete user"""
        try:
            from bson import ObjectId
            collection = db_service.get_collection(self.collection_name)
            
            result = collection.delete_one(
                {"_id": ObjectId(user_id)}
            )

            return result.deleted_count > 0
            
        except Exception as e:
            logger.error(f"Failed to delete user: {e}")
            raise

# Global repository instance
user_repository = UserRepository()
