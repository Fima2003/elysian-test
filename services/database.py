from typing import Optional
from pymongo import MongoClient
from pymongo.database import Database
from pymongo.collection import Collection
from config import get_config
import logging

logger = logging.getLogger(__name__)

class DatabaseService:
    """Database connection service"""
    
    def __init__(self):
        self.config = get_config()
        self._client: Optional[MongoClient] = None
        self._db: Optional[Database] = None
    
    def connect(self) -> Database:
        """Establish database connection"""
        try:
            if self._client is None:
                self._client = MongoClient(self.config.MONGO_URI)
                self._db = self._client[self.config.MONGO_DATABASE]
                logger.info(f"Connected to MongoDB: {self.config.MONGO_DATABASE}")
            if self._db is None:
                raise Exception("Database not initialized")
            return self._db
        except Exception as e:
            logger.error(f"Failed to connect to MongoDB: {e}")
            raise
    
    def get_collection(self, name: str) -> Collection:
        """Get a specific collection"""
        db = self.connect()
        return db[name]
    
    def close(self):
        """Close database connection"""
        if self._client:
            self._client.close()
            self._client = None
            self._db = None
            logger.info("Closed MongoDB connection")
    
    def test_connection(self) -> bool:
        """Test database connection"""
        try:
            db = self.connect()
            db.list_collection_names()
            return True
        except Exception as e:
            logger.error(f"Database connection test failed: {e}")
            return False
    
    def is_connected(self) -> bool:
        """Check if database is currently connected"""
        try:
            if self._client is None or self._db is None:
                return False
            # Ping the database to verify connection is alive
            self._client.admin.command('ping')
            return True
        except Exception as e:
            logger.error(f"Database connection check failed: {e}")
            return False

# Global database instance
db_service = DatabaseService()
