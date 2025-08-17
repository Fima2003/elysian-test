import bcrypt
from config import get_config
import logging

logger = logging.getLogger(__name__)
config = get_config()

def hash_password(password: str) -> str:
    """Hash a password using bcrypt"""
    try:
        # Convert password to bytes
        password_bytes = password.encode('utf-8')
        
        # Generate salt and hash password
        salt = bcrypt.gensalt(rounds=config.BCRYPT_ROUNDS)
        hashed = bcrypt.hashpw(password_bytes, salt)
        
        # Return as string for storage
        return hashed.decode('utf-8')
        
    except Exception as e:
        logger.error(f"Failed to hash password: {e}")
        raise

def verify_password(password: str, hashed_password) -> bool:
    """Verify a password against its hash"""
    try:
        # Convert password to bytes
        password_bytes = password.encode('utf-8')
        
        # Handle both string and bytes for hashed_password
        if isinstance(hashed_password, str):
            hashed_bytes = hashed_password.encode('utf-8')
        elif isinstance(hashed_password, bytes):
            hashed_bytes = hashed_password
        else:
            raise TypeError(f"hashed_password must be str or bytes, got {type(hashed_password)}")
        
        # Verify password
        return bcrypt.checkpw(password_bytes, hashed_bytes)
        
    except (TypeError, AttributeError) as e:
        # Let input validation errors propagate
        logger.error(f"Invalid input for password verification: {e}")
        raise
    except ValueError as e:
        # Let bcrypt validation errors propagate (e.g., invalid salt)
        logger.error(f"Invalid hash format: {e}")
        raise
    except Exception as e:
        # Catch other unexpected errors
        logger.error(f"Failed to verify password: {e}")
        return False
