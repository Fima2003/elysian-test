from typing import Optional, Tuple
from models.user import UserCreate, UserLogin, UserInDB, UserResponse, LoginResponse
from services.user_repository import user_repository
from utils.security import verify_password
import requests
import logging
from config import get_config

logger = logging.getLogger(__name__)
config = get_config()

class UserService:
    """User business logic service"""
    
    def __init__(self):
        self.repository = user_repository
    
    def create_user(self, user_data: UserCreate) -> Tuple[bool, str, Optional[UserResponse]]:
        """
        Create a new user
        Returns: (success, message, user_response)
        """
        try:
            # Create user in database
            user_in_db = self.repository.create_user(user_data)
            
            if user_in_db:
                # Convert to response model (without sensitive data)
                user_response = UserResponse(
                    id=user_in_db.id,
                    email=user_in_db.email,
                    created_at=user_in_db.created_at,
                    updated_at=user_in_db.updated_at
                )
                
                logger.info(f"User created successfully: {user_data.email}")
                return True, "User created successfully", user_response
            
            return False, "Failed to create user", None
            
        except ValueError as e:
            # Business logic errors (like duplicate email)
            logger.warning(f"User creation failed: {e}")
            return False, str(e), None
        except Exception as e:
            # Technical errors
            logger.error(f"User creation error: {e}")
            return False, "Internal server error", None
    
    def authenticate_user(self, login_data: UserLogin) -> Tuple[bool, str, Optional[UserInDB]]:
        """
        Authenticate user credentials
        Returns: (success, message, user)
        """
        try:
            # Find user by email
            user = self.repository.find_by_email(login_data.email)
            
            if not user:
                logger.warning(f"Login attempt for non-existent user: {login_data.email}")
                return False, "User was not found", None
            
            # Verify password
            if not verify_password(login_data.password, user.password):  # Use 'password' field instead of 'password_hash'
                logger.warning(f"Invalid password for user: {login_data.email}")
                return False, "Incorrect password", None
            
            logger.info(f"User authenticated successfully: {login_data.email}")
            return True, "Authentication successful", user
            
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return False, "Internal server error", None
    
    def login(self, login_data: UserLogin) -> Tuple[int, LoginResponse]:
        """
        Complete login process including external API call
        Returns: (status_code, response)
        """
        try:
            # Authenticate user
            is_authenticated, message, user = self.authenticate_user(login_data)
            
            if not is_authenticated:
                status_code = 404 if "not found" in message else 401
                return status_code, LoginResponse(message=message)
            
            # Get intro from external service
            try:
                response = requests.get(f'{config.NODE_URI}/get-intro')
                response.raise_for_status()
                intro_output = response.json().get('output')
                
                # Convert user to response model
                user_response = UserResponse(
                    id=user.id,
                    email=user.email,
                    created_at=user.created_at,
                    updated_at=user.updated_at
                )
                
                return 200, LoginResponse(
                    message="Login successful",
                    user=user_response,
                    output=intro_output
                )
                
            except requests.RequestException as e:
                logger.error(f"External service error: {e}")
                return 503, LoginResponse(message="Could not get intro")
            
        except Exception as e:
            logger.error(f"Login process error: {e}")
            return 500, LoginResponse(message="Internal server error")

# Global service instance
user_service = UserService()
