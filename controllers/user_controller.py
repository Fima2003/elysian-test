from flask import request, jsonify
from models.user import UserLogin, UserCreate, UserResponse
from services.user_service import user_service
from pydantic import ValidationError
import requests
import logging
from config import get_config

logger = logging.getLogger(__name__)

class UserController:
    """User API controller"""
    
    def __init__(self):
        self.service = user_service
    
    def register(self):
        """Register a new user"""
        try:
            # Try to parse JSON, handle parsing errors
            try:
                data = request.get_json(force=True)  # Force JSON parsing even with invalid Content-Type
            except Exception as json_error:
                logger.warning(f"JSON parsing error: {json_error}")
                return jsonify({
                    "success": False,
                    "message": "Invalid JSON format"
                }), 400
            
            if not data:
                return jsonify({
                    "success": False,
                    "message": "Invalid request format. JSON data required"
                }), 400
            
            # Validate request data
            try:
                user_data = UserCreate(**data)
            except ValidationError as e:
                error_messages = []
                for error in e.errors():
                    field = error['loc'][0] if error['loc'] else 'unknown'
                    message = error['msg']
                    error_messages.append(f"{field}: {message}")
                
                main_message = "Validation error: " + "; ".join(error_messages)
                
                return jsonify({
                    "success": False,
                    "message": main_message,
                    "errors": error_messages
                }), 400
            
            # Create user
            success, message, user_response = self.service.create_user(user_data)
            
            if success:
                # Convert user response to dict with proper ObjectId serialization
                user_dict = user_response.model_dump(mode='json') if user_response else None
                return jsonify({
                    "success": True,
                    "message": message,
                    "user": user_dict
                }), 201
            else:
                status_code = 409 if "already exists" in message else 400
                return jsonify({
                    "success": False,
                    "message": message
                }), status_code
                
        except Exception as e:
            logger.error(f"Registration error: {e}")
            return jsonify({
                "success": False,
                "message": "Internal server error"
            }), 500
    
    def login(self):
        """User login"""
        try:
            # Try to parse JSON, handle parsing errors
            try:
                data = request.get_json(force=True)  # Force JSON parsing even with invalid Content-Type
            except Exception as json_error:
                logger.warning(f"JSON parsing error: {json_error}")
                return jsonify({
                    "success": False,
                    "message": "Invalid JSON format"
                }), 400
            
            if not data:
                return jsonify({
                    "success": False,
                    "message": "Invalid request format. JSON data required"
                }), 400
            
            # Validate request data
            try:
                login_data = UserLogin(**data)
            except ValidationError as e:
                error_messages = []
                for error in e.errors():
                    field = error['loc'][0] if error['loc'] else 'unknown'
                    message = error['msg']
                    error_messages.append(f"{field}: {message}")
                
                main_message = "Validation error: " + "; ".join(error_messages)
                
                return jsonify({
                    "success": False,
                    "message": main_message, 
                    "errors": error_messages
                }), 400
            
            # Process login - authenticate user first
            is_authenticated, auth_message, user = self.service.authenticate_user(login_data)
            
            if not is_authenticated or user is None:
                status_code = 404 if "not found" in auth_message else 401
                return jsonify({
                    "success": False,
                    "message": auth_message
                }), status_code
            
            # If authenticated, get external intro and build response
            try:
                config = get_config()
                
                response = requests.get(f'{config.NODE_URI}/get-intro')
                response.raise_for_status()
                intro_output = response.json().get('output')
                
                # Convert user to response format
                user_response = UserResponse(
                    _id=user.id,
                    email=user.email,
                    created_at=user.created_at,
                    updated_at=user.updated_at
                )
                
                return jsonify({
                    "success": True,
                    "message": "Login successful",
                    "user": user_response.model_dump(mode='json'),
                    "token": intro_output  # Using intro_output as token for now
                }), 200
                
            except requests.RequestException as e:
                logger.error(f"External service error: {e}")
                return jsonify({
                    "success": False,
                    "message": "Could not get intro"
                }), 503
            
        except Exception as e:
            logger.error(f"Login error: {e}")
            return jsonify({
                "success": False,
                "message": "Internal server error"
            }), 500

# Global controller instance
user_controller = UserController()
