from pydantic import BaseModel, EmailStr, Field, field_validator
from typing import Optional, Dict, Any, Annotated
from datetime import datetime
from bson import ObjectId
import re

class PyObjectId(ObjectId):
    """Custom ObjectId type for Pydantic v2"""
    @classmethod
    def __get_pydantic_core_schema__(cls, source_type, handler):
        from pydantic_core import core_schema
        return core_schema.no_info_plain_validator_function(
            cls.validate,
            serialization=core_schema.to_string_ser_schema(),
        )
    
    @classmethod
    def validate(cls, v):
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid ObjectId")
        return ObjectId(v)

    @classmethod
    def __get_pydantic_json_schema__(cls, core_schema, handler):
        return {"type": "string"}

class UserBase(BaseModel):
    """Base user model with common fields"""
    email: EmailStr = Field(..., description="User email address")
    
    @field_validator('email')
    @classmethod
    def validate_email_domain(cls, v):
        """Validate email has at least 2 letters after the dot in domain"""
        email_str = str(v)
        # Check if there's an @ symbol
        if '@' not in email_str:
            raise ValueError('Invalid email format')
        
        # Get domain part (everything after @)
        domain = email_str.split('@')[-1]
        
        # Check if domain has a dot and at least 2 letters after the last dot
        if '.' not in domain:
            raise ValueError('Email domain must contain a dot')
        
        # Get the part after the last dot (TLD)
        tld = domain.split('.')[-1]
        
        if len(tld) < 2 or not tld.isalpha():
            raise ValueError('Email domain must have at least 2 letters after the dot')
        
        return v

class UserCreate(UserBase):
    """User creation model"""
    password: str = Field(..., description="User password")
    
    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        """Validate password strength"""
        if len(v.strip()) < 6:
            raise ValueError('Password must be at least 6 characters long')
        if len(v.strip()) > 128:
            raise ValueError('Password must be at most 128 characters long')
        return v.strip()

class UserLogin(BaseModel):
    """User login model"""
    email: EmailStr = Field(..., description="User email address")
    password: str = Field(..., description="User password")
    
    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        """Validate password is not empty"""
        if not v or len(v.strip()) == 0:
            raise ValueError('Password cannot be empty')
        return v
    
    @field_validator('email')
    @classmethod
    def validate_email_domain(cls, v):
        """Validate email has at least 2 letters after the dot in domain"""
        email_str = str(v)
        # Check if there's an @ symbol
        if '@' not in email_str:
            raise ValueError('Invalid email format')
        
        # Get domain part (everything after @)
        domain = email_str.split('@')[-1]
        
        # Check if domain has a dot and at least 2 letters after the last dot
        if '.' not in domain:
            raise ValueError('Email domain must contain a dot')
        
        # Get the part after the last dot (TLD)
        tld = domain.split('.')[-1]
        
        if len(tld) < 2 or not tld.isalpha():
            raise ValueError('Email domain must have at least 2 letters after the dot')
        
        return v

class UserResponse(UserBase):
    """User response model (without sensitive data)"""
    id: Optional[PyObjectId] = Field(alias="_id", default=None)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    
    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}

class UserInDB(UserBase):
    """User model as stored in database"""
    id: Optional[PyObjectId] = Field(alias="_id", default=None)
    password: str = Field(..., description="Hashed password")  # Match your MongoDB field name
    provider: Optional[str] = Field(default="password", description="Authentication provider")
    created_at: Optional[datetime] = Field(default_factory=datetime.utcnow)
    updated_at: Optional[datetime] = Field(default_factory=datetime.utcnow)
    
    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}

class LoginResponse(BaseModel):
    """Login response model"""
    message: str
    user: Optional[UserResponse] = None
    output: Optional[str] = None  # For external API response
