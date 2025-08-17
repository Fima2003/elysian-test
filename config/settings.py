import os
from dotenv import load_dotenv
from typing import List

load_dotenv()

class Config:
    """Base configuration class"""
    
    # Database
    MONGO_URI: str = os.getenv('MONGO_URI', 'mongodb://localhost:27017/')
    MONGO_DATABASE: str = os.getenv('MONGO_DATABASE', 'elysian_db')
    
    # External Services
    NODE_URI: str = os.getenv('NODE_URI', 'http://localhost:3000')
    
    # Application
    FLASK_ENV: str = os.getenv('FLASK_ENV', 'development')
    FLASK_DEBUG: bool = os.getenv('FLASK_DEBUG', 'True').lower() == 'true'
    FLASK_HOST: str = os.getenv('FLASK_HOST', '127.0.0.1')
    FLASK_PORT: int = int(os.getenv('FLASK_PORT', '5000'))
    
    # Security
    BCRYPT_ROUNDS: int = int(os.getenv('BCRYPT_ROUNDS', '12'))
    
    # CORS
    CORS_ORIGINS: List[str] = os.getenv('CORS_ORIGINS', '*').split(',')

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    FLASK_ENV = 'production'

class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    MONGO_DATABASE = 'elysian_db_test'

# Configuration mapping
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}

def get_config() -> Config:
    """Get configuration based on environment"""
    env = os.getenv('FLASK_ENV', 'development')
    return config.get(env, config['default'])()
