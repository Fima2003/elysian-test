# Elysian Backend API

A well-architected Flask REST API with MongoDB integration, featuring proper layered architecture, data validation, and security best practices.

## Architecture

```
back/
├── application.py                 # Application entry point (Application Factory)
├── application.py         # Legacy entry point (deprecated)
├── config/               # Configuration management
│   ├── __init__.py
│   └── settings.py       # Environment-based configuration
├── controllers/          # API controllers (Presentation layer)
│   ├── __init__.py
│   └── user_controller.py
├── models/              # Data models with validation
│   ├── __init__.py
│   └── user.py          # User models (Pydantic schemas)
├── services/            # Business logic & data access
│   ├── __init__.py
│   ├── database.py      # Database connection service
│   ├── user_repository.py # Data access layer
│   └── user_service.py  # Business logic layer
├── utils/               # Utilities
│   ├── __init__.py
│   └── security.py      # Password hashing/verification
├── .env.example         # Environment variables template
└── requirements.txt     # Python dependencies
```

## Features

- **Layered Architecture**: Controllers → Services → Repository → Database
- **Data Validation**: Pydantic models with comprehensive validation
- **Configuration Management**: Environment-based configuration
- **Security**: bcrypt password hashing, input validation
- **Error Handling**: Proper HTTP status codes and error responses
- **Logging**: Structured logging throughout the application
- **CORS Support**: Configurable cross-origin resource sharing
- **User Authentication**: Login with password verification
- **User Registration**: Create new user accounts
- **External API Integration**: Node.js service integration

### **Architecture Principles Applied**
- **Separation of Concerns**: Each layer has distinct responsibilities
- **Dependency Injection**: Services injected into controllers
- **Single Responsibility**: Each class has one clear purpose
- **Open/Closed Principle**: Easy to extend without modification
- **Application Factory Pattern**: Configurable app creation

## How to set up

### 1. Environment Setup
```bash
# Copy environment template
cp .env.example .env

# Edit .env with your configuration
nano .env
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Start MongoDB
```bash
# Use local MongoDB installation
mongod
```

### 4. Run Application
```bash
# Using new architecture
python application.py

# Application will start on http://127.0.0.1:5000
```

## API Endpoints

### Authentication

#### Register User
```http
POST /api/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "securepassword123"
}
```

#### Login User
```http
POST /api/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "securepassword123"
}
```

### Health Check
```http
GET /
```

## Configuration

Environment variables (see `.env.example`):

```env
# Database
MONGO_URI=mongodb://localhost:27017/
MONGO_DATABASE=elysian_db

# Application
FLASK_ENV=development
FLASK_DEBUG=True
FLASK_HOST=127.0.0.1
FLASK_PORT=5000

# Security
BCRYPT_ROUNDS=12

# CORS
CORS_ORIGINS=*

# External Services
NODE_URI=http://localhost:3000
```

## Data Models

### User Model
```python
{
  "email": "user@example.com",        # Required, validated email
  "password": "password123",          # Min 6 characters (for creation)
  "created_at": "2024-01-01T00:00:00Z",
  "updated_at": "2024-01-01T00:00:00Z"
}
```

## Security Features

- **Password Hashing**: bcrypt with configurable rounds
- **Input Validation**: Pydantic models prevent invalid data
- **Email Validation**: Proper email format validation
- **Error Handling**: No sensitive data in error responses
- **CORS Configuration**: Controlled cross-origin access

## Development

### Project Structure Benefits

1. **Maintainability**: Clear separation of concerns
2. **Testability**: Each layer can be tested independently  
3. **Scalability**: Easy to add new features and endpoints
4. **Flexibility**: Swap implementations without affecting other layers
5. **Readability**: Logical organization and naming conventions

### Adding New Features

1. **Model**: Add to `models/`
2. **Repository**: Add data access methods
3. **Service**: Add business logic
4. **Controller**: Add API endpoints
5. **Routes**: Register in `application.py`