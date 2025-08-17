from flask import Flask, jsonify
from flask_cors import CORS
from config import get_config
from services import db_service
from controllers import user_controller
from utils.security_middleware import security_middleware
import logging
import atexit

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def create_app() -> Flask:
    """Application factory pattern"""
    
    # Get configuration
    config = get_config()
    
    # Create Flask app
    app = Flask(__name__)
    
    # Initialize security middleware FIRST
    security_middleware.init_app(app)
    
    # Configure CORS
    CORS(app, origins=config.CORS_ORIGINS, supports_credentials=True)
    
    # Initialize database connection
    if not db_service.test_connection():
        logger.error("Failed to connect to database")
        raise Exception("Database connection failed")
    
    # Register routes
    @app.route('/')
    def root():
        """Root endpoint"""
        return {"status": "healthy", "message": "Elysian Backend API"}
    
    @app.route('/health')
    def health_check():
        """Health check endpoint with database connection status"""
        from datetime import datetime
        
        health_data = {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "database_connected": db_service.is_connected()
        }
        
        return health_data
    
    # Main user routes (rate-limited routes are handled by security middleware)
    @app.route('/api/register', methods=['POST'])
    def register():
        """User registration endpoint"""
        return user_controller.register()

    @app.route('/api/login', methods=['POST'])
    def login():
        """User login endpoint"""
        return user_controller.login()
    
    # Apply rate limiting after routes are registered
    security_middleware.apply_rate_limits()
    
    # Error handlers
    @app.errorhandler(400)
    def bad_request(error):
        # Check if it's a JSON parsing error
        if "Failed to decode JSON" in str(error) or "JSON" in str(error):
            return jsonify({
                "success": False,
                "message": "Invalid JSON format"
            }), 400
        else:
            return jsonify({
                "success": False,
                "message": "Bad request"
            }), 400

    @app.errorhandler(404)
    def not_found(error):
        return jsonify({
            "success": False,
            "message": "Endpoint not found"
        }), 404

    @app.errorhandler(405)
    def method_not_allowed(error):
        return jsonify({
            "success": False,
            "message": "Method not allowed"
        }), 405
    
    @app.errorhandler(500)
    def internal_error(error):
        logger.error(f"Internal server error: {error}")
        return jsonify({
            "success": False,
            "message": "Internal server error"
        }), 500
    
    # Cleanup on app shutdown
    def cleanup():
        db_service.close()
        logger.info("Application shutdown complete")
    
    atexit.register(cleanup)
    
    logger.info("Application initialized successfully")
    return app

def main():
    """Main application entry point"""
    try:
        config = get_config()
        app = create_app()
        
        logger.info(f"Starting server on {config.FLASK_HOST}:{config.FLASK_PORT}")
        app.run(
            host=config.FLASK_HOST,
            port=config.FLASK_PORT,
            debug=config.FLASK_DEBUG
        )
        
    except Exception as e:
        logger.error(f"Failed to start application: {e}")
        raise

if __name__ == "__main__":
    main()

app = create_app()
