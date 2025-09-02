from flask import request, jsonify, g
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
import os
import bleach
import logging
from typing import Any
import time
from collections import defaultdict, deque
import ipaddress
from functools import wraps

logger = logging.getLogger(__name__)

class SecurityMiddleware:
    """Security middleware for Flask application"""
    
    def __init__(self):
        self.failed_attempts = defaultdict(deque)  # IP -> deque of attempt timestamps
        self.blocked_ips = {}  # IP -> block_until_timestamp
        self.max_failures = 5  # Max failures before blocking
        self.block_duration = 300  # Block for 5 minutes (300 seconds)
        self.failure_window = 300  # Count failures within 5 minutes
    
    def init_app(self, app):
        """Initialize security middleware with Flask app"""
        
        # Configure rate limiting
        limiter = Limiter(
            key_func=get_remote_address,
            default_limits=["1000 per hour", "100 per minute"],
            storage_uri="memory://",
        )
        limiter.init_app(app)
        
        # Configure security headers with Talisman
        # Disable HTTPS redirect (302) inside test environment to keep tests deterministic
        is_testing = app.config.get('TESTING') or os.getenv('FLASK_ENV') == 'testing'
        Talisman(
            app,
            force_https=not is_testing,
            strict_transport_security=not is_testing,  # skip HSTS in tests
            content_security_policy={
                'default-src': "'self'",
                'script-src': "'self' 'unsafe-inline'",
                'style-src': "'self' 'unsafe-inline'",
                'img-src': "'self' data:",
                'connect-src': "'self'",
                'font-src': "'self'",
                'object-src': "'none'",
                'media-src': "'self'",
                'frame-src': "'none'",
            },
            content_security_policy_nonce_in=['script-src', 'style-src'],
            feature_policy={
                'geolocation': "'none'",
                'microphone': "'none'",
                'camera': "'none'",
            }
        )
        
        # Set up request size limits
        app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  # 1MB max request size
        
        # Apply specific rate limits to sensitive endpoints
        # This will be applied after routes are registered in the main app
        self.login_rate_limit = limiter.limit("5 per minute")
        self.register_rate_limit = limiter.limit("3 per minute")
        
        # Add middleware for IP blocking and input sanitization
        app.before_request(self.before_request)
        app.after_request(self.after_request)
        
        # Store limiter and app references
        self.limiter = limiter
        self.app = app

        # Reset per-IP tracking when (re)initializing for a new app instance to avoid
        # leaking state across tests or multiple app factories in the same process.
        # This ensures rate limit tests start from a clean slate.
        try:
            self.failed_attempts.clear()
            self.blocked_ips.clear()
        except Exception:
            # Be defensive; if structures were replaced, reinitialize them.
            from collections import defaultdict, deque
            self.failed_attempts = defaultdict(deque)
            self.blocked_ips = {}
        
        logger.info("Security middleware initialized")
    
    def apply_rate_limits(self):
        """Apply rate limits to existing routes after they're registered"""
        # Apply rate limiting to login route
        if 'login' in self.app.view_functions:
            self.app.view_functions['login'] = self.login_rate_limit(self.app.view_functions['login'])
            
        # Apply rate limiting to register route
        if 'register' in self.app.view_functions:
            self.app.view_functions['register'] = self.register_rate_limit(self.app.view_functions['register'])
    
    def before_request(self):
        """Process request before handling"""
        client_ip = get_remote_address()
		
        # Only enforce IP block on sensitive endpoints with POST methods
        if self._is_sensitive_request():
            if self.is_ip_blocked(client_ip):
                logger.warning(f"Blocked request from IP: {client_ip}")
                return jsonify({
                    "message": "Too many failed attempts. Access temporarily blocked.",
                    "retry_after": self.get_block_remaining_time(client_ip)
                }), 429
        
        # Sanitize JSON input
        if request.is_json and request.get_json():
            try:
                sanitized_data = self.sanitize_json_data(request.get_json())
                g.sanitized_json = sanitized_data
            except Exception as e:
                logger.warning(f"Failed to sanitize request data: {e}")
                return jsonify({"message": "Invalid request data"}), 400
    
    def after_request(self, response):
        """Process response after handling"""
        # Add additional security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # Log failed authentication attempts on auth endpoints
        auth_endpoints = {'login', 'register'}
        if (request.endpoint in auth_endpoints and 
            response.status_code in [401, 403, 422]):
            self.record_failed_attempt(get_remote_address())
        
        return response

    def _is_sensitive_request(self) -> bool:
        """Return True if current request targets sensitive auth endpoints with POST method."""
        try:
            path = (request.path or '').lower()
            method = (request.method or 'GET').upper()
            if method != 'POST':
                return False
            # Match canonical paths only
            sensitive_paths = {
                '/api/login',
                '/api/register'
            }
            return path in sensitive_paths
        except Exception:
            return False
    
    def sanitize_json_data(self, data: Any) -> Any:
        """Recursively sanitize JSON data"""
        if isinstance(data, dict):
            return {key: self.sanitize_json_data(value) for key, value in data.items()}
        elif isinstance(data, list):
            return [self.sanitize_json_data(item) for item in data]
        elif isinstance(data, str):
            # Remove potentially harmful content
            sanitized = bleach.clean(
                data,
                tags=[],  # Remove all HTML tags
                attributes={},  # Remove all attributes
                strip=True  # Strip tags instead of escaping
            )
            # Additional sanitization for common injection patterns
            sanitized = sanitized.replace('<script', '&lt;script')
            sanitized = sanitized.replace('javascript:', '')
            return sanitized.strip()
        else:
            return data
    
    def is_ip_blocked(self, ip: str) -> bool:
        """Check if IP is currently blocked"""
        if ip in self.blocked_ips:
            if time.time() < self.blocked_ips[ip]:
                return True
            else:
                # Block expired, remove it
                del self.blocked_ips[ip]
                if ip in self.failed_attempts:
                    del self.failed_attempts[ip]
        return False
    
    def get_block_remaining_time(self, ip: str) -> int:
        """Get remaining block time in seconds"""
        if ip in self.blocked_ips:
            remaining = int(self.blocked_ips[ip] - time.time())
            return max(0, remaining)
        return 0
    
    def record_failed_attempt(self, ip: str):
        """Record a failed authentication attempt"""
        current_time = time.time()
        
        # Clean old attempts outside the window
        while (self.failed_attempts[ip] and 
            current_time - self.failed_attempts[ip][0] > self.failure_window):
            self.failed_attempts[ip].popleft()
        
        # Add current attempt
        self.failed_attempts[ip].append(current_time)
        
        # Check if should block. Block only AFTER exceeding the threshold,
        # so with max_failures=5, attempts 1..5 are allowed (returning 401/etc),
        # and the 6th attempt triggers a block.
        if len(self.failed_attempts[ip]) > self.max_failures:
            self.blocked_ips[ip] = current_time + self.block_duration
            logger.warning(
                f"IP {ip} blocked due to {len(self.failed_attempts[ip])} failed attempts"
            )
    
    def is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/local"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback
        except ValueError:
            return False

# Global security middleware instance
security_middleware = SecurityMiddleware()

def require_json(f):
    """Decorator to ensure endpoint receives JSON data"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not request.is_json:
            return jsonify({"message": "Content-Type must be application/json"}), 400
        return f(*args, **kwargs)
    return decorated_function

def sanitize_input(f):
    """Decorator to use sanitized input data"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if hasattr(g, 'sanitized_json'):
            request._cached_json = (g.sanitized_json, g.sanitized_json)
        return f(*args, **kwargs)
    return decorated_function
