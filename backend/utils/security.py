"""
Security utilities for the VirusTotal File Scanner application.
"""
import re
import html
import functools
import time
from flask import request, jsonify, current_app
from werkzeug.security import safe_str_cmp

# Dictionary to store rate limiting information
# Structure: {ip_address: {'count': request_count, 'reset_time': reset_timestamp}}
rate_limit_store = {}

def sanitize_input(input_str):
    """
    Sanitize input string to prevent XSS and other injection attacks.
    
    Args:
        input_str: String to sanitize
        
    Returns:
        Sanitized string
    """
    if not isinstance(input_str, str):
        return input_str
    
    # Escape HTML characters
    sanitized = html.escape(input_str)
    
    # Remove potentially dangerous patterns
    sanitized = re.sub(r'javascript:', '', sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r'data:', '', sanitized, flags=re.IGNORECASE)
    
    return sanitized

def sanitize_dict(input_dict):
    """
    Recursively sanitize all string values in a dictionary.
    
    Args:
        input_dict: Dictionary to sanitize
        
    Returns:
        Sanitized dictionary
    """
    if not isinstance(input_dict, dict):
        return input_dict
    
    result = {}
    for key, value in input_dict.items():
        if isinstance(value, str):
            result[key] = sanitize_input(value)
        elif isinstance(value, dict):
            result[key] = sanitize_dict(value)
        elif isinstance(value, list):
            result[key] = [
                sanitize_dict(item) if isinstance(item, dict) 
                else sanitize_input(item) if isinstance(item, str)
                else item
                for item in value
            ]
        else:
            result[key] = value
    
    return result

def validate_uuid(uuid_str):
    """
    Validate that a string is a valid UUID.
    
    Args:
        uuid_str: String to validate
        
    Returns:
        Boolean indicating if the string is a valid UUID
    """
    uuid_pattern = re.compile(
        r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
        re.IGNORECASE
    )
    return bool(uuid_pattern.match(uuid_str))

def rate_limit(requests_per_minute=60):
    """
    Decorator for rate limiting API endpoints.
    
    Args:
        requests_per_minute: Maximum number of requests allowed per minute
        
    Returns:
        Decorated function
    """
    def decorator(f):
        @functools.wraps(f)
        def wrapped(*args, **kwargs):
            # Get client IP address
            ip_address = request.remote_addr
            
            # Get current timestamp
            current_time = time.time()
            
            # Initialize rate limit data for this IP if not exists
            if ip_address not in rate_limit_store:
                rate_limit_store[ip_address] = {
                    'count': 0,
                    'reset_time': current_time + 60  # Reset after 60 seconds
                }
            
            # Check if the reset time has passed
            if current_time > rate_limit_store[ip_address]['reset_time']:
                # Reset the counter
                rate_limit_store[ip_address] = {
                    'count': 0,
                    'reset_time': current_time + 60
                }
            
            # Increment the request count
            rate_limit_store[ip_address]['count'] += 1
            
            # Check if the request count exceeds the limit
            if rate_limit_store[ip_address]['count'] > requests_per_minute:
                # Return 429 Too Many Requests
                response = jsonify({
                    'error': 'Rate limit exceeded',
                    'retry_after': int(rate_limit_store[ip_address]['reset_time'] - current_time)
                })
                response.status_code = 429
                return response
            
            # Add rate limit headers to the response
            response = f(*args, **kwargs)
            
            # If the response is a tuple (response, status_code), extract the response
            if isinstance(response, tuple):
                response_obj = response[0]
                status_code = response[1]
                headers = response[2] if len(response) > 2 else {}
            else:
                response_obj = response
                status_code = 200
                headers = {}
            
            # Calculate remaining requests
            remaining = requests_per_minute - rate_limit_store[ip_address]['count']
            reset_time = int(rate_limit_store[ip_address]['reset_time'] - current_time)
            
            # Add rate limit headers
            headers['X-RateLimit-Limit'] = str(requests_per_minute)
            headers['X-RateLimit-Remaining'] = str(remaining)
            headers['X-RateLimit-Reset'] = str(reset_time)
            
            # Return the response with headers
            if isinstance(response, tuple):
                return response_obj, status_code, headers
            else:
                return response, status_code, headers
        
        return wrapped
    
    return decorator

def validate_content_type(required_content_type='application/json'):
    """
    Decorator to validate the Content-Type header of requests.
    
    Args:
        required_content_type: Required Content-Type header value
        
    Returns:
        Decorated function
    """
    def decorator(f):
        @functools.wraps(f)
        def wrapped(*args, **kwargs):
            # Check if the request has a body that needs validation
            if request.method in ['POST', 'PUT', 'PATCH'] and request.content_length:
                content_type = request.headers.get('Content-Type', '')
                
                # Check if the Content-Type header matches the required value
                if not content_type.startswith(required_content_type):
                    return jsonify({
                        'error': f'Invalid Content-Type header. Expected {required_content_type}'
                    }), 415
            
            return f(*args, **kwargs)
        
        return wrapped
    
    return decorator

def secure_headers():
    """
    Add security headers to a response.
    
    Returns:
        Dictionary of security headers
    """
    return {
        'Content-Security-Policy': "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'",
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Referrer-Policy': 'strict-origin-when-cross-origin'
    }

def security_headers_middleware():
    """
    Middleware to add security headers to all responses.
    
    Returns:
        Middleware function
    """
    def middleware(response):
        # Add security headers to the response
        for header, value in secure_headers().items():
            response.headers[header] = value
        return response
    
    return middleware