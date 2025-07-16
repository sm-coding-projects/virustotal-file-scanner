#!/bin/bash

# Start Nginx
service nginx start

# Start Gunicorn
cd /app
gunicorn --bind 0.0.0.0:5000 --workers 4 --timeout 120 backend.app:app