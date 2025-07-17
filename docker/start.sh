#!/bin/bash
set -e

# Create health check endpoint
mkdir -p /app/backend/static
cat > /app/backend/static/health <<EOF
OK
EOF

# Setup permissions
chown -R appuser:appuser /app/uploads
chown -R appuser:appuser /app/backend/static

# Start Nginx
echo "Starting Nginx..."
service nginx start || { echo "Failed to start Nginx"; exit 1; }

# Create a simple health check endpoint
echo "Setting up health check endpoint..."
ln -sf /app/backend/static/health /var/www/html/health

# Start Gunicorn with optimized settings
echo "Starting Gunicorn application server..."
cd /app

# Calculate number of workers based on available CPU cores
WORKERS=$(( 2 * $(nproc) + 1 ))
echo "Using $WORKERS Gunicorn workers"

# Switch to non-root user for better security
exec su -s /bin/bash appuser -c "gunicorn \
  --bind 0.0.0.0:5000 \
  --workers $WORKERS \
  --worker-class gthread \
  --threads 2 \
  --timeout 120 \
  --keep-alive 5 \
  --max-requests 1000 \
  --max-requests-jitter 50 \
  --log-level info \
  backend.app:app"