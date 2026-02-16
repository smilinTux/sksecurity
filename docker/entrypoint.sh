#!/bin/bash
# SKSecurity Enterprise - Docker Entrypoint Script

set -e

# Default environment variables
SKSECURITY_ENV=${SKSECURITY_ENV:-production}
SKSECURITY_DEBUG=${SKSECURITY_DEBUG:-false}
SKSECURITY_HOST=${SKSECURITY_HOST:-0.0.0.0}
SKSECURITY_PORT=${SKSECURITY_PORT:-8888}

echo "🛡️ Starting SKSecurity Enterprise"
echo "Environment: $SKSECURITY_ENV"
echo "Debug Mode: $SKSECURITY_DEBUG"
echo "Host: $SKSECURITY_HOST"
echo "Port: $SKSECURITY_PORT"

# Initialize configuration if not exists
if [ ! -f "/home/sksecurity/.config/sksecurity/config.yml" ]; then
    echo "⚙️ Initializing configuration..."
    sksecurity init --config-only
fi

# Update threat intelligence on startup
echo "🧠 Updating threat intelligence..."
sksecurity update || echo "⚠️ Threat intelligence update failed (will retry later)"

# Run any database migrations/setup
echo "🗃️ Setting up security database..."
sksecurity init --framework generic 2>/dev/null || echo "Database already initialized"

# Start the application based on command
case "$1" in
    dashboard)
        echo "📊 Starting security dashboard..."
        exec sksecurity dashboard --host "$SKSECURITY_HOST" --port "$SKSECURITY_PORT"
        ;;
    scan)
        echo "🔍 Running security scan..."
        shift
        exec sksecurity scan "$@"
        ;;
    monitor)
        echo "👁️ Starting security monitoring..."
        shift
        exec sksecurity monitor "$@"
        ;;
    update)
        echo "🔄 Updating threat intelligence..."
        exec sksecurity update
        ;;
    audit)
        echo "📋 Running security audit..."
        shift
        exec sksecurity audit "$@"
        ;;
    cli)
        echo "💻 Starting interactive CLI..."
        exec /bin/bash
        ;;
    *)
        echo "🚀 Running custom command: $@"
        exec "$@"
        ;;
esac