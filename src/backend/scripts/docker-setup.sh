#!/bin/bash

# Create necessary directories
mkdir -p secrets data/postgres data/mongodb logs/auth logs/virtual-care

# Generate random secrets if they don't exist
generate_secret() {
    if [ ! -f "secrets/$1" ]; then
        openssl rand -base64 32 > "secrets/$1"
        echo "Generated $1"
    fi
}

# Generate all required secrets
generate_secret "jwt_secret.txt"
generate_secret "session_secret.txt"
generate_secret "postgres_user.txt"
generate_secret "postgres_password.txt"
generate_secret "mongo_root_user.txt"
generate_secret "mongo_root_password.txt"
generate_secret "redis_password.txt"

# Set proper permissions
chmod 600 secrets/*
chmod -R 755 data logs

echo "Docker setup completed successfully!"
echo "Please make sure to set up your Twilio credentials in secrets/twilio_sid.txt and secrets/twilio_token.txt"
echo "You can now run: docker-compose up --build" 