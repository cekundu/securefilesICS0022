#!/usr/bin/env bash

set -euo pipefail

# Load environment variables
if [[ ! -f ".env" ]]; then
    echo "Missing .env file."
    echo "Create .env first (see INSTALL.md)."
    exit 1
fi

# Export variables from .env (only non-comment lines)
export $(grep -v '^#' .env | xargs)

# Validate required variables
required_vars=(POSTGRES_USER POSTGRES_PASSWORD POSTGRES_DB DB_PORT)
for var in "${required_vars[@]}"; do
    if [[ -z "${!var:-}" ]]; then
        echo "Missing required variable: $var"
        exit 1
    fi
done

JAR_PATH="build/libs/securefiles-0.0.1-SNAPSHOT.jar"

if [[ ! -f "$JAR_PATH" ]]; then
    echo "JAR not found: $JAR_PATH"
    echo "Run: ./gradlew clean bootJar"
    exit 1
fi

# Launch application
exec java -jar \
    -Dspring.profiles.active=default \
    "$JAR_PATH"
