# Stage 1: Builder
FROM node:18-alpine AS builder

# Install build dependencies
RUN apk add --no-cache python3 make g++

# Set working directory
WORKDIR /app

# Copy shared module files first
COPY shared ./shared

# Install and build shared module
WORKDIR /app/shared
RUN npm install --ignore-scripts
RUN npm run build

# Copy API Gateway files
WORKDIR /app/api-gateway
COPY api-gateway/package*.json ./

# Install API Gateway dependencies
RUN npm install --ignore-scripts

# Copy API Gateway source
COPY api-gateway/. .

# Build API Gateway
RUN npm run build

# Stage 2: Production
FROM node:18-alpine

# Install security updates and required packages
RUN apk update && apk upgrade \
    && apk add --no-cache dumb-init curl

# Set working directory
WORKDIR /app

# Copy built artifacts and dependencies
COPY --from=builder /app/api-gateway/dist ./dist
COPY --from=builder /app/api-gateway/node_modules ./node_modules
COPY --from=builder /app/shared/dist ./node_modules/@austa/shared/dist
COPY --from=builder /app/api-gateway/package*.json ./
COPY --from=builder /app/api-gateway/healthcheck.js ./

# Set security-related environment variables
ENV NODE_ENV=production \
    PORT=8000 \
    API_VERSION=v1 \
    NODE_OPTIONS="--max-old-space-size=2048" \
    SECURITY_HEADERS_ENABLED=true \
    RATE_LIMIT_ENABLED=true \
    AUDIT_LOGGING_ENABLED=true

# Configure security limits and policies
RUN mkdir -p /tmp/api-gateway && chown node:node /tmp/api-gateway

# Set up health monitoring
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD ["node", "./healthcheck.js"]

# Set container user
USER node

# Expose service port
EXPOSE 8000

# Set resource constraints
LABEL maintainer="AUSTA Healthcare" \
      application="api-gateway" \
      version="1.0.0" \
      security.hipaa.compliant="true" \
      security.updates.policy="auto" \
      monitoring.health.endpoint="/health" \
      vendor="AUSTA SuperApp"

# Use dumb-init as PID 1
ENTRYPOINT ["/usr/bin/dumb-init", "--"]

# Start the application
CMD ["node", "./dist/index.js"]

# Define volumes for persistent data
VOLUME ["/tmp/api-gateway"]