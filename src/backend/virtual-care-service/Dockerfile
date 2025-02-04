# Build stage
FROM node:18-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    python3 \
    make \
    g++

WORKDIR /app/virtual-care-service

# Copy package files
COPY virtual-care-service/package*.json ./
COPY package-lock.json ./

# Copy tsconfig files
COPY virtual-care-service/tsconfig.json ./tsconfig.json
COPY tsconfig.json ../tsconfig.json

# Copy shared directory
COPY shared/ ../shared/

# Install dependencies
RUN npm install \
    && npm cache clean --force

# Copy source code
COPY virtual-care-service/src/ ./src/

# Build the application
RUN npm run build \
    && npm prune --production \
    && npm cache clean --force

# Production stage
FROM node:18-alpine AS production

# Create non-root user/group
RUN addgroup -g 2000 vcgroup && \
    adduser -u 2000 -G vcgroup -s /bin/sh -D vcuser

WORKDIR /app

# Copy production files
COPY --from=builder /app/virtual-care-service/package*.json ./
COPY --from=builder /app/virtual-care-service/node_modules ./node_modules
COPY --from=builder /app/virtual-care-service/dist ./dist

# Set strict file permissions
RUN chown -R vcuser:vcgroup /app && \
    chmod -R 644 /app && \
    find /app -type d -exec chmod 755 {} \;

# Configure production environment
ENV NODE_ENV=production \
    PORT=3002 \
    NODE_OPTIONS="--max-old-space-size=2048" \
    UV_THREADPOOL_SIZE=4

# Create and configure log volume
RUN mkdir -p /app/logs && \
    chown -R vcuser:vcgroup /app/logs && \
    chmod 644 /app/logs

# Expose service port
EXPOSE 3002

# Create volume for logs
VOLUME ["/app/logs"]

# Switch to non-root user
USER vcuser

# Health check configuration
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:${PORT}/health || exit 1

# Add metadata labels
LABEL maintainer="AUSTA Healthcare" \
    service="virtual-care" \
    version="1.0.0" \
    environment="production" \
    security.scan-date="${BUILD_DATE}" \
    org.opencontainers.image.source="https://github.com/austa/virtual-care-service" \
    org.opencontainers.image.description="Virtual Care Service for secure video consultations"

# Security hardening
RUN apk add --no-cache curl && \
    rm -rf /var/cache/apk/* && \
    echo "vcuser soft nofile 65535" >> /etc/security/limits.conf && \
    echo "vcuser hard nofile 65535" >> /etc/security/limits.conf

# Start application with Node.js optimizations
CMD ["node", "dist/src/index.js"]