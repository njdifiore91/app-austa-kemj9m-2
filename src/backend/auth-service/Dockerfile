# Stage 1: Build environment
FROM node:18-alpine AS builder
# node:18-alpine v18.19.0

# Install build dependencies
RUN apk add --no-cache \
    python3 \
    make \
    g++

WORKDIR /app/auth-service

# Copy package files
COPY auth-service/package*.json ./
COPY package-lock.json ./

# Copy tsconfig files
COPY auth-service/tsconfig.json ./tsconfig.json
COPY tsconfig.json ../tsconfig.json

# Copy shared directory
COPY shared/ ../shared/

# Install dependencies
RUN npm install \
    && npm cache clean --force

# Copy source code
COPY auth-service/src/ ./src/

# Build the application
RUN npm run build \
    && npm prune --production \
    && npm cache clean --force

# Stage 2: Production environment
FROM node:18-alpine AS production
# node:18-alpine v18.19.0

# Create non-root user and group
RUN addgroup -S authservice && \
    adduser -S -G authservice authservice

WORKDIR /app

# Copy production files
COPY --from=builder --chown=authservice:authservice /app/auth-service/dist ./dist
COPY --from=builder --chown=authservice:authservice /app/auth-service/node_modules ./node_modules
COPY --from=builder --chown=authservice:authservice /app/auth-service/package*.json ./

# Create log directory with appropriate permissions
RUN mkdir -p /app/logs && \
    chown -R authservice:authservice /app/logs && \
    chmod -R 550 /app && \
    chmod -R 770 /app/logs

# Configure production environment variables
ENV NODE_ENV=production \
    PORT=3001 \
    NODE_OPTIONS="--max-old-space-size=2048" \
    UV_THREADPOOL_SIZE=4

# Security hardening
RUN apk add --no-cache dumb-init && \
    echo "fs.file-max = 65535" >> /etc/sysctl.conf && \
    echo "authservice soft nofile 65535" >> /etc/security/limits.conf && \
    echo "authservice hard nofile 65535" >> /etc/security/limits.conf

# Configure health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=30s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:${PORT}/health || exit 1

# Expose service port
EXPOSE 3001

# Switch to non-root user
USER authservice

# Use dumb-init as PID 1
ENTRYPOINT ["/usr/bin/dumb-init", "--"]

# Start the application with clustering enabled
CMD ["node", "dist/src/index.js"]