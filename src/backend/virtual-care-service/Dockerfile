# Stage 1: Build environment
FROM node:18-alpine AS builder
# node:18-alpine v18.19.0

# Install build dependencies
RUN apk add --no-cache \
    python3 \
    make \
    g++ \
    curl

# Set working directory
WORKDIR /app

# Copy shared module first
COPY shared shared/
WORKDIR /app/shared
COPY shared/package*.json ./
RUN npm install
RUN npm run build

# Build virtual-care service
WORKDIR /app/virtual-care
COPY virtual-care-service/package*.json ./
RUN npm install

# Copy virtual-care service source code
COPY virtual-care-service .

# Build TypeScript code and inspect directory structure
RUN node ./node_modules/typescript/bin/tsc -p tsconfig.json && \
    echo "Contents of current directory:" && \
    ls -la && \
    echo "Contents of dist directory:" && \
    ls -la dist/

# Stage 2: Production environment
FROM node:18-alpine
# node:18-alpine v18.19.0

# Create non-root user and group
RUN addgroup -S vcservice && \
    adduser -S -G vcservice -s /bin/sh vcservice

# Set working directory
WORKDIR /app

# Copy build artifacts and inspect
COPY --from=builder --chown=vcservice:vcservice /app/virtual-care/dist ./dist
COPY --from=builder --chown=vcservice:vcservice /app/virtual-care/node_modules ./node_modules
COPY --from=builder --chown=vcservice:vcservice /app/shared/dist ./shared/dist
COPY --from=builder --chown=vcservice:vcservice /app/virtual-care/package*.json ./
RUN echo "Contents of /app directory:" && \
    ls -la && \
    echo "Contents of /app/dist directory:" && \
    ls -la dist/

# Create and configure log directory
RUN mkdir -p /app/logs && \
    chown -R vcservice:vcservice /app/logs && \
    chmod -R 770 /app/logs

# Set environment variables
ENV NODE_ENV=production \
    PORT=3002

# Expose port
EXPOSE 3002

# Switch to non-root user
USER vcservice

# Start the service
CMD ["node", "dist/index.js"]