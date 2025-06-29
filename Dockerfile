# RTT-Secure Docker Container
# Advanced Enterprise Stealth Tunnel
# Designed and Developed by RmnJL
# Multi-stage build for enhanced security

# Build stage
FROM nimlang/nim:2.0.0-regular as builder

# Security: Create build directory
WORKDIR /build

# Copy source code
COPY . .

# Build with security optimizations
RUN nim install && \
    nim c -d:release -d:ssl --opt:speed --gc:orc -o:RTT-Secure src/main.nim

# Production stage - minimal and secure
FROM ubuntu:22.04

# Security metadata
LABEL maintainer="RmnJL"
LABEL description="RTT-Secure - Advanced Enterprise Stealth Tunnel"
LABEL version="2.0"
LABEL security.scan="enabled"

# Create non-root user for security
RUN groupadd -r rtt-secure && \
    useradd -r -g rtt-secure -d /opt/rtt-secure -s /bin/bash rtt-secure

# Install runtime dependencies only
RUN apt-get update && apt-get install -y \
    ca-certificates \
    openssl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create secure directories
RUN mkdir -p /opt/rtt-secure/config \
    && mkdir -p /opt/rtt-secure/logs \
    && chown -R rtt-secure:rtt-secure /opt/rtt-secure

# Copy binary from builder
COPY --from=builder /build/RTT-Secure /opt/rtt-secure/
COPY --from=builder /build/scripts/install-secure.sh /opt/rtt-secure/

# Set secure permissions
RUN chmod 750 /opt/rtt-secure/RTT-Secure \
    && chmod 750 /opt/rtt-secure/install-secure.sh \
    && chown rtt-secure:rtt-secure /opt/rtt-secure/RTT-Secure

# Security: Switch to non-root user
USER rtt-secure
WORKDIR /opt/rtt-secure

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD pgrep RTT-Secure > /dev/null || exit 1

# Expose port (can be overridden)
EXPOSE 443

# Security: Use exec form and non-root execution
ENTRYPOINT ["./RTT-Secure"]
CMD ["--help"]