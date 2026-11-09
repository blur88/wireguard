FROM python:3.12-slim

# Set environment defaults
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src \
    PORT=8080

# Create dedicated non-root user and group
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /sbin/nologin -d /app -M appuser

WORKDIR /app

# Install dependencies first for better layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY src/ /app/src/

# Ensure proper permissions
RUN chown -R appuser:appgroup /app

# Switch to unprivileged user
USER 10001:10001

EXPOSE 8080

CMD ["python", "-m", "wireguard_dashboard.main"]
