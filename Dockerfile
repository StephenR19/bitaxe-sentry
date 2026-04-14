FROM python:3.11-slim

# Create working directory
WORKDIR /app

# Create non-root user with UID 1000 (matches Umbrel)
RUN adduser --uid 1000 --disabled-password --gecos '' appuser

# Install Python dependencies before switching users
COPY bitaxe_sentry/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app code before switching users
COPY bitaxe_sentry /app/bitaxe_sentry

# Clear any Python bytecode cache that may have been copied
RUN find /app -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true && \
    find /app -name "*.pyc" -delete 2>/dev/null || true

# Copy Alembic configuration and migrations
COPY alembic.ini /app/alembic.ini
COPY alembic /app/alembic

# Prepare the persistent data directory and fix permissions
RUN mkdir -p /var/lib/bitaxe && chown -R 1000:1000 /var/lib/bitaxe

# Set environment variables and working directory
ENV PYTHONPATH=/app
WORKDIR /app

# Switch to non-root user AFTER setting permissions
USER appuser

# Default command
CMD ["python", "-m", "bitaxe_sentry.sentry"]
