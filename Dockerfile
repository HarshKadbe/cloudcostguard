FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY pyproject.toml .
RUN pip setuptools.install
RUN pip install -e .

# Copy source code
COPY cloudcostguard ./cloudcostguard

# Set non-root user
RUN useradd -m appuser
USER appuser

# Default command
ENTRYPOINT ["cloudcostguard"]
