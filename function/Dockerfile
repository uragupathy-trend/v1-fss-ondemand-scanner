# Use official Python base image optimized for x86_64 architecture
FROM python:3.9-slim

# Set environment variables for better performance
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Install system dependencies required for x86_64
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libc6-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Create function directory
WORKDIR /function

# Install FDK and other Python dependencies
COPY requirements.txt /function/
RUN pip3 install --no-cache-dir --upgrade pip && \
    pip3 install --no-cache-dir -r requirements.txt

# Copy function code
COPY . /function/

# Ensure the function is executable
RUN chmod +x /function/func.py

# Use the FDK entrypoint for OCI Functions
ENTRYPOINT ["/usr/local/bin/fdk", "/function/func.py", "handler"]
