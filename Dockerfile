# Using a specific hash of an image to protect against Supply Chain attacks
FROM python:3.13-slim@sha256:35b71c1b97893609aba7ab95b35b668c88a38c30783f24cf483330fe5a8315af AS builder

WORKDIR /app

# Installing dependencies in a virtual environment
ARG PIP_FIND_LINKS=/app/wheels
COPY wheels /app/wheels
COPY requirements-dev.txt .
RUN pip install --no-index --find-links="${PIP_FIND_LINKS}" --user --require-hashes -r requirements-dev.txt

# The final image (Runtime)
FROM python:3.13-slim@sha256:35b71c1b97893609aba7ab95b35b668c88a38c30783f24cf483330fe5a8315af

# Creating a non-root user and /data folder with correct permissions
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -m -s /bin/false appuser && \
    mkdir /data && chown appuser:appgroup /data
WORKDIR /app

# Copying only the installed packages from the builder layer
COPY --from=builder /root/.local /home/appuser/.local
COPY --chown=appuser:appgroup . .

# Configuring Paths
ENV PATH=/home/appuser/.local/bin:$PATH
ENV PYTHONUNBUFFERED=1

USER appuser

ENTRYPOINT ["python", "nginx_log_parser.py"]

# --file is required flag, see "docker-compose.yaml" for settings flags
CMD ["--help"]