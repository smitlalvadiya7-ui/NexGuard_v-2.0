FROM python:3.12-slim

# System packages required by the Python dependencies:
#   tesseract-ocr  → pytesseract (OCR)
#   libzbar0       → pyzbar (QR decoding)
#   libgl1         → opencv-python (headless GL stub)
#   libglib2.0-0   → opencv-python (GLib runtime)
RUN apt-get update && apt-get install -y --no-install-recommends \
        tesseract-ocr \
        libzbar0 \
        libgl1 \
        libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first (layer-cached unless requirements change)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Run as an unprivileged user, not root (OWASP A05). The app writes the SQLite
# DB, uploaded tempfiles and logs under /app, so hand it ownership before the
# switch — after this line every RUN/CMD is non-root.
RUN useradd --create-home --uid 10001 nexguard \
    && chown -R nexguard:nexguard /app
USER nexguard

EXPOSE 8000

# 0.0.0.0 required inside Docker; single worker is fine for SQLite
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
