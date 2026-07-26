# Small, no build toolchain needed -- Pillow ships manylinux wheels.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /srv

# DejaVu is what card.py looks for first; without it the card falls back to a
# bitmap font and looks broken. It is a few hundred KB, so just install it.
RUN apt-get update \
 && apt-get install -y --no-install-recommends fonts-dejavu-core \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app ./app
COPY examples ./examples

RUN useradd --create-home --uid 10001 agentaudit
USER agentaudit

EXPOSE 8000

# Nothing is written to disk and there is no shared state between workers other
# than the share-link cache, which is per-process by design.
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
