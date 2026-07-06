# sanitext -- minimal image. Standard-library only; no compiled deps.
FROM python:3.12-slim

ENV PYTHONUTF8=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY . /app

RUN pip install --no-cache-dir -e .

# Non-root for safety.
RUN useradd -m sanitext
USER sanitext

ENTRYPOINT ["sanitext"]
CMD ["--help"]
