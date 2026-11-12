# Hardened image for scanning untrusted documents with Docwraith.
#
# Build:  docker build -t docwraith .
# Run:    docker run --rm --network none --read-only \
#           --memory 2g --cpus 2 --pids-limit 256 \
#           --cap-drop ALL --security-opt no-new-privileges \
#           -v "$PWD/inbox:/scan:ro" docwraith /scan
#
# --network none enforces that the tool never reaches the network, which it has
# no reason to do. --read-only, --cap-drop ALL and a non-root user contain a
# parser-dependency exploit. Docwraith's own --isolate adds per-file memory,
# CPU and time limits inside the container.

FROM python:3.12-slim

# tesseract is optional and only needed for --ocr; drop this line to slim the
# image if you do not scan images.
RUN apt-get update \
 && apt-get install -y --no-install-recommends tesseract-ocr \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY docwraith.py .

# Run as an unprivileged user with no home and no shell.
RUN useradd --system --no-create-home --shell /usr/sbin/nologin scanner
USER scanner

ENTRYPOINT ["python", "/app/docwraith.py"]
CMD ["--help"]
