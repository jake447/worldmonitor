FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY agent.py .

# Non-root for parity with the other services.
RUN adduser --system --uid 1001 agent && chown -R agent /app
USER agent

# Worker: no port, no HTTP. Unbuffered so logs stream to Railway.
CMD ["python", "-u", "agent.py"]
