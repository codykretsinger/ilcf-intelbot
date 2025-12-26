FROM docker.io/python:3.11-slim

WORKDIR /app

# NEW: Install the system 'whois' tool so python-whois works
RUN apt-get update && apt-get install -y whois && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "intel_bot.py"]