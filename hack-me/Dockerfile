FROM python:3.11-slim

LABEL maintainer="Márcio Coutinho <marciolscoutinho@github>"
LABEL description="hack-me CTF — Deliberately Vulnerable Web App"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN python init_db.py

EXPOSE 5000

CMD ["python", "app.py"]
