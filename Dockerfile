FROM python:3.10-slim

# Evita que o Python faça buffer dos logs, permitindo ver os prints em tempo real
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "gerente.py"]
