FROM python:3.10-slim

ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Expõe a variável PORT padrão do Cloud Run
ENV PORT=8080

CMD ["python", "gerente.py"]

