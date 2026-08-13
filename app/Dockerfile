# Compliant twin — current slim base; pair with compliant requirements.txt
FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["python", "-c", "print('compliant-demo')"]
