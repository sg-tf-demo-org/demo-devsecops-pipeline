# DEMO ONLY — old base for Trivy image Critical/High fail path.
# Presenter: Beat 4. Compliant twin: fixtures/compliant/Dockerfile
FROM python:3.8.0-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["python", "-c", "print('vulnerable-demo')"]
