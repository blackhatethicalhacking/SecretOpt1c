FROM python:3.12-slim
LABEL org.opencontainers.image.title="SecretOpt1c" \
      org.opencontainers.image.source="https://github.com/blackhatethicalhacking/SecretOpt1c" \
      org.opencontainers.image.authors="Chris 'SaintDruG' Abou-Chabke"
WORKDIR /opt/secretopt1c
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY secretopt1c.py secrethub.json ./
ENTRYPOINT ["python", "secretopt1c.py"]
