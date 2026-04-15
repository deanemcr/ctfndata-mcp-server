FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ctfndata_mcp_server.py .
COPY admin_cli.py .

EXPOSE 8080

CMD ["python", "ctfndata_mcp_server.py"]
