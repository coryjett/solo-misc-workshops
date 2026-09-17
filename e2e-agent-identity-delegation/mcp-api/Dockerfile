FROM python:3.12-slim
RUN pip install --no-cache-dir "fastmcp>=2.3" "httpx>=0.27"
COPY server.py /app/server.py
WORKDIR /app
EXPOSE 8000
CMD ["python", "server.py"]
