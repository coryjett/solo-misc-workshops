FROM python:3.12-slim
RUN pip install --no-cache-dir "mcp[cli]==1.*" fastapi "uvicorn[standard]"
WORKDIR /app
COPY *.py ./
EXPOSE 8000
