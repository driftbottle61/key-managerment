FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV SSHWEB_HOST=0.0.0.0 SSHWEB_PORT=8080
VOLUME ["/app/data"]
EXPOSE 8080
# 用 waitress 生产服务器运行
CMD ["python", "-m", "waitress", "--host=0.0.0.0", "--port=8080", "--threads=8", "app:app"]
