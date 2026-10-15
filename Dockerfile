FROM python:3.12-slim
WORKDIR /app
COPY ppsm.py ./
COPY ppsm ./ppsm
COPY tests ./tests
VOLUME /data
EXPOSE 33506
CMD ["python", "ppsm.py", "--host", "0.0.0.0", "--port", "33506", "--no-browser", "--data", "/data"]
