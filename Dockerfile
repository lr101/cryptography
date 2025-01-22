FROM python:3.9-slim

WORKDIR /app

COPY src  ./src

CMD ["python", "src/main.py"]